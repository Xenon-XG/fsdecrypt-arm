use std::{
    fs::{create_dir_all, File, FileTimes},
    io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write},
    path::Path,
    time::{Duration, SystemTime},
};

use chrono::{FixedOffset, TimeZone};
use exfat_fs::dir::{entry::fs::FsElement, Root};

use aes::{
    cipher::{block_padding::NoPadding, BlockDecryptMut, InnerIvInit, KeyInit, KeyIvInit},
    Aes128Dec,
};
use anyhow::{anyhow, Result};
use bootid::{BootId, ContainerType, BOOTID_IV, BOOTID_KEY};
use crypto::{
    calculate_file_iv, calculate_page_iv, get_game_keys, Aes128CbcDec, GameKeys, EXFAT_HEADER,
    NTFS_HEADER, OPTION_IV, OPTION_KEY,
};
use indicatif::{ProgressBar, ProgressStyle};

mod bootid;
mod crypto;

const PAGE_SIZE: u64 = 4096;

fn exfat_timestamp_to_system_time(
    timestamp: &exfat_fs::timestamp::Timestamp,
) -> Result<SystemTime> {
    let exfat_date = timestamp.date();
    let exfat_time = timestamp.time();
    // exFAT UTC offset is in 15-minute intervals, so 1 = UTC+00:15, 2 = UTC+00:30, etc.
    let exfat_utc_offset = timestamp.utc_offset() as i32 * 15 * 60;
    let chrono_date_time = FixedOffset::east_opt(exfat_utc_offset)
        .ok_or_else(|| anyhow!("invaid utc offset: {}", timestamp.utc_offset()))?
        .with_ymd_and_hms(
            exfat_date.year as i32,
            exfat_date.month as u32,
            exfat_date.day as u32,
            exfat_time.hour as u32,
            exfat_time.minute as u32,
            exfat_time.second as u32,
        )
        .unwrap();

    return Ok(SystemTime::UNIX_EPOCH
        + Duration::from_micros(chrono_date_time.timestamp_micros().try_into()?));
}

fn extract_exfat_contents(exfat_path: &Path) -> Result<()> {
    println!("Extracting contents of {}", exfat_path.display());

    let file = File::open(exfat_path)?;
    let mut root = Root::open(file)?;

    // Create output directory with same name as exfat file (without extension)
    let output_dir = exfat_path.with_extension("");

    create_dir_all(&output_dir)?;
    extract_fs_elements(root.items(), &output_dir)?;

    Ok(())
}

fn extract_fs_elements(elements: &mut [FsElement<File>], output_dir: &Path) -> Result<()> {
    for element in elements {
        match element {
            FsElement::F(ref mut file) => {
                let dest_path = output_dir.join(file.name());
                let mut dest = File::create(dest_path)?;

                std::io::copy(file, &mut dest)?;

                dest.set_times(
                    FileTimes::new()
                        .set_accessed(exfat_timestamp_to_system_time(
                            file.timestamps().accessed(),
                        )?)
                        .set_modified(exfat_timestamp_to_system_time(
                            file.timestamps().modified(),
                        )?),
                )?;
            }
            FsElement::D(directory) => {
                let dest_path = output_dir.join(directory.name());
                create_dir_all(&dest_path)?;

                let mut children = directory.open()?;
                extract_fs_elements(&mut children, &dest_path)?;
            }
        }
    }

    Ok(())
}

fn main() -> Result<()> {
    let args = std::env::args().collect::<Vec<String>>();

    if args.len() < 2 {
        println!("Usage: fsdecrypt <input_file1> [<input_file2> ...]");
        return Ok(());
    }

    let bootid_cipher =
        Aes128CbcDec::new_from_slices(&BOOTID_KEY, &BOOTID_IV).map_err(|e| anyhow!(e))?;
    let mut bootid_bytes = [0u8; std::mem::size_of::<BootId>()];
    let mut page: Vec<u8> = Vec::with_capacity(PAGE_SIZE as usize);
    let mut page_iv = [0u8; 16];

    for path in args.iter().skip(1) {
        let path = Path::new(path);
        let file = File::open(path)?;
        let mut reader = BufReader::with_capacity(0x40000, file);

        reader.read_exact(&mut bootid_bytes)?;

        if let Err(e) = bootid_cipher
            .clone()
            .decrypt_padded_mut::<NoPadding>(&mut bootid_bytes)
        {
            println!("ERROR: Could not decrypt BootID: {e:#?}");
            continue;
        }

        let bootid = unsafe { std::mem::transmute::<[u8; 96], BootId>(bootid_bytes) };

        if bootid.container_type != ContainerType::OS
            && bootid.container_type != ContainerType::APP
            && bootid.container_type != ContainerType::OPTION
        {
            println!("ERROR: Unknown container type {}", bootid.container_type);
            continue;
        }

        let os_id = std::str::from_utf8(&bootid.os_id)?;
        let game_id = std::str::from_utf8(&bootid.game_id)?;
        let id = match bootid.container_type {
            ContainerType::OS => os_id,
            _ => game_id,
        };

        let keys = match bootid.container_type {
            ContainerType::OS => get_game_keys(os_id),
            ContainerType::APP => get_game_keys(game_id),
            _ => Some(GameKeys {
                key: OPTION_KEY,
                iv: Some(OPTION_IV),
            }),
        };

        let Some(keys) = keys else {
            println!("ERROR: Key not found for {id}. If you're using a custom key file, ensure the key file is 16/32 bytes and named {id}.bin.");
            continue;
        };

        let data_offset = bootid.header_block_count * bootid.block_size;
        let key = keys.key;
        let iv = if bootid.use_custom_iv { None } else { keys.iv };
        let iv = match iv {
            Some(iv) => iv,
            None => {
                reader.seek(SeekFrom::Start(data_offset))?;

                let reference = Read::by_ref(&mut reader);

                reference.take(4096).read_to_end(&mut page)?;

                if bootid.container_type == ContainerType::OPTION {
                    calculate_file_iv(key, EXFAT_HEADER, &page)?
                } else {
                    calculate_file_iv(key, NTFS_HEADER, &page)?
                }
            }
        };

        let output_filename = match bootid.container_type {
            ContainerType::OS => format!(
                "{os_id}_{:<04}.{:<02}.{:<02}_{}_{}.ntfs",
                bootid.os_version.major,
                bootid.os_version.minor,
                bootid.os_version.release,
                bootid.target_timestamp,
                bootid.sequence_number
            ),
            ContainerType::APP => {
                if bootid.sequence_number > 0 {
                    format!(
                        "{game_id}_{}.{:<02}.{:<02}_{}_{}_{}.{:<02}.{:<02}.ntfs",
                        unsafe { bootid.target_version.version.major },
                        unsafe { bootid.target_version.version.minor },
                        unsafe { bootid.target_version.version.release },
                        bootid.target_timestamp,
                        bootid.sequence_number,
                        bootid.source_version.major,
                        bootid.source_version.minor,
                        bootid.source_version.release,
                    )
                } else {
                    format!(
                        "{game_id}_{}.{:<02}.{:<02}_{}_{}.ntfs",
                        unsafe { bootid.target_version.version.major },
                        unsafe { bootid.target_version.version.minor },
                        unsafe { bootid.target_version.version.release },
                        bootid.target_timestamp,
                        bootid.sequence_number,
                    )
                }
            }
            _ => format!(
                "{game_id}_{}_{}_{}.exfat",
                unsafe { std::str::from_utf8(&bootid.target_version.option)? },
                bootid.target_timestamp,
                bootid.sequence_number,
            ),
        };
        let output_path = path.with_file_name(&output_filename);
        let output_file = File::create(&output_path)?;
        let output_size = (bootid.block_count - bootid.header_block_count) * bootid.block_size;

        output_file.set_len(output_size)?;

        let mut writer = BufWriter::with_capacity(0x40000, output_file);
        let cipher = Aes128Dec::new_from_slice(&key).map_err(|e| anyhow!(e))?;

        let pb = ProgressBar::new(output_size)
            .with_style(
                ProgressStyle::default_bar()
                    .template("{prefix} [{bar:20!.bright.yellow/dim.white}] {bytes:>8} [{elapsed}<{eta}, {bytes_per_sec}]")?
            );

        pb.set_prefix(output_filename.clone());
        reader.seek(SeekFrom::Start(data_offset))?;

        for _ in 0..output_size / PAGE_SIZE {
            let file_offset = reader.stream_position()? - data_offset;
            let reference = Read::by_ref(&mut reader);

            calculate_page_iv(file_offset, &iv, &mut page_iv);
            page.clear();
            reference.take(PAGE_SIZE).read_to_end(&mut page)?;

            let page_cipher = Aes128CbcDec::inner_iv_slice_init(cipher.clone(), &page_iv)
                .map_err(|e| anyhow!(e))?;
            page_cipher
                .decrypt_padded_mut::<NoPadding>(&mut page)
                .map_err(|e| anyhow!(e))?;

            writer.write_all(&page)?;
            pb.inc(PAGE_SIZE);
        }

        writer.flush()?;
        pb.finish();

        // Extract exfat contents if this is an exfat file
        if bootid.container_type == ContainerType::OPTION
            && output_path.extension().unwrap_or_default() == "exfat"
        {
            if let Err(e) = extract_exfat_contents(&output_path) {
                println!("WARNING: Failed to extract exfat contents: {e:#?}");
            } else {
                println!("Extracted exfat contents: {:?}", output_path);
                println!("Deleting exfat file: {:?}", output_path);

                std::fs::remove_file(output_path)?;
            }
        }

        page.clear();
        page_iv.fill(0);
        bootid_bytes.fill(0);
    }

    Ok(())
}
