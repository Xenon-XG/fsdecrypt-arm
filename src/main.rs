use std::{
    fs::{create_dir_all, File, FileTimes},
    io::{BufRead, BufReader, BufWriter, Write},
    path::{Path, PathBuf},
    time::{Duration, SystemTime},
};

use chrono::{FixedOffset, TimeZone};
use clap::Parser;
use exfat_fs::dir::{entry::fs::FsElement, Root};

use anyhow::{anyhow, Result};
use bootid::ContainerType;
use indicatif::{ProgressBar, ProgressStyle};
use ntfs::{
    indexes::NtfsFileNameIndex, structured_values::NtfsStandardInformation, Ntfs,
    NtfsAttributeType, NtfsTime,
};

use crate::stream::FscryptDecryptor;

mod bootid;
mod crypto;
mod stream;

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
    // Create output directory with same name as exfat file (without extension)
    let output_dir = exfat_path.with_extension("");

    let file = FscryptDecryptor::new(File::open(exfat_path)?).map_err(|e| anyhow!(e))?;
    let mut root = Root::open(file)?;

    let pb = ProgressBar::new(calculate_exfat_size(root.items())?)
        .with_style(
            ProgressStyle::default_bar().template(
                "{prefix} [{bar:20!.bright.yellow/dim.white}] {bytes:>8} [{elapsed}<{eta}, {bytes_per_sec}]",
            )?
        );
    pb.set_prefix(format!(
        "Extracting {}",
        exfat_path.file_name().unwrap().display(),
    ));

    create_dir_all(&output_dir)?;
    extract_exfat_elements(root.items(), &output_dir, &pb)?;

    pb.finish();

    Ok(())
}

fn calculate_exfat_size(elements: &[FsElement<FscryptDecryptor<File>>]) -> Result<u64> {
    let mut total = 0;

    for element in elements {
        match element {
            FsElement::F(ref file) => total += file.len(),
            FsElement::D(directory) => total += calculate_exfat_size(&directory.open()?)?,
        }
    }

    Ok(total)
}

fn extract_exfat_elements(
    elements: &mut [FsElement<FscryptDecryptor<File>>],
    output_dir: &Path,
    pb: &ProgressBar,
) -> Result<()> {
    for element in elements {
        match element {
            FsElement::F(ref mut file) => {
                let dest_path = output_dir.join(file.name());
                let mut dest = File::create(dest_path)?;

                dest.set_times(
                    FileTimes::new()
                        .set_accessed(exfat_timestamp_to_system_time(
                            file.timestamps().accessed(),
                        )?)
                        .set_modified(exfat_timestamp_to_system_time(
                            file.timestamps().modified(),
                        )?),
                )?;

                let mut writer = BufWriter::with_capacity(256 * 1024, &mut dest);

                std::io::copy(file, &mut writer)?;
                writer.flush()?;
                pb.inc(file.len());
            }
            FsElement::D(directory) => {
                let dest_path = output_dir.join(directory.name());
                create_dir_all(&dest_path)?;

                let mut children = directory.open()?;
                extract_exfat_elements(&mut children, &dest_path, &pb)?;
            }
        }
    }

    Ok(())
}

fn ntfs_time_to_system_time(ntfs_time: NtfsTime) -> SystemTime {
    // An NTFS "interval" is 100 nanoseconds.
    // The Windows epoch is 1601-01-01, while the Unix epoch is 1970-01-01.
    let intervals_since_windows_epoch = ntfs_time.nt_timestamp();
    let intervals_since_unix_epoch = intervals_since_windows_epoch - 116_444_736_000_000_000;
    let nanos_since_unix_epoch = intervals_since_unix_epoch * 100;

    return SystemTime::UNIX_EPOCH + Duration::from_nanos(nanos_since_unix_epoch);
}

fn extract_internal_vhd(image_path: &Path, sequence_number: u8) -> Result<PathBuf> {
    let vhd_filename = format!("internal_{sequence_number}.vhd");
    let output_path = image_path.with_extension("vhd");

    let mut fs = FscryptDecryptor::new(File::open(image_path)?).map_err(|e| anyhow!(e))?;

    let mut ntfs = Ntfs::new(&mut fs)?;

    ntfs.read_upcase_table(&mut fs)?;

    let root_directory = ntfs.root_directory(&mut fs)?;
    let index = root_directory.directory_index(&mut fs)?;
    let mut finder = index.finder();
    let entry = NtfsFileNameIndex::find(&mut finder, &ntfs, &mut fs, &vhd_filename)
        .ok_or_else(|| anyhow!("could not find VHD {vhd_filename}"))??;
    let file = entry.to_file(&ntfs, &mut fs)?;
    let data_item = file
        .data(&mut fs, "")
        .ok_or_else(|| anyhow!("file data does not exist"))??;
    let data_attribute = data_item.to_attribute()?;
    let mut data_value =
        BufReader::with_capacity(256 * 1024, data_attribute.value(&mut fs)?.attach(&mut fs));

    let mut output_file = File::create(&output_path)?;

    let pb = ProgressBar::new(data_attribute.value_length() as u64)
        .with_style(
            ProgressStyle::default_bar()
                .template("{prefix} [{bar:20!.bright.yellow/dim.white}] {bytes:>8} [{elapsed}<{eta}, {bytes_per_sec}]")?
        );
    pb.set_prefix(format!("{}", output_path.file_name().unwrap().display()));

    loop {
        let buffer = data_value.fill_buf()?;
        let length = buffer.len();

        if length == 0 {
            break;
        }

        output_file.write_all(buffer)?;
        data_value.consume(length);
        pb.inc(length as u64);
    }
    output_file.flush()?;

    pb.finish();

    let mut attributes_iterator = file.attributes();

    while let Some(attribute) = attributes_iterator.next(&mut fs) {
        let attribute = attribute?;
        let attribute = attribute.to_attribute()?;

        match attribute.ty() {
            Ok(NtfsAttributeType::StandardInformation) => {
                let info = attribute.resident_structured_value::<NtfsStandardInformation>()?;

                output_file.set_times(
                    FileTimes::new()
                        .set_accessed(ntfs_time_to_system_time(info.access_time()))
                        .set_modified(ntfs_time_to_system_time(info.modification_time())),
                )?;

                break;
            }
            _ => continue,
        }
    }

    Ok(output_path)
}

#[derive(Parser)]
#[command(version, about = "decryptor for some SEGA containers", long_about = None)]
struct Cli {
    #[arg(long, help = "do not extract contents of decrypted image")]
    no_extract: bool,

    #[arg(required = true)]
    files: Vec<PathBuf>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    for path in &cli.files {
        let file = FscryptDecryptor::new(File::open(path)?).map_err(|e| anyhow!(e))?;
        let bootid = file.bootid.clone();
        let output_filename = file.filename()?;
        let output_path = path.with_file_name(&output_filename);

        // Can't directly extract options since we can't impl exfat_fs::dir::ReadOffset
        // for our wrapper decryptor
        if cli.no_extract {
            let mut output_file = File::create(&output_path)?;

            output_file.set_len(file.len())?;

            let pb = ProgressBar::new(file.len())
                .with_style(
                    ProgressStyle::default_bar()
                        .template("{prefix} [{bar:20!.bright.yellow/dim.white}] {bytes:>8} [{elapsed}<{eta}, {bytes_per_sec}]")?
                );

            pb.set_prefix(output_filename.clone());

            let mut reader = BufReader::with_capacity(0x40000, file);

            loop {
                let buffer = reader.fill_buf()?;
                let length = buffer.len();

                if length == 0 {
                    break;
                }

                output_file.write_all(&buffer)?;
                reader.consume(length);

                pb.inc(length as u64);
            }

            output_file.flush()?;
        } else {
            match bootid.container_type {
                ContainerType::OS | ContainerType::APP => {
                    match extract_internal_vhd(&path, bootid.sequence_number) {
                        Ok(_) => {}
                        Err(e) => {
                            println!("WARNING: Failed to extract internal VHD: {e:#?}");
                        }
                    }
                }
                ContainerType::OPTION => match extract_exfat_contents(&path) {
                    Ok(_) => {}
                    Err(e) => {
                        println!("WARNING: Failed to extract exfat contents: {e:#?}");
                    }
                },
                _ => {
                    println!("WARNING: Unknown container type: {}", bootid.container_type);
                }
            }
        }
    }

    Ok(())
}
