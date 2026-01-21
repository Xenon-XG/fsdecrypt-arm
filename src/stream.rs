use std::{
    fs::File,
    io::{self, Read, Seek, SeekFrom},
    str::Utf8Error,
};

use aes::cipher::{
    block_padding::{NoPadding, UnpadError},
    BlockDecryptMut, InvalidLength,
};
use cipher::KeyIvInit;
use exfat_fs::disk::ReadOffset;

use crate::{
    bootid::{BootId, ContainerType, BOOTID_IV, BOOTID_KEY},
    crypto::{
        calculate_file_iv, calculate_page_iv, get_game_keys, Aes128CbcDec, GameKeys, EXFAT_HEADER,
        NTFS_HEADER, OPTION_IV, OPTION_KEY,
    },
};

const PAGE_SIZE: u64 = 4096;

#[derive(Debug, thiserror::Error)]
pub enum DecryptError {
    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Utf8(#[from] std::str::Utf8Error),

    #[error(transparent)]
    Unknown(#[from] anyhow::Error),

    #[error("Invalid IV length: {0:?}")]
    AesInvalidLength(InvalidLength),

    #[error("Malformed padding: {0:?}")]
    AesUnpadError(UnpadError),

    #[error("Unknown container type {0}")]
    InvalidContainerType(u8),

    #[error("There were no decryption keys for this container.")]
    NoMatchingKeys,
}

/// Decryptor for an fscrypt container.
#[derive(Debug)]
pub struct FscryptDecryptor<R> {
    /// The fscrypt file.
    input: R,

    /// The fscrypt file's bootid.
    pub bootid: BootId,

    key: [u8; 16],
    iv: [u8; 16],

    encrypted_page: Vec<u8>,
    plaintext_pos: u64,
    page: Option<Vec<u8>>,
}

impl<R> FscryptDecryptor<R> {
    pub fn len(&self) -> u64 {
        self.bootid.block_size * (self.bootid.block_count - self.bootid.header_block_count)
    }

    pub fn filename(&self) -> Result<String, Utf8Error> {
        let bootid = self.bootid;
        let os_id = std::str::from_utf8(&bootid.os_id)?;
        let game_id = std::str::from_utf8(&bootid.game_id)?;

        let filename = match bootid.container_type {
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

        Ok(filename)
    }
}

impl<R: Read + Seek> FscryptDecryptor<R> {
    pub fn new(mut input: R) -> Result<Self, DecryptError> {
        let bootid_cipher = Aes128CbcDec::new_from_slices(&BOOTID_KEY, &BOOTID_IV)
            .map_err(|e| DecryptError::AesInvalidLength(e))?;
        let mut bootid_bytes = [0u8; std::mem::size_of::<BootId>()];

        input.read_exact(&mut bootid_bytes)?;
        bootid_cipher
            .decrypt_padded_mut::<NoPadding>(&mut bootid_bytes)
            .map_err(|e| DecryptError::AesUnpadError(e))?;

        let bootid: BootId = unsafe { std::mem::transmute(bootid_bytes) };

        if bootid.container_type != ContainerType::OS
            && bootid.container_type != ContainerType::APP
            && bootid.container_type != ContainerType::OPTION
        {
            return Err(DecryptError::InvalidContainerType(bootid.container_type));
        }

        let data_offset = bootid.header_block_count * bootid.block_size;
        let mut page: Vec<u8> = Vec::with_capacity(PAGE_SIZE as usize);
        let keys = match bootid.container_type {
            ContainerType::OS => get_game_keys(std::str::from_utf8(&bootid.os_id)?),
            ContainerType::APP => get_game_keys(std::str::from_utf8(&bootid.game_id)?),
            _ => Some(GameKeys {
                key: OPTION_KEY,
                iv: Some(OPTION_IV),
            }),
        };
        let Some(keys) = keys else {
            return Err(DecryptError::NoMatchingKeys);
        };
        let iv = if bootid.use_custom_iv { None } else { keys.iv };
        let iv = match iv {
            Some(iv) => iv,
            None => {
                input.seek(SeekFrom::Start(data_offset))?;

                let reference = Read::by_ref(&mut input);

                reference.take(PAGE_SIZE).read_to_end(&mut page)?;

                if bootid.container_type == ContainerType::OPTION {
                    calculate_file_iv(keys.key, EXFAT_HEADER, &page)?
                } else {
                    calculate_file_iv(keys.key, NTFS_HEADER, &page)?
                }
            }
        };

        input.seek(SeekFrom::Start(data_offset))?;

        Ok(Self {
            input,
            bootid,
            key: keys.key,
            iv,
            encrypted_page: Vec::with_capacity(PAGE_SIZE as usize),
            plaintext_pos: 0,
            page: None,
        })
    }

    fn decrypt_page(&mut self) -> io::Result<()> {
        let page = &self.encrypted_page;
        let file_offset = self.input.stream_position()?
            - (self.bootid.header_block_count * self.bootid.block_size)
            - PAGE_SIZE;
        let mut page_iv = [0u8; 16];

        calculate_page_iv(file_offset, &self.iv, &mut page_iv);

        let page_cipher = Aes128CbcDec::new_from_slices(&self.key, &page_iv).unwrap();

        self.page = Some(
            page_cipher
                .decrypt_padded_vec_mut::<NoPadding>(&page)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "failed to decrypt"))?,
        );
        self.encrypted_page.clear();

        Ok(())
    }

    fn read_from_page(&mut self, buf: &mut [u8]) -> usize {
        let Some(ref page) = self.page else {
            return 0;
        };

        let page_offset = (self.plaintext_pos % PAGE_SIZE) as usize;
        let to_read = std::cmp::min(page.len() - page_offset, buf.len());

        buf[..to_read].copy_from_slice(&page[page_offset..page_offset + to_read]);

        self.plaintext_pos += to_read as u64;

        if self.plaintext_pos % PAGE_SIZE == 0 {
            self.page = None;
        }

        to_read
    }
}

impl<R: Read + Seek> Read for FscryptDecryptor<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.page.is_none() {
            if (self.encrypted_page.len() as u64) < PAGE_SIZE {
                Read::by_ref(&mut self.input)
                    .take(PAGE_SIZE)
                    .read_to_end(&mut self.encrypted_page)?;
            }

            self.decrypt_page()?;
        }

        Ok(self.read_from_page(buf))
    }
}

impl<R: Read + Seek> Seek for FscryptDecryptor<R> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let start = self.bootid.header_block_count * self.bootid.block_size;
        let target_pos = match pos {
            SeekFrom::Start(offset) => offset,
            SeekFrom::Current(offset) => {
                let res = (self.plaintext_pos as i64) + offset;

                if res < 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "cannot seek before the start",
                    ));
                }

                res as u64
            }
            SeekFrom::End(offset) => {
                let length = (self.bootid.block_count - self.bootid.header_block_count)
                    * self.bootid.block_size;
                let res = (length as i64) + offset;

                if res < 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "cannot seek before the start",
                    ));
                }

                res as u64
            }
        };
        let page_index = self.plaintext_pos / PAGE_SIZE;
        let target_index = target_pos / PAGE_SIZE;
        let target_offset = target_pos % PAGE_SIZE;

        if page_index == target_index {
            self.plaintext_pos = target_pos;
            return Ok(target_pos);
        }

        self.page = None;
        self.input
            .seek(SeekFrom::Start(start + target_index * PAGE_SIZE))?;
        self.plaintext_pos = target_index * PAGE_SIZE;

        if target_offset > 0 {
            let mut to_drop = vec![0; target_offset as usize];
            self.read_exact(&mut to_drop)?;
        }

        Ok(target_pos)
    }
}

impl ReadOffset for FscryptDecryptor<File> {
    type Err = std::io::Error;

    fn read_at(&self, offset: u64, buffer: &mut [u8]) -> Result<usize, Self::Err> {
        let start = self.bootid.header_block_count * self.bootid.block_size;
        let target_index = offset / PAGE_SIZE;
        let target_offset = offset % PAGE_SIZE;
        let mut page = [0u8; 4096];
        let mut page_iv = [0u8; 16];
        let page_offset = target_index * PAGE_SIZE;

        #[cfg(unix)]
        std::os::unix::fs::FileExt::read_at(&self.input, &mut page, start + page_offset)?;

        #[cfg(windows)]
        std::os::windows::fs::FileExt::seek_read(&self.input, &mut page, start + page_offset)?;

        calculate_page_iv(page_offset, &self.iv, &mut page_iv);

        let page_cipher = Aes128CbcDec::new_from_slices(&self.key, &page_iv).unwrap();

        page_cipher
            .decrypt_padded_mut::<NoPadding>(&mut page)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "failed to decrypt"))?;

        let to_read = std::cmp::min(buffer.len(), (PAGE_SIZE - target_offset) as usize);

        buffer[..to_read]
            .copy_from_slice(&page[target_offset as usize..target_offset as usize + to_read]);

        Ok(to_read)
    }
}
