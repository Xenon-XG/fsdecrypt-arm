use std::path::Path;

use aes::cipher::{block_padding::NoPadding, BlockDecryptMut, KeyIvInit};
use anyhow::{anyhow, Result};
use hex_literal::hex;

pub const NTFS_HEADER: [u8; 16] = hex!("eb52904e544653202020200010010000");
pub const EXFAT_HEADER: [u8; 16] = hex!("eb769045584641542020200000000000");

pub const OPTION_KEY: [u8; 16] = hex!("5c84a9e726eaa5dd351f2b0750c23697");
pub const OPTION_IV: [u8; 16] = hex!("c063bf6f562d084d7963c987f5281761");

pub type Aes128CbcDec = cbc::Decryptor<aes::Aes128Dec>;

#[derive(Debug, Clone, Copy)]
pub struct GameKeys {
    pub key: [u8; 16],
    pub iv: Option<[u8; 16]>,
}

pub fn calculate_page_iv(file_offset: u64, file_iv: &[u8], page_iv: &mut [u8]) {
    for (i, (fbyte, pbyte)) in file_iv.iter().zip(page_iv.iter_mut()).enumerate() {
        *pbyte = fbyte ^ (file_offset >> (8 * (i % 8))) as u8;
    }
}

pub fn calculate_file_iv(
    key: [u8; 16],
    expected_header: [u8; 16],
    first_page: &[u8],
) -> Result<[u8; 16]> {
    let mut iv = [0u8; 16];
    let mut header = [0u8; 16];

    header.copy_from_slice(&first_page[..16]);

    calculate_page_iv(0, &expected_header, &mut iv);

    let cipher = Aes128CbcDec::new_from_slices(&key, &iv).map_err(|e| anyhow!(e))?;

    cipher
        .decrypt_padded_mut::<NoPadding>(&mut header)
        .map_err(|e| anyhow!(e))?;

    Ok(header)
}

pub fn get_game_keys(game_id: &str) -> Option<GameKeys> {
    match game_id {
        // Nu Firmware / Hardware Test
        "SBZS" => Some(GameKeys {
            key: hex!("2ecbcff65ce0abecc10547f8ac8351d8"),
            iv: Some(hex!("f2ac6c2817d0574bba113d497e319f3e")),
        }),

        // KEY CHIP NU FACTORY / KEY CHIP NUSX FACTORY
        "SBZT" => Some(GameKeys {
            key: hex!("9ab9ce55ed9c194a715a73a7699f795b"),
            iv: Some(hex!("8552de88fedda6e859369fb000f44d5b")),
        }),

        // Nu Firmware / Hardware Test
        "SBZU" => Some(GameKeys {
            key: hex!("eb1228254cdd3077eb3e441c0227bf40"),
            iv: Some(hex!("3f9b4676118cee129fe2f1cb2747bca5")),
        }),

        // Project DIVA Arcade Future Tone
        "SBZV" => Some(GameKeys {
            key: hex!("3274a399594d84779625940b69c02d3f"),
            iv: Some(hex!("675ba66d29c87923f5f154c406afee42")),
        }),

        // Wonderland Wars
        "SDAP" => Some(GameKeys {
            key: hex!("41b5027c5e99d94aa9335d6d71838ecf"),
            iv: Some(hex!("41b5027c5e99d94aa9335d6d71838ecf")),
        }),

        // Herobank Arcade
        "SDAQ" => Some(GameKeys {
            key: hex!("c28f22bc1b339ae64180739886dc83d6"),
            iv: Some(hex!("0a29fd145d72bf8dedd436025df0a9fc")),
        }),

        // Uranai Collection: Torotte
        "SDAV" => Some(GameKeys {
            key: hex!("eed95513266a499a55e265b049169c44"),
            iv: Some(hex!("84c0e5931d91a6a477d62c271546056e")),
        }),

        // Shin Kouchuu Ouja Mushiking
        "SDBE" => Some(GameKeys {
            key: hex!("7053fb944572e5b631a665cef4b5bcdd"),
            iv: Some(hex!("ae4d7e884002c79eb35711554d613057")),
        }),

        // E-DEL Sand
        "SDBN" => Some(GameKeys {
            key: hex!("c1f14ae2e85b095e313c8baec125805e"),
            iv: Some(hex!("3c538eea66251acd5404b93f8976a7f7")),
        }),

        // CHUNITHM
        "SDBT" => Some(GameKeys {
            key: hex!("a6a870671fd432ec637adf7a822f97da"),
            iv: Some(hex!("2c277f31cd550cfa2c993b4dd56b85ae")),
        }),

        // Sonic Dash Extreme
        "SDBX" => Some(GameKeys {
            key: hex!("3dc19c2d0c20ac199d5fa46e7f6335a6"),
            iv: Some(hex!("d8f029ec90fe55be67584f742c55ef8b")),
        }),

        // Kancolle Arcade
        "SDBZ" => Some(GameKeys {
            key: hex!("521bde4460f4184edd879136adeea5ee"),
            iv: Some(hex!("1b8324032db69d7b0954794aa229fe68")),
        }),

        // crossbeats REV.
        "SDCA" => Some(GameKeys {
            key: hex!("1649490a03d6c2aec1c496982cb0405c"),
            iv: Some(hex!("4680711c7e67a26f9230d5af74b5dcfb")),
        }),

        // nailpuri
        "SDCD" => Some(GameKeys {
            key: hex!("43b38502d8f6d3c7b02b95fc28db5308"),
            iv: Some(hex!("6dfcb94bf74f152b55f3e0c7f35b44b5")),
        }),

        // Luigi's Mansion Arcade
        "SDCF" => Some(GameKeys {
            key: hex!("df986883da837538e37b959a3e4117cd"),
            iv: Some(hex!("dabf539738852f17714811af70435a83")),
        }),

        // Mario & Sonic at Rio Olympic Games
        "SDCH" => Some(GameKeys {
            key: hex!("e2da769e94f1d3aca1930cdbe0708c9f"),
            iv: Some(hex!("c7dcce203c84ab0477236d697570dadc")),
        }),

        // KEY CHIP NUSX EDB SOC
        "SDCR" => Some(GameKeys {
            key: hex!("4961a51fd36f14e72664f52373052160"),
            iv: Some(hex!("25d7d1341a282c5e0a34c64562c023ec")),
        }),

        // Celevie
        "SDCT" => Some(GameKeys {
            key: hex!("d6ae51f10ec76da93c981800fc3ad3cb"),
            iv: Some(hex!("fb8e43e280d330d06581732f2e11a6dc")),
        }),

        // CYTUS Ω
        "SDCX" => Some(GameKeys {
            key: hex!("79504ccc509b67d1f7a3f593e6f9d9d6"),
            iv: Some(hex!("1551ea8926f2aee233eec309de3e5f3c")),
        }),

        // KEY CHIP NUSX1.1 TDW
        "SDDB" => Some(GameKeys {
            key: hex!("875679b2cd1637962b0db25c51fb21a6"),
            iv: Some(hex!("8ef44722a0566e8f572356245687fbe5")),
        }),

        // Sangokushi Taisen
        "SDDD" => Some(GameKeys {
            key: hex!("564e967873de6cbcd22efeca6952e9dc"),
            iv: Some(hex!("4e3dd465cf09cd82b259f7bed5fc2d6d")),
        }),

        // Initial D Arcade Stage Zero
        "SDDF" => Some(GameKeys {
            key: hex!("65058573a0cb81749e694ae164c61b04"),
            iv: Some(hex!("981c4f45e3c6958f054e5d00916bdf2b")),
        }),

        // KEY CHIP NU1.1 ESC
        "SDDJ" => Some(GameKeys {
            key: hex!("630fe52276537bd7fb267adf175f4e99"),
            iv: Some(hex!("dc5755be57ded2cdb34433bbba2204ff")),
        }),

        // APM3 Sample Program 2
        "SDDL" => Some(GameKeys {
            key: hex!("992458295fd06d6a8af0dfb3f6854c19"),
            iv: Some(hex!("8484906d4cd5fd225e032843ed37495d")),
        }),

        // ALLS MX Factory Dummy
        "SDDM" => Some(GameKeys {
            key: hex!("0127958210f6ae9bdeb8975018b5af24"),
            iv: Some(hex!("181716badccff4bc2b1e29ae02a1bbbb")),
        }),

        // Demo ID
        "SDDN" => Some(GameKeys {
            key: hex!("41dd8e66290117ac67d311a2f0a6416e"),
            iv: Some(hex!("73e18e8418f6ceefb11e2767fdea190c")),
        }),

        // Soul Reverse
        "SDDP" => Some(GameKeys {
            key: hex!("cf6d64427eeca47674e17bcd46d1ea8c"),
            iv: Some(hex!("ce5174093d26ca2a31b58541e85ac276")),
        }),

        // SEGA World Driver Championship
        "SDDS" => Some(GameKeys {
            key: hex!("161bec6d90989d0e26d791170607a440"),
            iv: Some(hex!("81dc26a27028e2092332038aa1bffc47")),
        }),

        // O.N.G.E.K.I.
        "SDDT" => Some(GameKeys {
            key: hex!("3f7658728b9517d3314e684fa2e2a045"),
            iv: Some(hex!("41578833c547aaff04db597a6e9eb784")),
        }),

        "SDDU" => Some(GameKeys {
            key: hex!("649ae9982625f90c55af86713c55d3fd"),
            iv: Some(hex!("187116fc4647a7d3b6f2303a34f0a2fe")),
        }),

        // ALLS X / X2 Research & Development
        "SDDW" => Some(GameKeys {
            key: hex!("118565d344f3e14ca69299eeac049bb9"),
            iv: Some(hex!("9d6d392ec35ed94ef9fe0a5be0573981")),
        }),

        // KEY CHIP ALLS X FACTORY
        "SDDX" => Some(GameKeys {
            key: hex!("428bff0f9e7aafc169a7a75751ffda98"),
            iv: Some(hex!("f8250594f425332c6d349d7ea0e86669")),
        }),

        // Shin Kouchuu Ouja Mushiking TWN
        "SDEA" => Some(GameKeys {
            key: hex!("9f9cf148ac3c50aaf925af1dfb27f58b"),
            iv: Some(hex!("4d8ebbd971896b8a4a3dd84a23b329fc")),
        }),

        // WCCF FOOTISTA
        "SDEB" => Some(GameKeys {
            key: hex!("d511ed690415f6359843a134fd47836a"),
            iv: Some(hex!("ac139b382acdd112e31564ea7f38186c")),
        }),

        // Chrono Regalia
        "SDEC" => Some(GameKeys {
            key: hex!("f272e5016863af2ba0337f50de686f6e"),
            iv: Some(hex!("5327e132631e7f71b61be7cc0df382ce")),
        }),

        // CARD MAKER
        "SDED" => Some(GameKeys {
            key: hex!("21fcec779a16769f5277a36fb542992c"),
            iv: Some(hex!("22b50239f1b40ccc3e55a2d69c69b160")),
        }),

        // House of the Dead: Scarlet Dawn
        "SDEE" => Some(GameKeys {
            key: hex!("191eb7440672dab08ddbb7195efb356f"),
            iv: Some(hex!("c278b5386dc38bd76d71dbcd826954cf")),
        }),

        // FiZ
        "SDEG" => Some(GameKeys {
            key: hex!("721853dbe2d30bafe24f0edbd210deeb"),
            iv: Some(hex!("4dfb0bcec86159aab297166bcd509e6f")),
        }),

        // Fate/Grand Order Arcade
        "SDEJ" => Some(GameKeys {
            key: hex!("9de1ea6ae38d9011f55d8ee864395d24"),
            iv: Some(hex!("f60cde21982876d12d17662a48d90836")),
        }),

        // ALL.Net P.ras multi Ver.3
        "SDEM" => Some(GameKeys {
            key: hex!("700617f293696c07fb9f356d3b99240d"),
            iv: Some(hex!("667d026d6cdf329ff351dbaf7098e81d")),
        }),

        // StarHorse4 (Server) / MESTA Medal Station
        "SDEP" => Some(GameKeys {
            key: hex!("fa2b7ca53a823c152d940972cbf532f5"),
            iv: Some(hex!("f4af35120c48617704bb5b8471797a62")),
        }),

        // Initial D Arcade Stage Zero (CHN)
        "SDER" => Some(GameKeys {
            key: hex!("7d73367ebb218ec82930d58dc6d7950b"),
            iv: Some(hex!("9788c3eca2db6ba92bac4f6f7b706308")),
        }),

        // House of the Dead: Scarlet Dawn (EXP)
        "SDET" => Some(GameKeys {
            key: hex!("4643e7b2c3006e0264163edc8545fb72"),
            iv: Some(hex!("612bca81ea2958ffbac36f780f1ed688")),
        }),

        // KEY CHIP ALLS X HDZ
        "SDEU" => Some(GameKeys {
            key: hex!("23b3e9bb47e3ac9998f6e6c1adc4ae33"),
            iv: Some(hex!("a964714cea60688407bf554bd1c27ec2")),
        }),

        // House of the Dead: Scarlet Dawn (CHN)
        "SDEV" => Some(GameKeys {
            key: hex!("3c1f018d88926d98163b07a1563a4818"),
            iv: Some(hex!("ca7373c9c7dfebac0fc24254c030e4ad")),
        }),

        // maimai DX
        "SDEZ" => Some(GameKeys {
            key: hex!("d136eba05d40e82682e6aad8d9e8688c"),
            iv: Some(hex!("c484deeaa0249ef46695f63694b7372f")),
        }),

        // KEY CHIP ALLS X REC
        "SDFA" => Some(GameKeys {
            key: hex!("8e816b4362db24a230877885864d206d"),
            iv: Some(hex!("8e5a0ba6a0a1150d47d12bdb64debba7")),
        }),

        // WACCA
        "SDFE" => Some(GameKeys {
            key: hex!("f61719c371e5bca6788c139a53091617"),
            iv: Some(hex!("67d43173e343813fa2097fd32992a8e2")),
        }),

        // SANDRA
        "SDFG" => Some(GameKeys {
            key: hex!("3398fb86bfe630a14979411879861ac7"),
            iv: Some(hex!("a794c49c2c7639cd80571807c17246ff")),
        }),

        // Kemono Friends 3: Planet Tours
        "SDFL" => Some(GameKeys {
            key: hex!("2449b48067b9176a6e0f9563481e97f4"),
            iv: Some(hex!("616f8710454632eb4fb1d89d8c19c19a")),
        }),

        // KEY CHIP ALLS X CASJ
        "SDFN" => Some(GameKeys {
            key: hex!("29f62e22c6a9fd8be327631c68546405"),
            iv: Some(hex!("2a860976e6d98513825f291e56cfb5ee")),
        }),

        // KEY CHIP NUSX FUTURE
        "SDFP" => Some(GameKeys {
            key: hex!("570b87263a7ca0aa4c1388e204ee6d4b"),
            iv: Some(hex!("7640886011a2300a91fad9f36a8c4775")),
        }),

        // StarHorse4
        "SDFT" => Some(GameKeys {
            key: hex!("92a25f388c50737e39c3c2f006645f31"),
            iv: Some(hex!("a97e72f990417488cb4c67f8f0c3fb25")),
        }),

        // Mario & Sonic at TOKYO Olympic
        "SDFV" => Some(GameKeys {
            key: hex!("fe82db9a60295d829b95f03c2276018b"),
            iv: Some(hex!("34d82772ae18174f0a181dc53399ea9c")),
        }),

        // maimai DX (EXP)
        "SDGA" => Some(GameKeys {
            key: hex!("0a6610a62ef670c65b7e7b1750ffb7a1"),
            iv: Some(hex!("17a2a22915f81c5896edbba4c412585e")),
        }),

        // maimai DX (CHN)
        "SDGB" => Some(GameKeys {
            key: hex!("7ca4e6b6f3d6e8b26472973887d7fa3a"),
            iv: Some(hex!("53fe7135762de3f97e7fe76b0fef3f27")),
        }),

        // Puyo Puyo e-Sports Arcade
        "SDGH" => Some(GameKeys {
            key: hex!("b3e30e7eabac3767ade13c69c9b2f22b"),
            iv: Some(hex!("03deaea3742d69675b36cddc8b15ac91")),
        }),

        // WCCF FOOTISTA (EXP)
        "SDGK" => Some(GameKeys {
            key: hex!("9dc4a17fc39fca5a8a358984801caaa7"),
            iv: Some(hex!("e0445b11dcfa0dae56c85e8787e11d9b")),
        }),

        // KEY CHIP ALLS X HDZ CASJ
        "SDGP" => Some(GameKeys {
            key: hex!("c87ab31247e7b6ff95fdd79fb91f9f37"),
            iv: Some(hex!("2467ab3c031e3dc0568b7077efd27c36")),
        }),

        // ROKUMEN
        "SDGQ" => Some(GameKeys {
            key: hex!("c5356dae7b066bce88984aec36deb62d"),
            iv: Some(hex!("4e9f2982460e2fd907bde15709edfba7")),
        }),

        // CHUNITHM (EXP)
        "SDGS" => Some(GameKeys {
            key: hex!("a5150cc5065d2c59ee2f8f332cbd29d5"),
            iv: Some(hex!("84014d26696f290ad7ead70c7549bd81")),
        }),

        // Initial D THE ARCADE
        "SDGT" => Some(GameKeys {
            key: hex!("9d0bba20d1e84f2459399f5383beee72"),
            iv: Some(hex!("5d340013fdfb2464d253093602fe4b64")),
        }),

        "SDGV" => Some(GameKeys {
            key: hex!("573f5c8cc44f10f31ec749b695ebe886"),
            iv: Some(hex!("6bfca86f9d208a7944cdfc25ea3cd220")),
        }),

        // "Eiketsu Taisen: Sanzensekai no Hadou
        "SDGY" => Some(GameKeys {
            key: hex!("c04b663a59055acbdfebc6d3df0e6a04"),
            iv: Some(hex!("76fc5f1d88605107947d0c1ff347022d")),
        }),

        // Hori a Tale
        "SDGZ" => Some(GameKeys {
            key: hex!("9ad74efb208d6ee4fe5ee770331712cf"),
            iv: Some(hex!("45f6e53f0eb8fae6665b45444a61e266")),
        }),

        // CHUNITHM NEW!!
        "SDHD" => Some(GameKeys {
            key: hex!("3abd00d7a820ce862eaf474bf6c8f33e"),
            iv: Some(hex!("0f1e7eea78da7e037e0552c2843e1b6a")),
        }),

        "SDHH" => Some(GameKeys {
            key: hex!("fc6f887f3717c5d6713113b92fa3fb27"),
            iv: Some(hex!("ad76606460dbe1e91e41bef7ab0c1535")),
        }),

        // CHUNITHM (CHN)
        "SDHJ" => Some(GameKeys {
            key: hex!("985ea66ecb5b1f208c90e2b898f0b073"),
            iv: Some(hex!("164a65422e7f01b7f1b0849fc7737cdb")),
        }),

        // UFO CATCHER LINK STATION
        "SDHK" => Some(GameKeys {
            key: hex!("bc92d63c2a099ca2315a483c3041fdd7"),
            iv: Some(hex!("b14d8449b6d4325d83a2774b13dd21ff")),
        }),

        // WACCA (CHN)
        "SDHN" => Some(GameKeys {
            key: hex!("892123a26d7c03d49edd12a80ee0c58f"),
            iv: Some(hex!("76aa15a6868b8dbdf7207906354d5169")),
        }),

        // meityromantic
        "SDHR" => Some(GameKeys {
            key: hex!("1fb897cab97c8170a6ac0a21685c58d9"),
            iv: Some(hex!("f9b60f65b01e8e836a4bc20f7d39faf5")),
        }),

        // ALLS System
        "ACA" => Some(GameKeys {
            key: hex!("e4281bcf48c4d28eb05772ce6f98587a"),
            iv: Some(hex!("6cee7f5a2c4b5f1e93c5949114ff0b74")),
        }),

        // Read from {game_id}.bin for unknown keys.
        _ => {
            let filename = format!("{}.bin", game_id);
            let path = Path::new(&filename);

            if !path.exists() {
                return None;
            }

            let Ok(metadata) = path.metadata() else {
                return None;
            };

            let size = metadata.len();

            match size {
                16 => Some(GameKeys {
                    key: std::fs::read(filename)
                        .map(|v| v.try_into().unwrap())
                        .unwrap(),
                    iv: None,
                }),
                32 => {
                    let keyiv = std::fs::read(filename).unwrap();
                    let key = keyiv[..16].try_into().unwrap();
                    let iv: [u8; 16] = keyiv[16..].try_into().unwrap();
                    let iv = if iv == NTFS_HEADER || iv == EXFAT_HEADER {
                        None
                    } else {
                        Some(iv)
                    };

                    Some(GameKeys { key, iv })
                }
                _ => None,
            }
        }
    }
}
