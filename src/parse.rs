use std::fmt::{Display, Formatter};
use std::fs;
use std::path::PathBuf;

use crate::decode::decode_bencoded_value;
use crate::hash::calc_sha1;
use anyhow::Result;

/// Metainfo File Structure
///
/// All data in a metainfo file is bencoded.
///
/// The content of a metainfo file (the file ending in ".torrent") is a bencoded dictionary,
/// containing the keys listed below. All character string values are UTF-8 encoded.
///
/// https://wiki.theory.org/BitTorrentSpecification#Metainfo_File_Structure
#[derive(Debug)]
pub struct MetaInfo {
    /// The "announce" URL of the tracker
    pub announce: String,

    /// Info Dictionary
    pub info: Info,
}

/// Info Dictionary
///
/// A dictionary that describes the file(s) of the torrent. There are two possible forms:
/// one for the case of a 'single-file' torrent with no directory structure,
/// and one for the case of a 'multi-file' torrent.
///
/// We use the single-file variant.
///
/// https://wiki.theory.org/BitTorrentSpecification#Info_Dictionary
#[derive(Debug)]
pub struct Info {
    /// piece length: number of bytes in each piece (integer)
    plen: usize,

    /// pieces: string consisting of the concatenation of all 20-byte SHA1 hash values,
    /// one per piece (byte string, i.e. not urlencoded)
    pieces: String,
    // /// Single-file or multiple-file torrent
    // mode: Mode,
}

/// Single-file or multiple-file torrent
#[derive(Debug)]
pub enum Mode {
    SingleFile { name: String, length: usize },
    MultipleFile { name: String },
}

pub fn meta_info(path: &PathBuf) -> Result<MetaInfo> {
    let contents: Vec<u8> = fs::read(path)?;
    let contents: &[u8] = contents.as_ref();

    let decoded = decode_bencoded_value(contents)?;

    let announce = &decoded["announce"].to_string();
    let announce_len = announce.len();
    let announce = &announce[1..announce_len - 1];
    let announce = String::from(announce);

    let info = &decoded["info"];

    let plen = info["length"].to_string();
    let plen = plen.parse::<usize>()?;

    let pieces = calc_sha1(info)?;
    let pieces = String::from(&pieces[1..pieces.len() - 1]);

    // TODO
    let _mode = Mode::SingleFile {
        name: String::new(),
        length: 0,
    };

    Ok(MetaInfo {
        announce,
        info: Info { plen, pieces },
    })
}

impl Display for MetaInfo {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Tracker URL: {}\nLength: {}\nInfo Hash: {}\n",
            self.announce, self.info.plen, self.info.pieces
        )
    }
}

// d69f91e6b2ae4c542468d1073a71d4ea13879a7f
// d456af18f58438b96cc1ff7f636f08fd752b2a

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_info() {
        assert_eq!(
            "Tracker URL: http://bittorrent-test-tracker.codecrafters.io/announce\n\
            Length: 92063\nInfo Hash: d69f91e6b2ae4c542468d1073a71d4ea13879a7f\n",
            format!("{}", meta_info(&PathBuf::from("sample.torrent")).unwrap())
        );
    }
}
