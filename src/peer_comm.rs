//! # Peer Communication Facilities
//!
//! These are CLI commands per project requirements.
//!
//! ## Peer Wire Protocol & Handshake
//!
//! https://www.bittorrent.org/beps/bep_0003.html#peer-protocol
//!
//! https://wiki.theory.org/BitTorrentSpecification#Peer_wire_protocol_.28TCP.29
//!
//! `$ ./your_bittorrent.sh handshake sample.torrent <peer_ip>:<peer_port>`
//!
//! `Peer ID: 0102030405060708090a0b0c0d0e0f1011121314`
//!
//! Exact value will be different as it is randomly generated.
//!
//! *Note:* To get a peer IP & port to test this locally, run `./your_bittorrent.sh peers sample.torrent`
//! and pick any peer from the list.
//!
//! ## Peer Messages
//!
//! https://www.bittorrent.org/beps/bep_0003.html#peer-messages
//!
//! https://wiki.theory.org/BitTorrentSpecification#Messages
//!
//! `$ ./your_bittorrent.sh download_piece -o /tmp/test-piece sample.torrent <piece_index>`

use std::fs::File;
// use std::fs::OpenOptions;
use std::io::{BufWriter, Read, Write};
use std::net::SocketAddrV4;
use std::path::PathBuf;
// use std::sync::OnceLock;

use anyhow::Result;
use sha1::{Digest, Sha1};

use crate::constants::{BLOCK_SIZE, DEF_MSG_LEN, SHA1_LEN};
use crate::errors::PeerError;
use crate::message::{Message, MessageId, RequestPayload};
use crate::meta_info::Mode;
use crate::peer::Peer;
use crate::tracker::get_peers;

// static INFO_HASH: OnceLock<Result<[u8; SHA1_LEN]>> = OnceLock::new();

/// Sends a handshake to a single peer, and receives a handshake from the peer, in the same format.
///
/// Arguments:
/// - peer: &[`SocketAddrV4`], peer's socket address, <peer_ip>:<peer_port> (example: 127.0.0.1:8080)
/// - info_hash: &[u8; SHA1_LEN], can be obtained and calculated from a torrent file
///
/// Returns [`Peer`] which holds a 20 bytes long SHA1 representation of the peer ID received during the handshake.
///
/// [`Peer`] implements [`Display`] so it can be printed as the 40 characters long hexadecimal
/// representation of the peer ID received during the handshake.
///
/// Works with a single peer whose socket address it takes as an argument.
///
/// The handshake is a required message and must be the first message transmitted by the client.
///
/// `$ ./your_bittorrent.sh handshake sample.torrent <peer_ip>:<peer_port>`
///
/// `Peer ID: 0102030405060708090a0b0c0d0e0f1011121314`
///
/// Exact value will be different as it is randomly generated.
pub fn handshake(peer: &SocketAddrV4, info_hash: &[u8; SHA1_LEN]) -> Result<Peer, PeerError> {
    // let info_hash = INFO_HASH
    //     .get_or_init(|| Ok(meta_info(torrent)?.info.info_hash))
    //     .as_ref()
    //     .expect("info hash should be available at this point");

    let mut peer = Peer::new(peer);
    peer.handshake(info_hash)?;
    eprintln!("hs peer: {peer}"); //todo remove

    Ok(peer)
}

/// Downloads a single piece of a file and stores it.
///
/// Arguments:
/// - output: &[`PathBuf`], path to the output file for storing the downloaded piece
/// - torrent: &[`PathBuf`], path to a torrent file
/// - piece_index: &[`usize`], zero-based piece index
///
/// The last piece can be smaller than other pieces which are of same fixed size that
/// is defined in the torrent file.
///
/// Supports multiple peers. This improves download speeds because it pipelines requests
/// and avoids delays between blocks being sent to us from the peers. Source (PDF):
/// [BitTorrent Economics Paper](http://bittorrent.org/bittorrentecon.pdf)
///
/// `$ ./your_bittorrent.sh download_piece -o /tmp/test-piece sample.torrent <piece_index>`
pub fn download_piece(
    output: &PathBuf,
    torrent: &PathBuf,
    piece_index: usize,
) -> Result<(), PeerError> {
    let output = File::create(output)?;
    // let output = OpenOptions::new().append(true).create(true).open(output)?;
    let mut file_writer = BufWriter::new(output);

    // Perform the tracker GET request to get a list of peers
    let (peers, info) = get_peers(torrent)?;
    let peers = peers.0;

    // TODO: Create multiple peers and work with them at lower level.
    // TODO: Perhaps choose (at most) PIPELINED_REQUESTS peers and connect to all of them.
    let peer = &peers[0];
    // Establish a TCP connection with a peer, and perform a handshake
    let peer = handshake(peer, &info.info_hash)?;

    // Exchange messages with the peer
    let mut stream = peer
        .stream
        .unwrap_or_else(|| panic!("Expected to get a stream from the peer {}", peer.addr));

    // A read buffer, for received messages
    let mut buf = [0u8; DEF_MSG_LEN];

    // Implementation note:
    // We don't use a write buffer for sending messages.
    // We instead create messages through their constructor and convert them into a stream of bytes.
    // We do this to have a cleaner code with greater readability.
    // Perhaps it would have been slightly more performant if we had used a write buffer directly,
    // without performing those function calls and conversions, but we chose a nicer-looking code.
    // An alternative might be to have methods for sending and receiving messages.
    // This note stands as a reminder in case we sometime decide to improve performance.

    // Receive a Bitfield message
    // let mut msg_len = [0u8; 4];
    // stream.read_exact(&mut msg_len)?;
    // let msg_len = u32::from_be_bytes(msg_len) as usize;
    // let mut buf = vec![0u8; msg_len];
    // stream.read_exact(&mut buf)?;
    // eprintln!("{}, {:?}", msg_len, buf); // todo remove

    // Receive a Bitfield message
    // let mut buf = [0u8; DEF_MSG_LEN]; // todo remove
    let read = stream.read(&mut buf)?;
    eprintln!("{}, {:?}", read, buf); // todo remove
    let msg: Message = (&buf[..]).into();
    // let msg: Message = buf[..].to_vec().into(); // todo remove
    eprintln!("{:?} {}", msg, msg.id); //todo remove
    if msg.id != MessageId::Bitfield {
        return Err(PeerError::from((msg.id, MessageId::Bitfield)));
    }

    // Send the Interested message
    let msg = Message::new(MessageId::Interested, None);
    let msg = <Vec<u8>>::from(msg); // Or just: stream.write_all(msg.into())?;
    eprintln!("{:?}", msg); // todo remove
    stream.write_all(&msg)?;

    // Receive an Unchoke message
    // let mut buf = vec![0u8; 5];
    // stream.read_exact(&mut buf[0..])?;
    // eprintln!("{:?}", buf); // todo remove
    let read = stream.read(&mut buf)?;
    eprintln!("{}, {:?}", read, buf); // todo remove
    let msg = Message::from(&buf[..]);
    // let msg = Message::from(buf[..].to_vec()); // todo remove
    eprintln!("{:?}", msg); //todo remove
    if msg.id != MessageId::Unchoke {
        return Err(PeerError::from((msg.id, MessageId::Unchoke)));
    }

    // Calculate where the requested piece begins in the file - not needed in this function
    let _piece_begin = piece_index * info.plen;

    // The file to download is split into pieces of same fixed length,
    // which is defined in torrent file and is a power of two,
    // except potentially for the last piece which can be smaller.
    // File ultimately needs to be assembled from received pieces, but this function is not meant for that.
    // The file size is also provided in the torrent file.
    let file_len = match info.mode {
        Mode::SingleFile { length } => length,
        Mode::MultipleFile { .. } => unimplemented!("Multiple file mode"),
    };
    let piece_len = info.plen;
    let mut last_piece_len = file_len % piece_len;
    let num_pcs = file_len / piece_len + last_piece_len.clamp(0, 1); // not needed in this function
    if last_piece_len == 0 {
        last_piece_len = piece_len;
    }
    let is_last_piece = piece_index == num_pcs - 1;

    eprintln!("piece_index = {}", piece_index);
    eprintln!("file_len = {}", file_len);
    eprintln!("piece_len = {}", piece_len);
    eprintln!("last_piece_len = {}", last_piece_len);
    eprintln!("num_pcs = {}", num_pcs);
    eprintln!("is_last_piece = {}", is_last_piece);

    if piece_index >= num_pcs {
        return Err(PeerError::WrongPieceIndex(piece_index, num_pcs));
    }

    // Pieces are split into blocks and transferred as such.
    // Pieces ultimately need to be assembled from received blocks.
    // Block size is 16 kB (`BLOCK_SIZE`), except potentially for the last block which can be smaller.
    let block_len = BLOCK_SIZE;
    let mut num_blocks_per_piece = piece_len / block_len;
    let mut last_block_len = last_piece_len % block_len;
    let num_blocks_in_last_piece = last_piece_len / block_len + last_block_len.clamp(0, 1);
    if last_block_len == 0 {
        last_block_len = block_len;
    }
    let total_num_blocks = (num_pcs - 1) * num_blocks_per_piece + num_blocks_in_last_piece; // not needed in this function
    if is_last_piece {
        num_blocks_per_piece = num_blocks_in_last_piece;
    }

    eprintln!("block_len = {}", block_len);
    eprintln!("num_blocks_per_piece = {}", num_blocks_per_piece);
    eprintln!("num_blocks_in_last_piece = {}", num_blocks_in_last_piece);
    eprintln!("last_block_len = {}", last_block_len);
    eprintln!("total_num_blocks = {}", total_num_blocks);

    let mut hasher = Sha1::new();

    // Send a Request message for each block
    // Again, we don't request pieces but blocks.
    let index = piece_index as u32;
    let mut length = block_len as u32;
    for i in 0..num_blocks_per_piece {
        let begin = u32::try_from(i * block_len)?;
        if is_last_piece && i == num_blocks_per_piece - 1 {
            length = last_block_len as u32;
        }
        eprintln!(
            "i = {}: index = {}, begin = {}, length = {}",
            i, index, begin, length
        );
        let tmp =
            <RequestPayload as Into<Vec<u8>>>::into(RequestPayload::new(index, begin, length));
        // let tmp: Vec<u8> = RequestPayload::new(index, begin, length).into();
        let msg = Message::new(
            MessageId::Request,
            // Some(RequestPayload::new(index, begin, length).into()),
            Some(&tmp),
        );
        let msg = <Vec<u8>>::from(msg); // Or just: stream.write_all(msg.into())?;
        eprintln!("send: {:?}", msg); // todo remove
        stream.write_all(&msg)?;
        // tmp.clear();

        // Wait for a Piece message for each block we've requested
        // let mut buf = [0u8; 4 + 1 + 8 + BLOCK_SIZE];
        let mut buf = vec![0u8; (4 + 1 + 8 + length) as usize];
        // let read = stream.read(&mut buf)?;
        let read = stream.read_exact(&mut buf)?; // todo: ()
        eprintln!(
            "receive: {:?}, {:?}, payload len = {}",
            read,
            &buf[..13],
            &buf[13..].len()
        ); // todo remove
        let msg: Message = (&buf[..]).into();
        // eprintln!("{:?} {}", msg, msg.id); //todo remove
        if msg.id != MessageId::Piece {
            return Err(PeerError::from((msg.id, MessageId::Piece)));
        }

        let payload = &msg.payload.expect("Expected to have some payload received")[8..];
        hasher.update(payload);
        file_writer.write_all(payload)?;
    }

    // Hash-check the piece
    let piece = hex::encode(info.pieces.0[piece_index]);
    let hash = hex::encode(hasher.finalize());
    eprintln!("{:?} {:?}", piece, hash); //todo remove
    if piece != hash {
        return Err(PeerError::HashMismatch(piece, hash));
    }

    file_writer.flush()?;

    // let peer = &peers[1];
    // let peer = handshake(peer, &info_hash)?;
    // let peer = &peers[2];
    // let peer = handshake(peer, &info_hash)?;

    Ok(())
}
