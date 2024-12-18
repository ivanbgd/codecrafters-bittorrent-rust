//! # A BitTorrent Client
//!
//! ## Usage
//!
//! ```shell
//! - ./your_bittorrent.sh decode <encoded_value>
//! - ./your_bittorrent.sh info <path_to_torrent_file>
//! - ./your_bittorrent.sh peers <path_to_torrent_file>
//! - ./your_bittorrent.sh handshake <path_to_torrent_file> <peer_ip>:<peer_port>
//! - ./your_bittorrent.sh download_piece -o <path_to_output_file> <path_to_torrent_file> <piece_index>
//! - ./your_bittorrent.sh download -o <path_to_output_file> <path_to_torrent_file>
//! - ./your_bittorrent.sh magnet_parse "<magnet-link>"
//! - ./your_bittorrent.sh magnet_handshake "<magnet-link>"
//! - ./your_bittorrent.sh magnet_info "<magnet-link>"
//! - ./your_bittorrent.sh magnet_download_piece -o <path_to_output_file> "<magnet-link>" <piece_index>
//! - ./your_bittorrent.sh magnet_download -o <path_to_output_file> "<magnet-link>"
//! ```

use anyhow::Result;
use clap::Parser;
use log::info;

use bittorrent_starter_rust::bencode::decode_bencoded_value;
use bittorrent_starter_rust::cli::{Args, Commands};
use bittorrent_starter_rust::config::get_config;
use bittorrent_starter_rust::errors::ae2s;
use bittorrent_starter_rust::magnet::{
    magnet_download, magnet_download_piece, magnet_handshake, parse_magnet_link,
    request_magnet_info,
};
use bittorrent_starter_rust::meta_info::read_meta_info;
use bittorrent_starter_rust::peer_comm::{download, download_piece, handshake};
use bittorrent_starter_rust::tracker::get_peers;

#[tokio::main]
async fn main() -> Result<(), String> {
    env_logger::init();
    info!("Starting the app");

    let args = Args::parse();
    let config = get_config();

    match &args.command {
        Commands::Decode { encoded_value } => {
            let decoded_value = decode_bencoded_value(encoded_value.as_bytes()).map_err(ae2s)?;
            println!("{}", decoded_value);
        }
        Commands::Info { torrent } => {
            let meta = read_meta_info(torrent)?;
            println!("{}", meta);
        }
        Commands::Peers { torrent } => {
            let (peers, _) = get_peers(torrent).await?;
            println!("{}", peers);
        }
        Commands::Handshake { torrent, peer } => {
            let peer = handshake(peer, &read_meta_info(torrent)?.info.info_hash).await?;
            println!("Peer ID: {}", peer);
        }
        Commands::DownloadPiece {
            output,
            torrent,
            piece_index,
        } => {
            download_piece(config, output, torrent, *piece_index).await?;
        }
        Commands::Download { output, torrent } => {
            download(config, output, torrent).await?;
        }
        Commands::MagnetParse { magnet_link } => {
            let magnet_link = parse_magnet_link(magnet_link)?.to_string();
            let display: String = magnet_link.split_inclusive('\n').take(2).collect();
            println!("{}", display);
        }
        Commands::MagnetHandshake { magnet_link } => {
            let peer = magnet_handshake(magnet_link).await?;
            println!("Peer ID: {}", peer);
            let ext_id = peer.get_extension_id()?;
            println!("Peer Metadata Extension ID: {ext_id}");
        }
        Commands::MagnetInfo { magnet_link } => {
            let ml = parse_magnet_link(magnet_link)?.to_string();
            let display: String = ml.split_inclusive('\n').take(2).collect();
            println!("{}", display);
            let info = request_magnet_info(magnet_link).await?.0;
            println!("{}", info);
        }
        Commands::MagnetDownloadPiece {
            output,
            magnet_link,
            piece_index,
        } => {
            magnet_download_piece(config, output, magnet_link, *piece_index).await?;
        }
        Commands::MagnetDownload {
            output,
            magnet_link,
        } => {
            magnet_download(config, output, magnet_link).await?;
        }
    }

    Ok(())
}
