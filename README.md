[![progress-banner](https://backend.codecrafters.io/progress/bittorrent/ca143921-9bbb-45ad-81e4-25927be2c7a8)](https://app.codecrafters.io/users/ivanbgd?r=2qF)

This is a starting point for Rust solutions to the
["Build Your Own BitTorrent" Challenge](https://app.codecrafters.io/courses/bittorrent/overview).

In this challenge, you’ll build a BitTorrent client that's capable of parsing a
.torrent file and downloading a file from a peer. Along the way, we’ll learn
about how torrent files are structured, HTTP trackers, BitTorrent’s Peer
Protocol, pipelining and more.

**Note**: If you're viewing this repo on GitHub, head over to
[codecrafters.io](https://codecrafters.io) to try the challenge.

# Passing the first stage

The entry point for your BitTorrent implementation is in `src/main.rs`. Study
and uncomment the relevant code, and push your changes to pass the first stage:

```sh
git commit -am "pass 1st stage" # any msg
git push origin master
```

Time to move on to the next stage!

# Stage 2 & beyond

Note: This section is for stages 2 and beyond.

1. Ensure you have `cargo (1.70)` installed locally
2. Run `./your_bittorrent.sh` to run your program, which is implemented in
   `src/main.rs`. This command compiles your Rust project, so it might be slow
   the first time you run it. Subsequent runs will be fast.
3. Commit your changes and run `git push origin master` to submit your solution
   to CodeCrafters. Test output will be streamed to your terminal.

# Running the Program

Torrent files and magnet links are supported for downloading a single file.

- `./your_bittorrent.sh decode <encoded_value>`
- `./your_bittorrent.sh info <path_to_torrent_file>`
- `./your_bittorrent.sh peers <path_to_torrent_file>`
- `./your_bittorrent.sh handshake <path_to_torrent_file> <peer_ip>:<peer_port>`
    - Peer's IP address and port can be obtained by running the `peers` command and picking any peer from the list.
- `./your_bittorrent.sh download_piece -o <path_to_output_file> <path_to_torrent_file> <piece_index>`
- `./your_bittorrent.sh download -o <path_to_output_file> <path_to_torrent_file>`
- `./your_bittorrent.sh magnet_parse "<magnet-link>"`
- `./your_bittorrent.sh magnet_handshake "<magnet-link>"`
- `./your_bittorrent.sh magnet_info "<magnet-link>"`
- `./your_bittorrent.sh magnet_download_piece -o <path_to_output_file> "<magnet-link>" <piece_index>`
- `./your_bittorrent.sh magnet_download -o <path_to_output_file> "<magnet-link>"`

We can alternatively run it by `cargo run --release`, instead of `./your_bittorrent.sh`.

To enable the provided logging facility, first set the logging level by setting the `RUST_LOG` environment variable.  
To set it for the entire terminal session, execute `export RUST_LOG=debug`, for example, first.  
Or, prepend the run command with a desired log level; for example:  
`RUST_LOG=debug ./your_bittorrent.sh download -o <path_to_output_file> <path_to_torrent_file>`  
Choose between:  
`RUST_LOG=[trace | debug | info | warn]`  
*Note*: Logging is fully enabled only for the `download_piece` and `download` commands. Some commands
don't have any log output.

Sample torrent files are provided in the root of the repository,
as well as in the [test_samples](./test_samples) subdirectory.

*Note:* The sample torrent files can be used for testing the code, and in this case they work, but these are **NOT**
real-world torrent files!

# Limitations

This challenge is **NOT** production-ready!

First, it only supports single-file torrents, but even they are not fully, i.e., properly supported,
so even they don't work.

Secondly, multi-file torrents are not supported at all. This solution has placeholders to support the functionality,
but it hasn't been implemented.

We only support compact mode, but that is the recommended mode in practice anyway, so it should be enough.  
https://www.bittorrent.org/beps/bep_0023.html  
The assignment itself only supports the compact mode.

# Improvements Over the Requirements

- Optional application configuration, through the optional [config.json](config.json) file.
- Logging.
- Timing of the whole-file download.
- We check the Bitfield message payload to see whether a peer has the piece that we need.  
  The challenge doesn't require this as all their peers have all the required pieces during testing,
  but in real life this is practically required.
- We pipeline requests to a single peer for increased download speed.  
  This was suggested as optional but is practically required because of the test timeout.  
  This increases the download speed from a single peer significantly.
- We also added working with multiple peers at once, on top of pipelining requests to a single peer.  
  This was also suggested as optional, but not required.  
  Still, this is something that is required in case of real-life torrents.
  Namely, we cannot rely on a single peer having all pieces in real life. In the challenge's test suite, they do.  
  We try to find a peer that has a piece, for every piece.

# Possible Improvements

- Make the application work for real-life single-file torrents.
- Make the application work for real-life multiple-file torrents.
- Send keep-alive messages to connected peers.
- Discover new peers at regular time intervals, but this is not required in the challenge.
- Whenever a piece is successfully downloaded and written to file, store the necessary information (work parameters)
  in a file that can be used to resume download of the file when the application is restarted, if the file hasn't
  been downloaded fully.
- The [BitTorrent Economics Paper](http://bittorrent.org/bittorrentecon.pdf) (PDF) has more ideas,
  but none of them are required in this challenge.
