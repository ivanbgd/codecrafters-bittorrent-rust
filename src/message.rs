//! # Messages
//!
//! https://www.bittorrent.org/beps/bep_0003.html#peer-messages
//!
//! https://wiki.theory.org/BitTorrentSpecification#Messages
//!
//! # Implementation note
//!
//! We are using the [`From`] trait and its associated [`From::from`] function.
//! The function returns raw result of conversion, meaning, it is not wrapped in [`Result`].
//! We cannot change that, because it is not our trait.
//!
//! This further means that we can only panic in case something goes wrong.
//! The rest of our code, i.e., most of it, returns raw results wrapped in [`anyhow::Error`],
//! so this part is not in line with the rest of the library code.
//!
//! This isn't crucial; we are just mentioning it in case we decide to change that in the future.
//! We could write our own functions or methods that perform the conversions and that return
//! results wrapped in [`anyhow::Error`].

use std::collections::HashMap;
use std::fmt::{Display, Formatter};

use crate::bencode::{bencode_value, decode_bencoded_value};
use crate::constants::{HashType, MAX_FRAME_SIZE};
use crate::errors::{
    MagnetError, MessageCodecError, MessageError, MessageIdError, PeerError, PiecePayloadError,
};
use crate::meta_info::Info;
use anyhow::{Context, Result};
use bytes::{Buf, BufMut, BytesMut};
use log::{trace, warn};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use serde_repr::*;
use sha1::{Digest, Sha1};
use tokio_util::codec::{Decoder, Encoder};

/// Message types
///
/// All non-keepalive messages contain a single byte which holds their type.
#[derive(Debug, PartialEq)]
pub enum MessageId {
    /// choke: `<len=0001><id=0>`
    ///
    /// The `choke` message is fixed-length (1 byte) and has no payload.
    Choke = 0,

    /// unchoke: `<len=0001><id=1>`
    ///
    /// The `unchoke` message is fixed-length (1 byte) and has no payload.
    Unchoke = 1,

    /// interested: `<len=0001><id=2>`
    ///
    /// The `interested` message is fixed-length (1 byte) and has no payload.
    Interested = 2,

    /// not interested: `<len=0001><id=3>`
    ///
    /// The `not interested` message is fixed-length (1 byte) and has no payload.
    NotInterested = 3,

    /// have: `<len=0005><id=4><piece index>`
    ///
    /// The `have` message is fixed-length (5 bytes). The payload is the zero-based index of a piece
    /// that has just been successfully downloaded and verified via the hash.
    Have = 4,

    /// bitfield: `<len=0001+X><id=5><bitfield>`
    ///
    /// The `bitfield` message may only be sent immediately after the handshaking sequence is completed,
    /// and before any other messages are sent. It is optional, and need not be sent if a client has no pieces.
    ///
    /// The bitfield message is variable length (1 + X bytes), where X is the length of the bitfield.
    ///
    /// The payload is a bitfield representing the pieces that have been successfully downloaded.
    ///
    /// The high bit in the first byte corresponds to piece index 0. Bits that are cleared indicated a missing piece,
    /// and set bits indicate a valid and available piece. Spare bits at the end are set to zero.
    Bitfield = 5,

    /// request: `<len=0013><id=6><index><begin><length>`
    ///
    /// The `request` message is fixed length (13 bytes), and is used to request a block.
    ///
    /// The payload contains the following information:
    ///   - index: integer specifying the zero-based piece index
    ///   - begin: integer specifying the zero-based byte offset within the piece
    ///   - length: integer specifying the requested length
    Request = 6,

    /// piece: `<len=0009+X><id=7><index><begin><block>`
    ///
    /// The `piece` message is variable length (9 + X bytes), where X is the length of the block.
    ///
    /// The payload contains the following information:
    ///   - index: integer specifying the zero-based piece index
    ///   - begin: integer specifying the zero-based byte offset within the piece
    ///   - block: block of data, which is a subset of the piece specified by index
    ///
    /// Note that the `piece` messages are correlated with `request` messages implicitly.
    /// It's possible for an unexpected `piece` to arrive if `choke` and `unchoke` messages
    /// are sent in quick succession and/or transfer is going very slowly.
    Piece = 7,

    /// cancel: `<len=0013><id=8><index><begin><length>`
    ///
    /// The `cancel` message is fixed length (13 bytes), and is used to cancel block requests.
    ///
    /// The payload is identical to that of the "request" message. It is typically used during "End Game".
    Cancel = 8,

    /// port: `<len=0003><id=9><listen-port>`
    ///
    /// The `port` message is fixed length (3 bytes).
    ///
    /// The port message is sent by newer versions of the Mainline that implements a DHT tracker.
    /// The listen port is the port this peer's DHT node is listening on.
    /// This peer should be inserted in the local routing table (if DHT tracker is supported).
    Port = 9,

    /// Extended messages follow the standard BitTorrent message format:
    /// - message length prefix (4 bytes),
    /// - message id (1 byte) - this will be `20` for all messages implemented by extensions,
    /// - payload (variable size).
    ///
    /// The Extended message payload is structured as follows:
    /// - Extended message id (1 byte):
    ///     - This will be 0 for the extended handshake.
    /// - Bencoded dictionary (variable size):
    ///     - This will contain a key "m" with another dictionary as its value.
    ///     - The inner dictionary maps supported extension names to their corresponding message IDs.
    Extended = 20,

    /// Unsupported message ID
    Unsupported,
}

/// In case we'd like to print [`MessageId`] as raw byte, i.e., as [`u8`].
///
/// Use [`Debug`] for human-readable output, which we derived for this enum.
impl Display for MessageId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self as *const Self as u8)
    }
}

impl From<MessageId> for u8 {
    fn from(value: MessageId) -> u8 {
        value as u8
    }
}

impl TryFrom<u8> for MessageId {
    type Error = MessageIdError;

    fn try_from(value: u8) -> Result<MessageId, MessageIdError> {
        match value {
            0 => Ok(MessageId::Choke),
            1 => Ok(MessageId::Unchoke),
            2 => Ok(MessageId::Interested),
            3 => Ok(MessageId::NotInterested),
            4 => Ok(MessageId::Have),
            5 => Ok(MessageId::Bitfield),
            6 => Ok(MessageId::Request),
            7 => Ok(MessageId::Piece),
            8 => Ok(MessageId::Cancel),
            9 => Ok(MessageId::Port),
            20 => Ok(MessageId::Extended),
            v => Err(MessageIdError::UnsupportedId(v)),
        }
    }
}

/// All messages in the protocol take the form of `<length prefix><message ID><payload>`.
/// - The length prefix is a four byte big-endian value.
///     - It doesn't count toward the total message length.
///     - It represents the length of the rest of the message in bytes.
/// - The message ID is a single decimal byte.
/// - The payload is message-dependent.
///
/// The keep-alive message is a message with zero bytes, specified with the length prefix set to zero.
/// There is no message ID and no payload for it.
#[derive(Debug)]
pub struct Message {
    len: u32,
    pub id: MessageId,
    pub payload: Option<Vec<u8>>,
}

impl Message {
    /// Creates a new message consisting of message length, type (`id`) and payload for sending to a peer.
    ///
    /// The message length is calculated automatically and stored in the message.
    pub fn new(id: MessageId, payload: Option<Vec<u8>>) -> Self {
        let payload_len = payload.as_ref().unwrap_or(&vec![]).len();
        let len = 1 + payload_len as u32;

        Self { len, id, payload }
    }
}

impl Display for Message {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Message {{ len: {}, id: {:?}", self.len, self.id)?;
        if self.id == MessageId::Extended {
            let payload = self
                .payload
                .as_ref()
                .expect("Payload should exist for extended messages.")
                .to_owned();
            let payload: ExtendedMessageHandshakePayload = payload
                .try_into()
                .expect("Failed to convert raw payload, Vec<u8>, to ExtendedMessagePayload.");
            write!(f, ", payload: {} }}", payload)
        } else {
            write!(f, ", payload: {:02X?} }}", &self.payload)
        }
    }
}

/// Converts a [`Message`] into a byte stream.
impl From<Message> for Vec<u8> {
    /// Serializes a [`Message`] for a send transfer over the wire.
    fn from(value: Message) -> Vec<u8> {
        let len = u32::to_be_bytes(value.len);
        let id = value.id.into();
        let payload = value.payload.unwrap_or_default();
        let payload_len = payload.len();

        let mut buf = Vec::with_capacity(4 + 1 + payload_len);

        buf.extend(len);
        buf.push(id);
        buf.extend(payload);

        buf
    }
}

/// Converts a byte stream into a [`Message`].
impl TryFrom<Vec<u8>> for Message {
    type Error = MessageError;

    /// Deserializes a byte stream received from a wire transfer into [`Message`].
    fn try_from(value: Vec<u8>) -> Result<Message, MessageError> {
        let len = u32::from_be_bytes(<[u8; 4]>::try_from(&value[0..4]).with_context(|| {
            format!(
                "Failed to deserialize message length; received: {:?}",
                value
            )
        })?);
        let id = value[4].try_into()?; // Same as: let id = MessageId::try_from(value[4]);
        let payload = if len == 1 {
            None
        } else {
            Some(value[5..4 + len as usize].to_vec())
        };

        Ok(Self { len, id, payload })
    }
}

/// Payload for the [`MessageId::Request`] message
///
/// The payload contains the following information:
///   - index: integer specifying the zero-based piece index
///   - begin: integer specifying the zero-based byte offset within the piece
///   - length: integer specifying the requested length
#[derive(Debug)]
pub struct RequestPayload {
    index: u32,
    begin: u32,
    length: u32,
}

impl RequestPayload {
    /// Creates a new request payload consisting of piece index, byte offset within the piece
    /// and length for sending to a peer.
    pub fn new(index: u32, begin: u32, length: u32) -> Self {
        Self {
            index,
            begin,
            length,
        }
    }
}

/// Unused
impl Display for RequestPayload {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "-> piece_i = {:3}, begin = {:6}, length = {:5}",
            self.index, self.begin, self.length
        )
    }
}

/// Converts a [`RequestPayload`] into a byte stream.
impl From<RequestPayload> for Vec<u8> {
    /// Serializes a [`RequestPayload`] for a send transfer over the wire.
    fn from(value: RequestPayload) -> Vec<u8> {
        let mut buf = Vec::with_capacity(12);
        buf.extend(u32::to_be_bytes(value.index));
        buf.extend(u32::to_be_bytes(value.begin));
        buf.extend(u32::to_be_bytes(value.length));
        buf
    }
}

/// Unused.
///
/// Converts a [`RequestPayload`] into a byte stream.
impl<'a> From<RequestPayload> for &'a [u8] {
    /// Serializes a [`RequestPayload`] for a send transfer over the wire.
    fn from(value: RequestPayload) -> &'a [u8] {
        let mut buf = Vec::with_capacity(12);
        buf.extend(u32::to_be_bytes(value.index));
        buf.extend(u32::to_be_bytes(value.begin));
        buf.extend(u32::to_be_bytes(value.length));
        buf.leak()
    }
}

/// Payload for the [`MessageId::Piece`] message
///
/// The payload contains the following information:
///   - index: integer specifying the zero-based piece index
///   - begin: integer specifying the zero-based byte offset within the piece
///   - block: block of data, which is a subset of the piece specified by index
#[derive(Debug)]
pub struct PiecePayload<'a> {
    pub index: u32,
    pub begin: u32,
    pub block: &'a [u8],
}

/// Converts a reference to a [`MessageId::Piece`] into a [`PiecePayload`].
impl<'a> TryFrom<&'a Message> for PiecePayload<'a> {
    type Error = PiecePayloadError;

    /// Converts a reference to a [`MessageId::Piece`] into a [`PiecePayload`].
    ///
    /// Validates the payload length against the message length.
    ///
    /// Uses `PiecePayload::try_from(value: &'a [u8])`.
    ///
    /// # Errors
    /// If message length is different from payload length increased by one,
    /// returns [`PiecePayloadError::WrongLen`].
    fn try_from(value: &'a Message) -> Result<PiecePayload, PiecePayloadError> {
        let payload: &[u8] = value
            .payload
            .as_ref()
            .context("Expected to have received some payload")?;

        let msg_len = value.len as usize;
        if msg_len != 1 + payload.len() {
            return Err(PiecePayloadError::WrongLen(msg_len, 1 + payload.len()));
        }

        payload.try_into()
    }
}

/// Converts a byte stream into a [`PiecePayload`].
impl<'a> TryFrom<&'a [u8]> for PiecePayload<'a> {
    type Error = PiecePayloadError;

    /// Deserializes a [`PiecePayload`] received from a wire transfer.
    ///
    /// This function is not aware of the requested length of the block of data,
    /// hence it can't check whether it has received the entire requested block.
    fn try_from(value: &'a [u8]) -> Result<PiecePayload, PiecePayloadError> {
        let index = u32::from_be_bytes(value[0..4].try_into().context("failed to convert index")?);
        let begin = u32::from_be_bytes(value[4..8].try_into().context("failed to convert begin")?);
        let block = &value[8..];

        Ok(Self {
            index,
            begin,
            block,
        })
    }
}

//////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////

/*                            Message Codec                                 */

//////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////

#[derive(Debug)]
pub struct MessageCodec;

impl Decoder for MessageCodec {
    type Item = Message;
    type Error = MessageCodecError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if src.len() < 4 {
            // Not enough data to read length prefix.
            return Ok(None);
        }

        // Read length prefix.
        let mut length_bytes = [0u8; 4];
        length_bytes.copy_from_slice(&src[..4]);
        let length = u32::from_be_bytes(length_bytes) as usize;

        // Check for heartbeat messages.
        if length == 0 {
            // Discard it.
            src.advance(4);

            // But also try again in case the src buffer has more messages.
            return self.decode(src);
        }

        if src.len() < 5 {
            // Not enough data to read length prefix and the message id.
            return Ok(None);
        }

        // Check that the length is not too large.
        if length > MAX_FRAME_SIZE - 4 {
            return Err(MessageCodecError::LengthError(length.to_string()));
        }

        if src.len() < 4 + length {
            // The full message has not yet arrived.
            //
            // We reserve more space in the buffer. This is not strictly
            // necessary, but is a good idea performance-wise.
            src.reserve(4 + length - src.len());

            // We inform the Framed that we need more bytes to form the next frame.
            return Ok(None);
        }

        let id = src[4].try_into()?;

        let payload = if length > 1 {
            Some(src[5..4 + length].to_vec())
        } else {
            None
        };

        // Use advance to modify src such that it no longer contains this frame.
        src.advance(4 + length);

        let msg = Message::new(id, payload);

        Ok(Some(msg))
    }
}

impl Encoder<Message> for MessageCodec {
    type Error = MessageCodecError;

    fn encode(&mut self, msg: Message, dst: &mut BytesMut) -> std::result::Result<(), Self::Error> {
        let length = msg.len as usize;

        // Don't send a message if it is longer than the other end will accept.
        if length > MAX_FRAME_SIZE - 4 {
            return Err(MessageCodecError::LengthError(length.to_string()));
        }

        // Convert the length into a byte array.
        // The cast to u32 cannot overflow due to the length check above.
        let len_slice = u32::to_be_bytes(length as u32);

        // Reserve space in the buffer.
        dst.reserve(4 + length);

        dst.extend_from_slice(&len_slice);
        dst.put_u8(msg.id as u8);
        if let Some(payload) = msg.payload {
            dst.extend_from_slice(&payload);
        }

        Ok(())
    }
}

//////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////

/*                     Extended Message Support                             */

//////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////

/// At the start of the payload of the message exists a single byte message identifier.
/// This identifier can refer to different extension messages and only one ID is specified, `0`.
/// If the ID is `0`, the message is a handshake message.
///
/// See: https://www.bittorrent.org/beps/bep_0010.html
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[repr(u8)]
pub enum ExtendedMessageId {
    /// Extension handshake message
    Handshake = 0,

    /// Any other message ID, which can be an arbitrary [`u8`] value different from `0`
    Custom(u8),
}

/// In case we'd like to print [`ExtendedMessageId`] as raw byte, i.e., as [`u8`].
///
/// Use [`Debug`] for human-readable output, which we derived for this enum.
impl Display for ExtendedMessageId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self as *const Self as u8)
    }
}

impl From<ExtendedMessageId> for u8 {
    fn from(value: ExtendedMessageId) -> u8 {
        match value {
            ExtendedMessageId::Handshake => 0u8,
            ExtendedMessageId::Custom(v) => v,
        }
    }
}

impl TryFrom<u8> for ExtendedMessageId {
    type Error = MessageIdError;

    fn try_from(value: u8) -> Result<ExtendedMessageId, MessageIdError> {
        match value {
            0 => Ok(ExtendedMessageId::Handshake),
            v => match v {
                0 => Err(MessageIdError::UnsupportedId(v)),
                v => Ok(ExtendedMessageId::Custom(v)),
            },
        }
    }
}

/// The Extended message payload is structured as follows:
/// - Extended message id (1 byte):
///     - This will be 0 for the extended handshake.
/// - Bencoded dictionary (variable size):
///     - This will contain a key "m" with another dictionary as its value.
///     - The inner dictionary maps supported extension names to their corresponding message IDs.
///
/// See: https://www.bittorrent.org/beps/bep_0010.html
#[derive(Debug, Serialize)]
pub struct ExtendedMessageHandshakePayload {
    pub id: ExtendedMessageId,
    pub dict: Vec<u8>,
}

impl Display for ExtendedMessageHandshakePayload {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{{ id: {:?}, dict: {:?} }}",
            self.id,
            String::from_utf8_lossy(&self.dict)
        )
    }
}

impl ExtendedMessageHandshakePayload {
    /// Serializes `dict` into a bencode byte vector and stores it as such.
    pub(crate) fn new(
        id: ExtendedMessageId,
        dict: ExtendedMessageHandshakeDict,
    ) -> Result<Self, MessageError> {
        let dict = serde_bencode::to_bytes(&dict)?;

        Ok(Self { id, dict })
    }
}

/// Converts a [`ExtendedMessageHandshakePayload`] into a byte stream.
impl From<ExtendedMessageHandshakePayload> for Vec<u8> {
    /// Serializes a [`ExtendedMessageHandshakePayload`] for a send transfer over the wire.
    fn from(value: ExtendedMessageHandshakePayload) -> Self {
        let id = value.id.into();
        let dict = value.dict;

        let mut buf = Vec::with_capacity(1 + dict.len());

        buf.push(id);
        buf.extend(dict);

        buf
    }
}

/// Converts a byte stream into a [`ExtendedMessageHandshakePayload`].
impl TryFrom<Vec<u8>> for ExtendedMessageHandshakePayload {
    type Error = MessageError;

    /// Deserializes a byte stream received from a wire transfer into [`ExtendedMessageHandshakePayload`].
    fn try_from(value: Vec<u8>) -> Result<ExtendedMessageHandshakePayload, MessageError> {
        let id = value[0].try_into()?;
        let dict = value[1..].to_vec();

        Ok(ExtendedMessageHandshakePayload { id, dict })
    }
}

/// The real payload of a handshake message is a bencoded dictionary (which we define here),
/// aside from the message ID (which is 0 for extended handshake).
///
/// All items in the dictionary are optional.
/// Any unknown names should be ignored by the client.
/// All parts of the dictionary are case-sensitive.
///
/// See: https://www.bittorrent.org/beps/bep_0010.html
///
/// For the bencoding part see: https://www.bittorrent.org/beps/bep_0003.html
/// - Keys must be strings and appear in sorted order (sorted as raw strings, not alphanumerics).
#[derive(Clone, Debug, Serialize)]
pub struct ExtendedMessageHandshakeDict {
    /// Dictionary of supported extension messages which maps names of extensions to an extended message ID
    /// for each extension message. The only requirement on these IDs is that no extension message share the same one.
    /// Setting an extension number to zero means that the extension is not supported/disabled.
    /// The client should ignore any extension names it doesn't recognize.
    ///
    /// The extension message IDs are the IDs used to send the extension messages to the peer sending this handshake,
    /// i.e., the IDs are local to this particular peer.
    pub(crate) m: Option<HashMap<String, u8>>,

    /// An integer value of the number of bytes of the metadata.
    pub(crate) metadata_size: Option<usize>,

    /// Local TCP listen port. Allows each side to learn about the TCP port number of the other side.
    /// Note that there is no need for the receiving side of the connection to send this extension message,
    /// since its port number is already known.
    p: Option<u16>,

    /// Client name and version (as an utf-8 string).
    /// This is a much more reliable way of identifying the client than relying on the peer id encoding.
    v: Option<String>,
}

impl Display for ExtendedMessageHandshakeDict {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "ExtendedMessageHandshakeDict {{ m: {:?}, metadata_size: {:?}, p: {:?}, v: {:?} }}",
            self.m, self.metadata_size, self.p, self.v
        )
    }
}

impl ExtendedMessageHandshakeDict {
    /// Takes fields `m`, `metadata_size`, `p` and `v` and stores them in the dictionary.
    ///
    /// See: https://www.bittorrent.org/beps/bep_0010.html
    pub(crate) fn new(
        m: Option<HashMap<String, u8>>,
        metadata_size: Option<usize>,
        p: Option<u16>,
        v: Option<String>,
    ) -> Self {
        Self {
            m,
            metadata_size,
            p,
            v,
        }
    }
}
/// Converts a byte stream into a [`ExtendedMessageHandshakeDict`].
impl TryFrom<Vec<u8>> for ExtendedMessageHandshakeDict {
    type Error = MessageError;

    /// Deserializes a byte stream received from a wire transfer into [`ExtendedMessageHandshakeDict`].
    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        let val = decode_bencoded_value(&value)?;
        trace!("val = {val:?}");

        let m: Option<HashMap<String, u8>> = match val.get("m").map(|m| m.as_object()) {
            Some(map) => {
                if let Some(map) = map {
                    let mut m = HashMap::new();
                    for (k, v) in map {
                        let v = u8::try_from(v.as_u64().unwrap_or_default())?;
                        m.insert(k.to_owned(), v);
                    }
                    Some(m)
                } else {
                    None
                }
            }
            None => None,
        };

        let metadata_size = val
            .get("metadata_size")
            .map(|ms| ms.as_u64().unwrap_or_default() as usize);

        let p = val.get("p").map(|p| p.as_u64().unwrap_or_default() as u16);

        let v = val
            .get("v")
            .map(|v| v.as_str().unwrap_or_default().to_string());

        Ok(Self {
            m,
            metadata_size,
            p,
            v,
        })
    }
}

/// Extension message for metadata
///
/// Used for transferring of the info-dictionary part of the .torrent file, referred to as the metadata.
///
/// See: https://www.bittorrent.org/beps/bep_0009.html#extension-message
#[derive(Debug, Deserialize_repr, PartialEq, Serialize_repr)]
#[repr(u8)]
pub enum ExtensionMessageId {
    /// Requests a piece of metadata from the peer
    Request = 0,

    /// Sends a piece of metadata to the peer
    Data = 1,

    /// Signals that the peer doesn't have the piece of metadata that was requested
    Reject = 2,

    /// Unsupported message ID
    Unsupported,
}

/// In case we'd like to print [`ExtensionMessageId`] as raw byte, i.e., as [`u8`].
///
/// Use [`Debug`] for human-readable output, which we derived for this enum.
impl Display for ExtensionMessageId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self as *const Self as u8)
    }
}

impl From<ExtensionMessageId> for u8 {
    fn from(value: ExtensionMessageId) -> u8 {
        value as u8
    }
}

impl From<ExtensionMessageId> for usize {
    fn from(value: ExtensionMessageId) -> usize {
        value as usize
    }
}

impl TryFrom<u8> for ExtensionMessageId {
    type Error = MessageIdError;

    fn try_from(value: u8) -> Result<ExtensionMessageId, MessageIdError> {
        match value {
            0 => Ok(ExtensionMessageId::Request),
            1 => Ok(ExtensionMessageId::Data),
            2 => Ok(ExtensionMessageId::Reject),
            v => Err(MessageIdError::UnsupportedId(v)),
        }
    }
}

/// Payload for the [`MessageId::Extended`].[`ExtensionMessageId::*`] message types
///
/// It is used in both ways: for requesting and getting metadata from a peer.
///
/// The Extension message payload is structured as follows:
/// - Extended message id (1 byte):
///     - The peer's extension id.
/// - Bencoded dictionary (variable size):
///     - This dictionary will look like this: `{'msg_type': 0, 'piece': 0}` or
///       `{'msg_type': 1, 'piece': 0, 'total_size': 3425}` or `{'msg_type': 2, 'piece': 0}`
///       (encoded as a bencoded dictionary).
///     - `msg_type` is `0` for a request message, `1` for a data message, and `2` for a reject message.
///     - `piece` is the zero-based piece index of the metadata being requested.
///     - `total_size` is the length of the metadata piece (optional; contained only in the data messages).
///  - Metadata piece contents (variable size), in case of a data message only.
///
/// This `struct` works with raw bytes for the payload (the dictionary and optional contents). // TODO: Should it, though? Remove this line.
///
/// See: https://www.bittorrent.org/beps/bep_0009.html#extension-message
#[derive(Debug, Deserialize, Serialize)]
pub struct ExtensionPayload {
    pub id: ExtendedMessageId,
    dict: ExtensionMessage,
    // pub info: Option<Value>,
    //
    // pub payload: Vec<u8>, // todo rem
    pub info: Option<Info>,
    // contents: Option<MetadataContents>, // todo rem
}

impl Display for ExtensionPayload {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let info = if let Some(info) = &self.info {
            info.to_string()
        } else {
            "None".to_string()
        };
        // todo: try both variants
        // let info = self.info.clone().unwrap_or_default();

        write!(
            f,
            "{{ id: {:?}, dict: {}, info: {} }}",
            self.id, self.dict, info
        )

        // write!(f, "{{ id: {:?}, dict: {} }}", self.id, self.dict) // todo rem
    }
}

impl ExtensionPayload {
    // TODO: rem, probably not needed. Or it could be?
    // /// Creates a new extension request payload consisting of the peer's extension `id`,
    // /// message type (request, data or reject), piece index and total size of the piece.
    // ///
    // /// Serializes `dict` into a bencode byte vector and stores it as such.
    // pub fn new(
    //     id: ExtendedMessageId,
    //     msg_type: ExtensionMessageId,
    //     piece_index: u32,
    //     total_size: Option<u32>,
    // ) -> Result<Self, MessageError> {
    //     let dict = ExtensionMessage {
    //         msg_type,
    //         piece: piece_index,
    //         total_size,
    //     };
    //
    //     // let dict = HashMap::from([ // todo rem
    //     //     ("msg_type".to_string(), ExtensionMessageId::Request.into()),
    //     //     ("piece".to_string(), piece_index),
    //     // ]);
    //     // let dict = serde_bencode::to_bytes(&dict)?;
    //
    //     Ok(Self { id, dict })
    // }

    /// Creates a new extension request payload consisting of the peer's extension id and piece index.
    ///
    /// This is meant only for creating requests, because message type is fixed
    /// to [`ExtensionMessageId::Request`] internally.
    ///
    /// Serializes `dict` into a bencode byte vector and stores it as such.
    pub fn new_request(id: ExtendedMessageId, piece_index: u32) -> Result<Self, MessageError> {
        let dict = ExtensionMessage {
            msg_type: ExtensionMessageId::Request, // todo: rem as u8
            piece: piece_index,
            total_size: None,
        };

        // let dict = HashMap::from([
        //     ("msg_type".to_string(), ExtensionMessageId::Request.into()),
        //     ("piece".to_string(), piece_index),
        // ]); // todo rem
        // let dict = serde_bencode::to_bytes(&dict)?;

        Ok(Self {
            id,
            dict,
            info: None,
        })
    }
}

/// Converts an [`ExtensionPayload`] into a byte stream.
impl TryFrom<ExtensionPayload> for Vec<u8> {
    type Error = MessageError;

    /// Serializes an [`ExtensionPayload`] for a send transfer over the wire.
    fn try_from(value: ExtensionPayload) -> Result<Vec<u8>, MessageError> {
        let id = value.id.into();
        let dict = serde_bencode::to_bytes(&value.dict)?;
        let contents = value.info.unwrap_or_default(); // todo: see if default makes sense - perhaps it doesn't, and in that case remove Default from everywhere you put it
                                                       // let contents: Vec<u8> = if let Some(contents) = value.info {
                                                       //     // bincode::serialize(&contents)? // TODO: remove!
                                                       //     serde_json::from_value(contents)?
                                                       // } else {
                                                       //     vec![]
                                                       // };

        eprintln!("-> contents = {contents:?}"); // todo rem

        let mut buf: Vec<u8> = Vec::with_capacity(1 + dict.len()); // + contents.len());

        buf.push(id);
        buf.extend(dict);
        // buf.extend(contents); // todo rem

        Ok(buf)
    }
}

/// Converts a byte stream into [`ExtensionPayload`].
impl TryFrom<Vec<u8>> for ExtensionPayload {
    type Error = MessageError;

    /// Deserializes a byte stream received from a wire transfer into [`ExtensionPayload`].
    fn try_from(value: Vec<u8>) -> Result<ExtensionPayload, MessageError> {
        // todo!()
        let id = value[0].try_into()?;
        let payload = &value[1..];

        let payload_len = payload.len();
        let info_len = 0usize;

        // TODO: This acrobatic logic is NOT correct!!!
        // It is correct for the first piece only, but not for other pieces!!!
        // I'll have to do this outside of this function... :/ Good thing is I have metadata_size there, which is total_size.

        eprintln!(
            "<= value 1 = {:?}",
            String::from_utf8_lossy(&payload[..payload_len - info_len])
        ); // todo rem
           // todo: this is failing!
           // let dict: ExtensionMessage = serde_bencode::from_bytes(&payload[1..1 + 133 - 91])?; // todo: 91
           // let aux = b"d3:foo3:bar5:helloi52ee";
           // let dict = decode_bencoded_value(&payload[1..1 + 133 - 91])?; // todo: 91
           // let dict = b"d8:msg_typei1e5:piecei0e10:total_sizei91ee";
           // eprintln!("dict = {:?}", String::from_utf8_lossy(dict)); //todo rem
           // let dict = decode_bencoded_value(dict)?; // todo rem
           // let dict = serde_bencode::from_bytes(aux.as_bytes())?; // todo: rem
           // eprintln!("<= dict = {:?}", dict.as_object().unwrap()); // todo rem

        let dict = &payload[..payload_len - 91];
        eprintln!("<= dict 1 = {}", String::from_utf8_lossy(dict)); // todo rem
        let dict = decode_bencoded_value(dict)?;
        eprintln!("<= dict 2 = {dict:?}"); // todo rem
        let dict: ExtensionMessage = serde_json::from_value(dict)?;
        // let dict = ExtensionMessage {
        //     msg_type: 0,
        //     piece: 0,
        //     total_size: Some(0),
        // }; //todo rem
        eprintln!("<= dict 3 = {dict:?}"); // todo rem
        eprintln!("<= dict.msg_type = {:?}", dict.msg_type); // todo rem

        if dict.msg_type == ExtensionMessageId::Reject {
            let err = MessageError::Reject;
            warn!("{err:#}");
            return Err(err);
        }

        eprintln!(
            "<= value 2 = {:?}",
            String::from_utf8_lossy(&payload[payload_len - 91..])
        ); // todo rem
           // let info: Option<Info> = Some(bincode::deserialize(serde_bencode::from_bytes(
           //     &value[1 + 133 - 91..],
           // )?)?); // todo: 91
           // let info = b"d6:lengthi79752e4:name11:magnet2.gif12:piece lengthi262144e6:pieces20:ZZZZZZZZZZZZZZZZZZ12e";
        let info = &payload[payload_len - 91..];
        eprintln!("<= info 1 = {}", String::from_utf8_lossy(info)); // todo rem
        let pieces = &info[info.len() - 1 * 20 - 1..info.len() - 1]; // todo rem
        eprintln!("<= pieces 1 = {:?}", String::from_utf8_lossy(pieces)); // todo rem
                                                                          // let pieces = hex::decode(pieces).unwrap();
                                                                          // eprintln!("<= pieces 2 = {:?}", pieces); // todo rem

        let info_hash: HashType = *Sha1::digest(info).as_ref();
        let info_hash_hex = hex::encode(info_hash);

        let mut info: Info = serde_bencode::from_bytes(info)?;
        eprintln!("<= info 2 = {}", info); // todo rem
                                           // let info: Info = serde_json::from_value(info)?;
                                           // eprintln!("<= info 3 = {}", info); // todo rem
                                           // let info: Option<Info> = Some(bincode::deserialize(info)?); // todo: rem
                                           // eprintln!("<= info 4 = {:?}", info); // todo rem

        info.info_hash = info_hash;
        info.info_hash_hex = info_hash_hex;
        eprintln!("<= info 3 = {}", info); // todo rem
        let info = Some(info);

        Ok(ExtensionPayload { id, dict, info })
    }
}

/// Extension message - part of [`ExtensionPayload`]
///
/// It is used in both ways: for requesting and getting metadata from a peer.
///
/// The Extension message is structured as follows:
/// - `{'msg_type': 0, 'piece': 0}` or `{'msg_type': 1, 'piece': 0, 'total_size': 3425}`
///    or `{'msg_type': 2, 'piece': 0}` (encoded as a bencoded dictionary).
/// - `msg_type` is `0` for a request message, `1` for a data message, and `2` for a reject message.
/// - `piece` is the zero-based piece index of the metadata being requested.
/// - `total_size` is the length of the metadata piece (optional; contained only in the data messages).
///
/// It is meant to be bencoded for a wire transfer.
///
/// See: https://www.bittorrent.org/beps/bep_0009.html#extension-message
#[derive(Debug, Deserialize, Serialize)]
struct ExtensionMessage {
    msg_type: ExtensionMessageId, // todo: revert to ExtensionMessageId
    piece: u32,
    total_size: Option<u32>,
}

impl Display for ExtensionMessage {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{{ msg_type: {:?}, piece: {}, total_size: {:?} }}",
            self.msg_type, self.piece, self.total_size
        )
    }
}

// TODO: Maybe implement From and to ExtensionPayload. But this probably isn't possible, as ExtensionMessage is only a subset of ExtensionPayload.

// TODO: needed?
// impl ExtensionMessage {
//     /// Creates a new extension message.
//     ///
//     /// This is meant only for creating requests,
//     /// because message type is internally fixed to [`ExtensionMessageId::Request`].
//     ///
//     /// Serializes `dict` into a bencode byte vector and stores it as such.
//     pub fn new(id: ExtensionMessageId, piece_index: usize) -> Result<Self, MessageError> {
//         let dict = HashMap::from([
//             ("msg_type".to_string(), ExtensionMessageId::Request.into()),
//             ("piece".to_string(), piece_index),
//         ]);
//         let dict = serde_bencode::to_bytes(&dict)?;
//
//         Ok(Self { id, dict })
//     }
// }

// TODO: needed? Is it correct at all?!
// /// Converts an [`ExtensionMessage`] into a byte stream (bencoded).
// impl From<ExtensionMessage> for Vec<u8> {
//     /// Serializes an [`ExtensionMessage`] for a send transfer over the wire (bencoded).
//     fn from(value: ExtensionMessage) -> Vec<u8> {
//         let msg_type = value.msg_type.into();
//         let piece = u32::to_be_bytes(value.piece);
//         let total_size = u32::to_be_bytes(value.total_size.unwrap_or_default());
//         eprintln!("-> total_size = {total_size:?}, len = {}", total_size.len()); // todo rem
//
//         let mut buf: Vec<u8> = Vec::with_capacity(1 + 4 + total_size.len());
//
//         buf.push(msg_type);
//         buf.extend(piece);
//         buf.extend(total_size);
//
//         let buf = serde_bencode::to_bytes(&buf).unwrap(); // todo: unwrap -> ?
//         eprintln!("-> buf = {buf:?}, len = {}", buf.len()); // todo rem
//
//         buf
//     }
// }

// TODO: needed?
// /// Converts a bencoded byte stream into a [`ExtensionMessage`].
// impl TryFrom<Vec<u8>> for ExtensionMessage {
//     type Error = MessageError;
//
//     /// Deserializes a bencoded byte stream received from a wire transfer into [`ExtensionMessage`].
//     fn try_from(value: Vec<u8>) -> Result<ExtensionMessage, MessageError> {
//         eprintln!("<= value = {value:?}, len = {}", value.len()); // todo rem
//
//         let val: ExtensionMessage = serde_bencode::from_bytes(&value)?;
//         eprintln!("<= val = {val:?}"); // todo rem
//
//         Ok(val)
//
//         // let msg_type = value[0].try_into()?;
//         // let piece = u32::from_be_bytes(value[1..5].try_into().context("failed to convert piece")?);
//         // let total_size = None;
//         // eprintln!("<= total_size = {total_size:?}"); // todo rem
//         //
//         // Ok(ExtensionMessage {
//         //     msg_type,
//         //     piece,
//         //     total_size,
//         // })
//     }
// }

// todo: remove?
// #[derive(Clone, Debug, Default, Deserialize, Serialize)]
// struct MetadataContents {
//     info: Info,
//
//     #[serde(with = "serde_bytes")]
//     binary_data: Vec<u8>,
// }
//
// impl Display for MetadataContents {
//     fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
//         // todo: do we really want to see binary data?!
//         write!(
//             f,
//             "info: {:?}, binary data: {:?}",
//             self.info, self.binary_data
//         )
//     }
// }

// impl From<MetadataContents> for Vec<u8> {
//     fn from(value: MetadataContents) -> Self {
//         todo!()
//     }
// }

// TODO: Impl From <-> Vec<u8>, in one or both ways?
