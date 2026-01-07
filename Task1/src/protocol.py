"""
protocol.py - Message Protocol Definitions Module

This module defines the communication protocol for the chat application.
It specifies message types, formats, and provides functions for encoding
and decoding messages transmitted over the network.

Protocol Design:
- Uses JSON for message serialization (human-readable, easy to debug)
- Messages are prefixed with 4-byte length header for reliable framing
- Supports various message types: TEXT, FILE, PHOTO, JOIN, LEAVE, etc.

Message Format:
{
    "type": "MESSAGE_TYPE",
    "sender": "username",
    "recipient": "all" or "specific_username",
    "content": "message content or base64 encoded data",
    "filename": "optional filename for file transfers",
    "filesize": optional file size in bytes,
    "timestamp": "ISO 8601 timestamp"
}

Author: Student
Date: January 2026
Course: B205 Computer Networks
Institution: Gisma University of Applied Sciences
"""

import json
import struct
from datetime import datetime
from typing import Dict, Any, Optional, Tuple
from enum import Enum


class MessageType(Enum):
    """
    Enumeration of all supported message types in the protocol.

    Each message type represents a different kind of communication
    or event in the chat system. Using an Enum provides type safety
    and prevents typos in message type strings.

    Attributes:
        TEXT: Regular text chat message
        FILE: Generic file transfer
        PHOTO: Image file transfer (displayed inline in client)
        JOIN: User joined the chat notification
        LEAVE: User left the chat notification
        USERS: List of currently online users
        PRIVATE: Private message to specific user
        ERROR: Error notification from server
        PING: Keep-alive ping message
        PONG: Response to ping message
    """
    TEXT = "TEXT"           # Regular text message
    FILE = "FILE"           # File transfer
    PHOTO = "PHOTO"         # Photo/image transfer
    JOIN = "JOIN"           # User joined notification
    LEAVE = "LEAVE"         # User left notification
    USERS = "USERS"         # Online users list update
    PRIVATE = "PRIVATE"     # Private/direct message
    ERROR = "ERROR"         # Error message
    PING = "PING"           # Keep-alive ping
    PONG = "PONG"           # Keep-alive response


class Message:
    """
    Represents a chat message with all its attributes.

    This class encapsulates all information about a message including
    the sender, recipient, content, and metadata. It provides methods
    for serialization to/from JSON format.

    Attributes:
        msg_type (MessageType): Type of the message
        sender (str): Username of the message sender
        recipient (str): Target recipient ('all' for broadcast)
        content (str): Message content or base64 encoded file data
        filename (str): Optional filename for file transfers
        filesize (int): Optional file size in bytes
        timestamp (str): ISO 8601 formatted timestamp

    Methods:
        to_dict(): Convert message to dictionary
        to_json(): Serialize message to JSON string
        from_dict(): Create Message from dictionary (class method)
        from_json(): Create Message from JSON string (class method)

    Example:
        >>> msg = Message(MessageType.TEXT, 'alice', 'all', 'Hello everyone!')
        >>> json_str = msg.to_json()
        >>> received_msg = Message.from_json(json_str)
    """

    def __init__(
        self,
        msg_type: MessageType,
        sender: str,
        recipient: str = "all",
        content: str = "",
        filename: Optional[str] = None,
        filesize: Optional[int] = None,
        timestamp: Optional[str] = None
    ):
        """
        Initialize a new Message instance.

        Args:
            msg_type (MessageType): Type of the message
            sender (str): Username of the sender
            recipient (str): Target recipient, 'all' for broadcast (default: 'all')
            content (str): Message content (default: '')
            filename (str, optional): Filename for file transfers
            filesize (int, optional): File size in bytes
            timestamp (str, optional): ISO timestamp, auto-generated if not provided
        """
        self.msg_type = msg_type
        self.sender = sender
        self.recipient = recipient
        self.content = content
        self.filename = filename
        self.filesize = filesize
        # Generate timestamp if not provided
        self.timestamp = timestamp or datetime.now().isoformat()

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert the message to a dictionary representation.

        Creates a dictionary with all message attributes, suitable for
        JSON serialization. Only includes optional fields if they have values.

        Returns:
            Dict[str, Any]: Dictionary representation of the message
        """
        # Start with required fields
        message_dict = {
            "type": self.msg_type.value,  # Use enum value string
            "sender": self.sender,
            "recipient": self.recipient,
            "content": self.content,
            "timestamp": self.timestamp
        }

        # Add optional fields only if they have values
        if self.filename:
            message_dict["filename"] = self.filename
        if self.filesize is not None:
            message_dict["filesize"] = self.filesize

        return message_dict

    def to_json(self) -> str:
        """
        Serialize the message to a JSON string.

        Returns:
            str: JSON string representation of the message
        """
        return json.dumps(self.to_dict())

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Message':
        """
        Create a Message instance from a dictionary.

        Factory method that constructs a Message object from a dictionary,
        typically received from JSON parsing.

        Args:
            data (Dict[str, Any]): Dictionary containing message data

        Returns:
            Message: New Message instance

        Raises:
            KeyError: If required fields are missing
            ValueError: If message type is invalid
        """
        # Convert type string to MessageType enum
        try:
            msg_type = MessageType(data["type"])
        except ValueError:
            # Handle unknown message types gracefully
            msg_type = MessageType.ERROR

        return cls(
            msg_type=msg_type,
            sender=data.get("sender", "unknown"),
            recipient=data.get("recipient", "all"),
            content=data.get("content", ""),
            filename=data.get("filename"),
            filesize=data.get("filesize"),
            timestamp=data.get("timestamp")
        )

    @classmethod
    def from_json(cls, json_str: str) -> 'Message':
        """
        Create a Message instance from a JSON string.

        Args:
            json_str (str): JSON string to parse

        Returns:
            Message: New Message instance

        Raises:
            json.JSONDecodeError: If JSON parsing fails
        """
        data = json.loads(json_str)
        return cls.from_dict(data)

    def __str__(self) -> str:
        """Return human-readable string representation of the message."""
        return f"Message({self.msg_type.value}, from={self.sender}, to={self.recipient})"


# ============================================================================
# Protocol Encoding/Decoding Functions
# ============================================================================

# Length prefix format: 4-byte unsigned big-endian integer
# This allows message sizes up to 4GB (2^32 - 1 bytes)
LENGTH_PREFIX_FORMAT = '>I'
LENGTH_PREFIX_SIZE = 4


def encode_message(message: Message) -> bytes:
    """
    Encode a message for network transmission.

    Converts a Message object to bytes with a 4-byte length prefix.
    The length prefix ensures reliable message framing over TCP.

    Protocol format:
    [4 bytes: message length][N bytes: JSON message data]

    Args:
        message (Message): The message to encode

    Returns:
        bytes: Encoded message with length prefix

    Example:
        >>> msg = Message(MessageType.TEXT, 'alice', 'all', 'Hello!')
        >>> encoded = encode_message(msg)
        >>> len(encoded) > 4  # Has length prefix + data
        True
    """
    # Convert message to JSON string
    json_str = message.to_json()

    # Encode JSON string to bytes (UTF-8)
    json_bytes = json_str.encode('utf-8')

    # Create 4-byte length prefix (big-endian unsigned int)
    length_prefix = struct.pack(LENGTH_PREFIX_FORMAT, len(json_bytes))

    # Combine length prefix with message data
    return length_prefix + json_bytes


def encode_dict(data: Dict[str, Any]) -> bytes:
    """
    Encode a dictionary directly for network transmission.

    Convenience function when working with raw dictionaries instead
    of Message objects.

    Args:
        data (Dict[str, Any]): Dictionary to encode

    Returns:
        bytes: Encoded data with length prefix
    """
    json_str = json.dumps(data)
    json_bytes = json_str.encode('utf-8')
    length_prefix = struct.pack(LENGTH_PREFIX_FORMAT, len(json_bytes))
    return length_prefix + json_bytes


def decode_length_prefix(data: bytes) -> int:
    """
    Decode the length prefix from received data.

    Extracts the message length from the first 4 bytes of received data.

    Args:
        data (bytes): At least 4 bytes of received data

    Returns:
        int: Length of the following message in bytes

    Raises:
        struct.error: If data is less than 4 bytes
    """
    if len(data) < LENGTH_PREFIX_SIZE:
        raise ValueError(f"Data too short for length prefix: {len(data)} bytes")

    # Unpack returns a tuple, we need the first (only) element
    length = struct.unpack(LENGTH_PREFIX_FORMAT, data[:LENGTH_PREFIX_SIZE])[0]
    return length


def decode_message(data: bytes) -> Message:
    """
    Decode a message from received network data.

    Parses the JSON message data (without length prefix) and creates
    a Message object.

    Args:
        data (bytes): Message data (without length prefix)

    Returns:
        Message: Decoded message object

    Raises:
        json.JSONDecodeError: If JSON parsing fails
    """
    # Decode bytes to string
    json_str = data.decode('utf-8')

    # Parse JSON and create Message
    return Message.from_json(json_str)


def decode_dict(data: bytes) -> Dict[str, Any]:
    """
    Decode data to a dictionary.

    Convenience function when working with raw dictionaries.

    Args:
        data (bytes): JSON data as bytes (without length prefix)

    Returns:
        Dict[str, Any]: Decoded dictionary
    """
    json_str = data.decode('utf-8')
    return json.loads(json_str)


# ============================================================================
# Message Factory Functions
# ============================================================================

def create_text_message(sender: str, content: str, recipient: str = "all") -> Message:
    """
    Create a text chat message.

    Args:
        sender (str): Username of the sender
        content (str): Message text content
        recipient (str): Target recipient (default: 'all' for broadcast)

    Returns:
        Message: Configured text message
    """
    return Message(
        msg_type=MessageType.TEXT,
        sender=sender,
        recipient=recipient,
        content=content
    )


def create_file_message(
    sender: str,
    filename: str,
    file_data: str,
    filesize: int,
    recipient: str = "all"
) -> Message:
    """
    Create a file transfer message.

    Args:
        sender (str): Username of the sender
        filename (str): Name of the file being sent
        file_data (str): Base64 encoded file content
        filesize (int): Original file size in bytes
        recipient (str): Target recipient (default: 'all')

    Returns:
        Message: Configured file transfer message
    """
    return Message(
        msg_type=MessageType.FILE,
        sender=sender,
        recipient=recipient,
        content=file_data,
        filename=filename,
        filesize=filesize
    )


def create_photo_message(
    sender: str,
    filename: str,
    photo_data: str,
    filesize: int,
    recipient: str = "all"
) -> Message:
    """
    Create a photo transfer message.

    Photos are handled separately from files to allow inline display
    in the chat client.

    Args:
        sender (str): Username of the sender
        filename (str): Name of the photo file
        photo_data (str): Base64 encoded photo data
        filesize (int): Original photo size in bytes
        recipient (str): Target recipient (default: 'all')

    Returns:
        Message: Configured photo message
    """
    return Message(
        msg_type=MessageType.PHOTO,
        sender=sender,
        recipient=recipient,
        content=photo_data,
        filename=filename,
        filesize=filesize
    )


def create_join_message(username: str) -> Message:
    """
    Create a user join notification message.

    Args:
        username (str): Username of the user who joined

    Returns:
        Message: Join notification message
    """
    return Message(
        msg_type=MessageType.JOIN,
        sender=username,
        content=f"{username} has joined the chat"
    )


def create_leave_message(username: str) -> Message:
    """
    Create a user leave notification message.

    Args:
        username (str): Username of the user who left

    Returns:
        Message: Leave notification message
    """
    return Message(
        msg_type=MessageType.LEAVE,
        sender=username,
        content=f"{username} has left the chat"
    )


def create_users_message(users: list) -> Message:
    """
    Create an online users list message.

    Args:
        users (list): List of currently online usernames

    Returns:
        Message: Users list message with usernames in content
    """
    return Message(
        msg_type=MessageType.USERS,
        sender="server",
        content=json.dumps(users)  # Encode list as JSON string
    )


def create_error_message(error_text: str) -> Message:
    """
    Create an error notification message.

    Args:
        error_text (str): Description of the error

    Returns:
        Message: Error message
    """
    return Message(
        msg_type=MessageType.ERROR,
        sender="server",
        content=error_text
    )


def create_private_message(sender: str, recipient: str, content: str) -> Message:
    """
    Create a private/direct message.

    Args:
        sender (str): Username of the sender
        recipient (str): Username of the recipient
        content (str): Message content

    Returns:
        Message: Private message
    """
    return Message(
        msg_type=MessageType.PRIVATE,
        sender=sender,
        recipient=recipient,
        content=content
    )


# Test the protocol when run directly
if __name__ == '__main__':
    print("\n=== Protocol Module Test ===\n")

    # Test message creation
    print("1. Testing message creation:")
    text_msg = create_text_message("alice", "Hello everyone!", "all")
    print(f"   Created: {text_msg}")
    print(f"   JSON: {text_msg.to_json()}")

    # Test encoding
    print("\n2. Testing message encoding:")
    encoded = encode_message(text_msg)
    print(f"   Encoded length: {len(encoded)} bytes")
    print(f"   Length prefix: {decode_length_prefix(encoded)} bytes")

    # Test decoding
    print("\n3. Testing message decoding:")
    # Extract message data (skip length prefix)
    msg_data = encoded[LENGTH_PREFIX_SIZE:]
    decoded = decode_message(msg_data)
    print(f"   Decoded: {decoded}")
    print(f"   Content: {decoded.content}")

    # Test all message types
    print("\n4. Testing all message types:")
    join_msg = create_join_message("bob")
    print(f"   JOIN: {join_msg.to_json()}")

    users_msg = create_users_message(["alice", "bob", "charlie"])
    print(f"   USERS: {users_msg.to_json()}")

    error_msg = create_error_message("Username already taken")
    print(f"   ERROR: {error_msg.to_json()}")

    private_msg = create_private_message("alice", "bob", "Secret message!")
    print(f"   PRIVATE: {private_msg.to_json()}")

    print("\n=== Test Complete ===")
