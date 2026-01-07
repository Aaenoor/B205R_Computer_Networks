"""
file_handler.py - File Transfer Handler Module

This module handles file and photo transfer operations for the chat application.
It provides functionality for encoding files to base64 for transmission over
the network, decoding received files, and validating file types and sizes.

Base64 encoding is used because:
1. JSON cannot directly contain binary data
2. Base64 converts binary to ASCII-safe text
3. Easy to embed in JSON messages
4. Widely supported and well-understood

Note: Base64 increases data size by approximately 33%, so large files
should be transferred in chunks or using a separate file transfer protocol.

Author: Student
Date: January 2026
Course: B205 Computer Networks
Institution: Gisma University of Applied Sciences
"""

import base64
import os
import mimetypes
from typing import Tuple, Optional, Dict, Any
from datetime import datetime

# Import configuration
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from config import Config
except ImportError:
    Config = None


class FileHandler:
    """
    Handles file encoding, decoding, and validation for network transfer.

    This class provides methods for preparing files for transmission
    over the network and reconstructing them on receipt. It includes
    validation for file size and type restrictions.

    Attributes:
        max_file_size (int): Maximum allowed file size in bytes
        chunk_size (int): Size of chunks for large file handling
        allowed_extensions (list): List of permitted file extensions

    Methods:
        encode_file(): Convert file to base64 string
        decode_file(): Convert base64 string back to file
        validate_file(): Check if file meets requirements
        get_file_info(): Get metadata about a file
        is_image(): Check if file is an image type

    Example:
        >>> handler = FileHandler()
        >>> encoded, info = handler.encode_file('photo.jpg')
        >>> handler.decode_file(encoded, 'received_photo.jpg')
    """

    # Common image extensions for inline display
    IMAGE_EXTENSIONS = {'.png', '.jpg', '.jpeg', '.gif', '.bmp', '.webp'}

    def __init__(self):
        """
        Initialize the FileHandler with configuration settings.

        Loads file transfer settings from the configuration file,
        including maximum file size, chunk size, and allowed extensions.
        """
        # Load configuration
        if Config:
            config = Config()
            file_config = config.get_file_transfer_config()
            self.max_file_size = file_config['max_file_size']
            self.chunk_size = file_config['chunk_size']
            self.allowed_extensions = file_config['allowed_extensions']
        else:
            # Default values if config not available
            self.max_file_size = 10 * 1024 * 1024  # 10MB
            self.chunk_size = 8192  # 8KB
            self.allowed_extensions = [
                '.txt', '.pdf', '.png', '.jpg', '.jpeg',
                '.gif', '.doc', '.docx', '.zip'
            ]

        # Directory for saving received files
        self._downloads_dir = None

    def set_downloads_directory(self, path: str) -> None:
        """
        Set the directory for saving received files.

        Args:
            path (str): Path to downloads directory
        """
        self._downloads_dir = path
        # Create directory if it doesn't exist
        if not os.path.exists(path):
            os.makedirs(path)

    def get_downloads_directory(self) -> str:
        """
        Get the downloads directory path.

        Returns:
            str: Path to downloads directory
        """
        if self._downloads_dir:
            return self._downloads_dir

        # Default to user's home directory Downloads folder
        home = os.path.expanduser('~')
        downloads = os.path.join(home, 'Downloads', 'ChatApp')
        if not os.path.exists(downloads):
            os.makedirs(downloads)
        return downloads

    def validate_file(self, file_path: str) -> Tuple[bool, str]:
        """
        Validate a file for transfer.

        Checks if the file exists, is within size limits, and has
        an allowed extension.

        Args:
            file_path (str): Path to the file to validate

        Returns:
            Tuple[bool, str]: (is_valid, error_message)
                - is_valid: True if file passes all checks
                - error_message: Empty string if valid, error description if not

        Example:
            >>> handler = FileHandler()
            >>> valid, error = handler.validate_file('document.pdf')
            >>> if not valid:
            ...     print(f"Cannot send file: {error}")
        """
        # Check if file exists
        if not os.path.exists(file_path):
            return False, f"File not found: {file_path}"

        # Check if it's a file (not a directory)
        if not os.path.isfile(file_path):
            return False, f"Path is not a file: {file_path}"

        # Check file size
        file_size = os.path.getsize(file_path)
        if file_size > self.max_file_size:
            size_mb = file_size / (1024 * 1024)
            max_mb = self.max_file_size / (1024 * 1024)
            return False, f"File too large: {size_mb:.1f}MB (max: {max_mb:.1f}MB)"

        # Check file extension
        _, ext = os.path.splitext(file_path)
        ext = ext.lower()
        if ext not in self.allowed_extensions:
            return False, f"File type not allowed: {ext}"

        return True, ""

    def get_file_info(self, file_path: str) -> Dict[str, Any]:
        """
        Get metadata about a file.

        Extracts information about a file including name, size,
        extension, and MIME type.

        Args:
            file_path (str): Path to the file

        Returns:
            Dict[str, Any]: Dictionary containing:
                - filename: Base name of the file
                - filepath: Full path to the file
                - extension: File extension (including dot)
                - size: File size in bytes
                - size_formatted: Human-readable size string
                - mime_type: MIME type of the file
                - is_image: Whether the file is an image

        Example:
            >>> info = handler.get_file_info('photo.jpg')
            >>> print(f"File: {info['filename']} ({info['size_formatted']})")
        """
        filename = os.path.basename(file_path)
        _, extension = os.path.splitext(file_path)
        extension = extension.lower()

        # Get file size
        size = os.path.getsize(file_path) if os.path.exists(file_path) else 0

        # Get MIME type
        mime_type, _ = mimetypes.guess_type(file_path)

        return {
            'filename': filename,
            'filepath': file_path,
            'extension': extension,
            'size': size,
            'size_formatted': self._format_size(size),
            'mime_type': mime_type or 'application/octet-stream',
            'is_image': extension in self.IMAGE_EXTENSIONS
        }

    def _format_size(self, size_bytes: int) -> str:
        """
        Format file size in human-readable format.

        Args:
            size_bytes (int): Size in bytes

        Returns:
            str: Formatted size string (e.g., "1.5 MB")
        """
        # Define size units
        units = ['B', 'KB', 'MB', 'GB']
        unit_index = 0
        size = float(size_bytes)

        # Convert to appropriate unit
        while size >= 1024 and unit_index < len(units) - 1:
            size /= 1024
            unit_index += 1

        # Format with appropriate precision
        if unit_index == 0:
            return f"{int(size)} {units[unit_index]}"
        else:
            return f"{size:.1f} {units[unit_index]}"

    def is_image(self, file_path: str) -> bool:
        """
        Check if a file is an image.

        Args:
            file_path (str): Path to the file

        Returns:
            bool: True if file has an image extension
        """
        _, ext = os.path.splitext(file_path)
        return ext.lower() in self.IMAGE_EXTENSIONS

    def encode_file(self, file_path: str) -> Tuple[str, Dict[str, Any]]:
        """
        Encode a file to base64 string for network transmission.

        Reads the file in binary mode and encodes it to base64,
        which can be safely included in JSON messages.

        Args:
            file_path (str): Path to the file to encode

        Returns:
            Tuple[str, Dict[str, Any]]: (base64_data, file_info)
                - base64_data: Base64 encoded file content
                - file_info: Metadata about the file

        Raises:
            FileNotFoundError: If file does not exist
            ValueError: If file fails validation

        Example:
            >>> encoded_data, info = handler.encode_file('photo.jpg')
            >>> # Send encoded_data over network
        """
        # Validate file first
        is_valid, error = self.validate_file(file_path)
        if not is_valid:
            raise ValueError(error)

        # Get file information
        file_info = self.get_file_info(file_path)

        # Read file in binary mode
        with open(file_path, 'rb') as f:
            file_data = f.read()

        # Encode to base64
        # base64.b64encode returns bytes, decode to string for JSON
        base64_data = base64.b64encode(file_data).decode('utf-8')

        return base64_data, file_info

    def decode_file(
        self,
        base64_data: str,
        filename: str,
        save_path: Optional[str] = None
    ) -> str:
        """
        Decode a base64 string and save as file.

        Reconstructs a file from base64 encoded data received
        over the network.

        Args:
            base64_data (str): Base64 encoded file content
            filename (str): Name to save the file as
            save_path (str, optional): Directory to save file in.
                                       Uses downloads directory if not specified.

        Returns:
            str: Full path to the saved file

        Raises:
            ValueError: If base64 decoding fails

        Example:
            >>> saved_path = handler.decode_file(received_data, 'photo.jpg')
            >>> print(f"File saved to: {saved_path}")
        """
        # Determine save location
        if save_path is None:
            save_path = self.get_downloads_directory()

        # Ensure directory exists
        if not os.path.exists(save_path):
            os.makedirs(save_path)

        # Generate unique filename if file already exists
        full_path = os.path.join(save_path, filename)
        full_path = self._get_unique_path(full_path)

        try:
            # Decode base64 to bytes
            file_data = base64.b64decode(base64_data)

            # Write to file
            with open(full_path, 'wb') as f:
                f.write(file_data)

            return full_path

        except Exception as e:
            raise ValueError(f"Failed to decode file: {e}")

    def _get_unique_path(self, file_path: str) -> str:
        """
        Generate a unique file path if file already exists.

        Adds a counter to the filename if a file with the same name
        already exists in the target directory.

        Args:
            file_path (str): Original file path

        Returns:
            str: Unique file path
        """
        if not os.path.exists(file_path):
            return file_path

        # Split path into directory, name, and extension
        directory = os.path.dirname(file_path)
        filename = os.path.basename(file_path)
        name, ext = os.path.splitext(filename)

        # Add counter until we find a unique name
        counter = 1
        while os.path.exists(file_path):
            new_name = f"{name}_{counter}{ext}"
            file_path = os.path.join(directory, new_name)
            counter += 1

        return file_path

    def decode_to_bytes(self, base64_data: str) -> bytes:
        """
        Decode base64 data to bytes without saving to file.

        Useful for displaying images in the GUI without saving
        to disk first.

        Args:
            base64_data (str): Base64 encoded data

        Returns:
            bytes: Decoded binary data

        Example:
            >>> image_bytes = handler.decode_to_bytes(photo_data)
            >>> # Use image_bytes with PIL/Tkinter
        """
        return base64.b64decode(base64_data)

    def encode_bytes(self, data: bytes) -> str:
        """
        Encode bytes to base64 string.

        Args:
            data (bytes): Binary data to encode

        Returns:
            str: Base64 encoded string
        """
        return base64.b64encode(data).decode('utf-8')


# Create global instance for convenience
_file_handler = None


def get_file_handler() -> FileHandler:
    """
    Get the singleton FileHandler instance.

    Returns:
        FileHandler: File handler instance
    """
    global _file_handler
    if _file_handler is None:
        _file_handler = FileHandler()
    return _file_handler


# Convenience functions
def encode_file(file_path: str) -> Tuple[str, Dict[str, Any]]:
    """Encode a file to base64."""
    return get_file_handler().encode_file(file_path)


def decode_file(base64_data: str, filename: str, save_path: str = None) -> str:
    """Decode base64 data and save to file."""
    return get_file_handler().decode_file(base64_data, filename, save_path)


def validate_file(file_path: str) -> Tuple[bool, str]:
    """Validate a file for transfer."""
    return get_file_handler().validate_file(file_path)


def is_image(file_path: str) -> bool:
    """Check if file is an image."""
    return get_file_handler().is_image(file_path)


# Test the module when run directly
if __name__ == '__main__':
    print("\n=== File Handler Module Test ===\n")

    handler = FileHandler()

    # Test file info
    print("1. Testing file info:")
    # Create a test file
    test_file = 'test_file.txt'
    with open(test_file, 'w') as f:
        f.write("This is a test file for the chat application.\n" * 10)

    info = handler.get_file_info(test_file)
    print(f"   Filename: {info['filename']}")
    print(f"   Size: {info['size_formatted']}")
    print(f"   MIME Type: {info['mime_type']}")
    print(f"   Is Image: {info['is_image']}")

    # Test validation
    print("\n2. Testing validation:")
    valid, error = handler.validate_file(test_file)
    print(f"   Valid: {valid}")
    if error:
        print(f"   Error: {error}")

    # Test encoding
    print("\n3. Testing encoding:")
    encoded, file_info = handler.encode_file(test_file)
    print(f"   Original size: {file_info['size']} bytes")
    print(f"   Encoded size: {len(encoded)} characters")
    print(f"   Size increase: {(len(encoded) / file_info['size'] - 1) * 100:.1f}%")

    # Test decoding
    print("\n4. Testing decoding:")
    saved_path = handler.decode_file(encoded, 'decoded_test.txt', '.')
    print(f"   Saved to: {saved_path}")

    # Verify content
    with open(saved_path, 'r') as f:
        decoded_content = f.read()
    with open(test_file, 'r') as f:
        original_content = f.read()
    print(f"   Content matches: {decoded_content == original_content}")

    # Clean up test files
    print("\n5. Cleaning up:")
    os.remove(test_file)
    os.remove(saved_path)
    print("   Test files removed")

    print("\n=== Test Complete ===")
