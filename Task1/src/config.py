"""
config.py - Configuration Management Module

This module handles loading and managing configuration settings for the
chat application from an INI configuration file. It provides a centralized
way to access server, client, database, logging, and file transfer settings.

The configuration is loaded from 'config.ini' in the project root directory.
Default values are provided for all settings to ensure the application can
run even if the config file is missing or incomplete.

Author: Student
Date: January 2026
Course: B205 Computer Networks
Institution: Gisma University of Applied Sciences
"""

import configparser
import os
from typing import Dict, Any, List


class Config:
    """
    Configuration manager class that loads and provides access to application settings.

    This class implements the Singleton pattern to ensure only one configuration
    instance exists throughout the application lifecycle. It reads settings from
    an INI file and provides type-safe access methods for different setting types.

    Attributes:
        _instance (Config): Singleton instance of the Config class
        _config (configparser.ConfigParser): The configuration parser object
        _config_path (str): Path to the configuration file

    Methods:
        get_server_config(): Returns server-related settings
        get_client_config(): Returns client-related settings
        get_database_config(): Returns database-related settings
        get_logging_config(): Returns logging-related settings
        get_file_transfer_config(): Returns file transfer settings

    Example:
        >>> config = Config()
        >>> server_settings = config.get_server_config()
        >>> print(server_settings['host'])
        'localhost'
    """

    # Singleton instance
    _instance = None

    def __new__(cls):
        """
        Implement Singleton pattern to ensure only one Config instance exists.

        This method is called before __init__ and controls instance creation.
        If an instance already exists, it returns that instance instead of
        creating a new one.

        Returns:
            Config: The singleton Config instance
        """
        if cls._instance is None:
            # Create new instance only if one doesn't exist
            cls._instance = super(Config, cls).__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        """
        Initialize the configuration manager.

        Loads configuration from the INI file if this is the first initialization.
        Uses a flag to prevent re-initialization on subsequent calls due to
        the Singleton pattern.
        """
        # Prevent re-initialization (Singleton pattern)
        if self._initialized:
            return

        self._initialized = True
        self._config = configparser.ConfigParser()

        # Determine the path to config.ini
        # Look in parent directory of src/ folder
        current_dir = os.path.dirname(os.path.abspath(__file__))
        self._config_path = os.path.join(os.path.dirname(current_dir), 'config.ini')

        # Load configuration file
        self._load_config()

    def _load_config(self) -> None:
        """
        Load configuration from the INI file.

        Attempts to read the configuration file. If the file doesn't exist
        or is unreadable, default values will be used (handled by getter methods).

        Raises:
            No exceptions raised - uses defaults if file is missing
        """
        if os.path.exists(self._config_path):
            try:
                self._config.read(self._config_path)
                print(f"[CONFIG] Loaded configuration from: {self._config_path}")
            except Exception as e:
                print(f"[CONFIG] Warning: Could not read config file: {e}")
                print("[CONFIG] Using default values")
        else:
            print(f"[CONFIG] Config file not found at: {self._config_path}")
            print("[CONFIG] Using default values")

    def get_server_config(self) -> Dict[str, Any]:
        """
        Get server-related configuration settings.

        Returns a dictionary containing all server settings including
        host address, port number, maximum connections, and buffer size.

        Returns:
            Dict[str, Any]: Dictionary with keys:
                - host (str): Server hostname/IP address
                - port (int): Server port number
                - max_connections (int): Maximum simultaneous connections
                - buffer_size (int): Socket receive buffer size in bytes

        Example:
            >>> config = Config()
            >>> server = config.get_server_config()
            >>> print(f"Server will run on {server['host']}:{server['port']}")
        """
        return {
            'host': self._config.get('SERVER', 'host', fallback='localhost'),
            'port': self._config.getint('SERVER', 'port', fallback=5000),
            'max_connections': self._config.getint('SERVER', 'max_connections', fallback=10),
            'buffer_size': self._config.getint('SERVER', 'buffer_size', fallback=4096)
        }

    def get_client_config(self) -> Dict[str, Any]:
        """
        Get client-related configuration settings.

        Returns a dictionary containing client connection settings including
        default server address, port, and connection timeout.

        Returns:
            Dict[str, Any]: Dictionary with keys:
                - default_server (str): Default server to connect to
                - default_port (int): Default server port
                - connection_timeout (int): Connection timeout in seconds
        """
        return {
            'default_server': self._config.get('CLIENT', 'default_server', fallback='localhost'),
            'default_port': self._config.getint('CLIENT', 'default_port', fallback=5000),
            'connection_timeout': self._config.getint('CLIENT', 'connection_timeout', fallback=10)
        }

    def get_database_config(self) -> Dict[str, str]:
        """
        Get database-related configuration settings.

        Returns the path to the SQLite database file used for storing
        message history and user information.

        Returns:
            Dict[str, str]: Dictionary with keys:
                - db_path (str): Path to SQLite database file
        """
        return {
            'db_path': self._config.get('DATABASE', 'db_path', fallback='chat_history.db')
        }

    def get_logging_config(self) -> Dict[str, str]:
        """
        Get logging-related configuration settings.

        Returns settings for the application logging system including
        log level, file path, and message format.

        Returns:
            Dict[str, str]: Dictionary with keys:
                - level (str): Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
                - log_file (str): Path to log file
                - format (str): Log message format string
        """
        return {
            'level': self._config.get('LOGGING', 'level', fallback='INFO'),
            'log_file': self._config.get('LOGGING', 'log_file', fallback='chat_server.log'),
            'format': self._config.get('LOGGING', 'format',
                                       fallback='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        }

    def get_file_transfer_config(self) -> Dict[str, Any]:
        """
        Get file transfer-related configuration settings.

        Returns settings for file and photo transfer functionality including
        maximum file size, chunk size, and allowed file extensions.

        Returns:
            Dict[str, Any]: Dictionary with keys:
                - max_file_size (int): Maximum file size in bytes
                - chunk_size (int): Chunk size for transfer in bytes
                - allowed_extensions (List[str]): List of allowed file extensions
        """
        # Get allowed extensions as comma-separated string and convert to list
        extensions_str = self._config.get('FILE_TRANSFER', 'allowed_extensions',
                                          fallback='.txt,.pdf,.png,.jpg,.jpeg,.gif,.doc,.docx,.zip')
        # Split by comma and strip whitespace from each extension
        allowed_extensions = [ext.strip() for ext in extensions_str.split(',')]

        return {
            'max_file_size': self._config.getint('FILE_TRANSFER', 'max_file_size',
                                                  fallback=10485760),  # 10MB default
            'chunk_size': self._config.getint('FILE_TRANSFER', 'chunk_size',
                                               fallback=8192),  # 8KB default
            'allowed_extensions': allowed_extensions
        }

    def reload(self) -> None:
        """
        Reload configuration from the INI file.

        Useful for applying configuration changes without restarting
        the application. Re-reads the config file from disk.
        """
        self._load_config()
        print("[CONFIG] Configuration reloaded")


# Create a global config instance for easy access
# This allows importing config directly: from config import config
config = Config()


# Module-level functions for convenience
def get_server_host() -> str:
    """Get the server host address."""
    return config.get_server_config()['host']


def get_server_port() -> int:
    """Get the server port number."""
    return config.get_server_config()['port']


def get_database_path() -> str:
    """Get the database file path."""
    return config.get_database_config()['db_path']


# Test the configuration when run directly
if __name__ == '__main__':
    # Test configuration loading
    print("\n=== Configuration Test ===\n")

    test_config = Config()

    print("Server Configuration:")
    print(f"  {test_config.get_server_config()}")

    print("\nClient Configuration:")
    print(f"  {test_config.get_client_config()}")

    print("\nDatabase Configuration:")
    print(f"  {test_config.get_database_config()}")

    print("\nLogging Configuration:")
    print(f"  {test_config.get_logging_config()}")

    print("\nFile Transfer Configuration:")
    print(f"  {test_config.get_file_transfer_config()}")

    print("\n=== Test Complete ===")
