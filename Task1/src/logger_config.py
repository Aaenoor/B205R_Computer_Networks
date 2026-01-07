"""
logger_config.py - Logging Configuration Module

This module sets up the logging infrastructure for the chat application.
It configures both file and console logging handlers with appropriate
formatting and log levels. The logging system is essential for debugging,
monitoring, and auditing the application's behavior.

The module provides:
- Console handler for real-time monitoring
- File handler for persistent log storage
- Configurable log levels and formats
- Separate loggers for different components (server, client, database)

Author: Student
Date: January 2026
Course: B205 Computer Networks
Institution: Gisma University of Applied Sciences
"""

import logging
import os
import sys
from datetime import datetime
from typing import Optional

# Import configuration settings
try:
    from config import Config
except ImportError:
    # Handle case where module is run directly or from different directory
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from config import Config


class LoggerSetup:
    """
    Logging configuration and setup class.

    This class provides methods to create and configure loggers for different
    components of the application. It supports both console and file logging
    with customizable formats and log levels.

    Attributes:
        _config (Config): Configuration instance for logging settings
        _log_dir (str): Directory path for log files
        _initialized (bool): Flag to track if logging is set up

    Methods:
        setup_logging(): Initialize the logging system
        get_logger(): Get a configured logger for a specific component
        set_log_level(): Change the log level dynamically

    Example:
        >>> logger_setup = LoggerSetup()
        >>> logger = logger_setup.get_logger('server')
        >>> logger.info('Server started successfully')
    """

    def __init__(self):
        """
        Initialize the LoggerSetup instance.

        Loads logging configuration and prepares the logging directory.
        Does not set up handlers until setup_logging() is called.
        """
        self._config = Config()
        self._logging_config = self._config.get_logging_config()
        self._initialized = False

        # Determine log directory (same as config.ini location)
        current_dir = os.path.dirname(os.path.abspath(__file__))
        self._log_dir = os.path.dirname(current_dir)

    def setup_logging(self, log_to_console: bool = True, log_to_file: bool = True) -> None:
        """
        Set up the logging system with console and/or file handlers.

        Configures the root logger and creates handlers based on the
        configuration settings. This should be called once at application startup.

        Args:
            log_to_console (bool): Whether to output logs to console (default: True)
            log_to_file (bool): Whether to output logs to file (default: True)

        Note:
            Calling this method multiple times is safe - it will skip
            re-initialization if already set up.
        """
        if self._initialized:
            return

        # Get the root logger
        root_logger = logging.getLogger()

        # Set log level from configuration
        log_level = self._get_log_level(self._logging_config['level'])
        root_logger.setLevel(log_level)

        # Create formatter with configured format
        log_format = self._logging_config['format']
        formatter = logging.Formatter(log_format)

        # Add console handler if requested
        if log_to_console:
            console_handler = self._create_console_handler(formatter)
            root_logger.addHandler(console_handler)

        # Add file handler if requested
        if log_to_file:
            file_handler = self._create_file_handler(formatter)
            if file_handler:
                root_logger.addHandler(file_handler)

        self._initialized = True
        logging.info("Logging system initialized successfully")

    def _get_log_level(self, level_str: str) -> int:
        """
        Convert log level string to logging constant.

        Args:
            level_str (str): Log level name (DEBUG, INFO, WARNING, ERROR, CRITICAL)

        Returns:
            int: Corresponding logging level constant

        Example:
            >>> self._get_log_level('INFO')
            20  # logging.INFO value
        """
        # Map of string names to logging constants
        level_map = {
            'DEBUG': logging.DEBUG,
            'INFO': logging.INFO,
            'WARNING': logging.WARNING,
            'ERROR': logging.ERROR,
            'CRITICAL': logging.CRITICAL
        }

        # Return the mapped level or INFO as default
        return level_map.get(level_str.upper(), logging.INFO)

    def _create_console_handler(self, formatter: logging.Formatter) -> logging.StreamHandler:
        """
        Create and configure a console (stdout) handler.

        The console handler outputs log messages to the terminal in real-time,
        useful for monitoring application behavior during development and debugging.

        Args:
            formatter (logging.Formatter): The formatter to use for log messages

        Returns:
            logging.StreamHandler: Configured console handler
        """
        # Create handler that outputs to stdout
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(formatter)

        # Console can show all levels (controlled by root logger)
        console_handler.setLevel(logging.DEBUG)

        return console_handler

    def _create_file_handler(self, formatter: logging.Formatter) -> Optional[logging.FileHandler]:
        """
        Create and configure a file handler for persistent logging.

        Log files are stored in the project directory with timestamps in the filename
        to allow for log rotation and historical analysis.

        Args:
            formatter (logging.Formatter): The formatter to use for log messages

        Returns:
            logging.FileHandler: Configured file handler, or None if creation fails
        """
        try:
            # Get log file path from configuration
            log_filename = self._logging_config['log_file']
            log_path = os.path.join(self._log_dir, log_filename)

            # Create file handler
            # 'a' mode appends to existing file, preserving history
            file_handler = logging.FileHandler(log_path, mode='a', encoding='utf-8')
            file_handler.setFormatter(formatter)
            file_handler.setLevel(logging.DEBUG)

            return file_handler

        except Exception as e:
            # Log to console if file handler creation fails
            print(f"[WARNING] Could not create log file handler: {e}")
            return None

    def get_logger(self, name: str) -> logging.Logger:
        """
        Get a logger instance for a specific component.

        Creates or retrieves a logger with the given name. Child loggers
        inherit settings from the root logger but can be configured independently.

        Args:
            name (str): Name of the logger/component (e.g., 'server', 'client', 'database')

        Returns:
            logging.Logger: Configured logger instance

        Example:
            >>> server_logger = logger_setup.get_logger('server')
            >>> server_logger.info('Client connected: user123')
        """
        # Ensure logging is set up before returning a logger
        if not self._initialized:
            self.setup_logging()

        return logging.getLogger(name)

    def set_log_level(self, level: str, logger_name: Optional[str] = None) -> None:
        """
        Dynamically change the log level.

        Allows changing the log level at runtime without restarting the application.
        Can change level for a specific logger or the root logger.

        Args:
            level (str): New log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
            logger_name (str, optional): Specific logger name, or None for root logger
        """
        log_level = self._get_log_level(level)

        if logger_name:
            # Set level for specific logger
            logger = logging.getLogger(logger_name)
        else:
            # Set level for root logger
            logger = logging.getLogger()

        logger.setLevel(log_level)
        logging.info(f"Log level changed to {level} for {'root' if not logger_name else logger_name}")


# Create a global logger setup instance
_logger_setup = LoggerSetup()


def setup_logging(log_to_console: bool = True, log_to_file: bool = True) -> None:
    """
    Module-level function to set up logging.

    Convenience function that calls the LoggerSetup.setup_logging() method
    on the global instance.

    Args:
        log_to_console (bool): Whether to output logs to console
        log_to_file (bool): Whether to output logs to file
    """
    _logger_setup.setup_logging(log_to_console, log_to_file)


def get_logger(name: str) -> logging.Logger:
    """
    Module-level function to get a logger.

    Convenience function that calls the LoggerSetup.get_logger() method
    on the global instance.

    Args:
        name (str): Name of the logger/component

    Returns:
        logging.Logger: Configured logger instance
    """
    return _logger_setup.get_logger(name)


# Pre-defined loggers for common components
# These can be imported directly: from logger_config import server_logger
def get_server_logger() -> logging.Logger:
    """Get the server component logger."""
    return get_logger('chat.server')


def get_client_logger() -> logging.Logger:
    """Get the client component logger."""
    return get_logger('chat.client')


def get_database_logger() -> logging.Logger:
    """Get the database component logger."""
    return get_logger('chat.database')


def get_protocol_logger() -> logging.Logger:
    """Get the protocol component logger."""
    return get_logger('chat.protocol')


# Test the logging system when run directly
if __name__ == '__main__':
    print("\n=== Logging System Test ===\n")

    # Set up logging
    setup_logging()

    # Get loggers for different components
    server_log = get_server_logger()
    client_log = get_client_logger()
    db_log = get_database_logger()

    # Test different log levels
    print("Testing log levels:\n")

    server_log.debug("This is a DEBUG message from server")
    server_log.info("This is an INFO message from server")
    server_log.warning("This is a WARNING message from server")
    server_log.error("This is an ERROR message from server")

    client_log.info("Client logger test message")
    db_log.info("Database logger test message")

    print("\n=== Test Complete ===")
    print(f"Check the log file in the project directory for persistent logs")
