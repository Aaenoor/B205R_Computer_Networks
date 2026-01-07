"""
database.py - SQLite Database Handler Module

This module provides database functionality for the chat application using
SQLite. It handles storing and retrieving message history, user information,
and contact lists. SQLite was chosen for its simplicity, as it requires no
separate server and is built into Python's standard library.

Database Schema:
- messages: Stores all chat messages with sender, recipient, content, and timestamp
- users: Tracks user information and last seen timestamps
- contacts: Manages user contact lists

Author: Student
Date: January 2026
Course: B205 Computer Networks
Institution: Gisma University of Applied Sciences
"""

import sqlite3
import os
from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple
from contextlib import contextmanager

# Import configuration and logging
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from config import Config
    from logger_config import get_database_logger
except ImportError:
    # Fallback if imports fail
    Config = None
    get_database_logger = lambda: None


class DatabaseManager:
    """
    SQLite database manager for the chat application.

    This class provides all database operations including creating tables,
    storing messages, retrieving history, and managing user information.
    It uses context managers for safe connection handling and implements
    thread-safe operations where needed.

    Attributes:
        db_path (str): Path to the SQLite database file
        logger: Logger instance for database operations

    Methods:
        initialize_database(): Create tables if they don't exist
        save_message(): Store a message in the database
        get_messages(): Retrieve message history
        save_user(): Store or update user information
        get_online_users(): Get list of online users
        add_contact(): Add a user to contacts
        get_contacts(): Get user's contact list

    Example:
        >>> db = DatabaseManager()
        >>> db.initialize_database()
        >>> db.save_message('alice', 'all', 'Hello!', 'TEXT')
        >>> messages = db.get_messages(limit=10)
    """

    def __init__(self, db_path: Optional[str] = None):
        """
        Initialize the DatabaseManager.

        Args:
            db_path (str, optional): Path to database file. If not provided,
                                     uses path from configuration file.
        """
        # Get database path from config or use provided path
        if db_path:
            self.db_path = db_path
        elif Config:
            config = Config()
            self.db_path = config.get_database_config()['db_path']
        else:
            self.db_path = 'chat_history.db'

        # Make path absolute if relative
        if not os.path.isabs(self.db_path):
            # Store database in the project directory
            current_dir = os.path.dirname(os.path.abspath(__file__))
            project_dir = os.path.dirname(current_dir)
            self.db_path = os.path.join(project_dir, self.db_path)

        # Set up logger
        if get_database_logger:
            self.logger = get_database_logger()
        else:
            self.logger = None

        self._log("DatabaseManager initialized with path: " + self.db_path)

    def _log(self, message: str, level: str = "info") -> None:
        """
        Log a message if logger is available.

        Args:
            message (str): Message to log
            level (str): Log level (debug, info, warning, error)
        """
        if self.logger:
            log_func = getattr(self.logger, level, self.logger.info)
            log_func(message)

    @contextmanager
    def get_connection(self):
        """
        Context manager for database connections.

        Provides safe handling of database connections with automatic
        commit on success and rollback on error. Using a context manager
        ensures connections are properly closed even if exceptions occur.

        Yields:
            sqlite3.Connection: Database connection object

        Example:
            >>> with self.get_connection() as conn:
            ...     cursor = conn.cursor()
            ...     cursor.execute("SELECT * FROM messages")
        """
        conn = None
        try:
            # Connect to database (creates file if doesn't exist)
            conn = sqlite3.connect(self.db_path)

            # Enable foreign keys
            conn.execute("PRAGMA foreign_keys = ON")

            # Return rows as dictionaries for easier access
            conn.row_factory = sqlite3.Row

            yield conn

            # Commit transaction if no exceptions
            conn.commit()

        except sqlite3.Error as e:
            # Rollback on error
            if conn:
                conn.rollback()
            self._log(f"Database error: {e}", "error")
            raise

        finally:
            # Always close connection
            if conn:
                conn.close()

    def initialize_database(self) -> None:
        """
        Create database tables if they don't exist.

        Sets up the database schema with tables for messages, users,
        and contacts. Uses IF NOT EXISTS to prevent errors on subsequent runs.
        """
        self._log("Initializing database tables...")

        with self.get_connection() as conn:
            cursor = conn.cursor()

            # Create messages table
            # Stores all chat messages with metadata
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    sender TEXT NOT NULL,
                    recipient TEXT NOT NULL,
                    content TEXT,
                    message_type TEXT NOT NULL,
                    filename TEXT,
                    filesize INTEGER,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')

            # Create index on timestamp for faster queries
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_messages_timestamp
                ON messages(timestamp DESC)
            ''')

            # Create index on sender for filtering by user
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_messages_sender
                ON messages(sender)
            ''')

            # Create users table
            # Tracks user information and online status
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                    last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                    is_online INTEGER DEFAULT 0,
                    message_count INTEGER DEFAULT 0
                )
            ''')

            # Create contacts table
            # Manages user contact lists (many-to-many relationship)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS contacts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    owner_username TEXT NOT NULL,
                    contact_username TEXT NOT NULL,
                    added_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(owner_username, contact_username)
                )
            ''')

        self._log("Database tables initialized successfully")

    def save_message(
        self,
        sender: str,
        recipient: str,
        content: str,
        message_type: str,
        filename: Optional[str] = None,
        filesize: Optional[int] = None,
        timestamp: Optional[str] = None
    ) -> int:
        """
        Save a message to the database.

        Stores a chat message with all its metadata. Returns the ID of the
        inserted message for reference.

        Args:
            sender (str): Username of the message sender
            recipient (str): Target recipient ('all' for broadcast)
            content (str): Message content or base64 file data
            message_type (str): Type of message (TEXT, FILE, PHOTO, etc.)
            filename (str, optional): Filename for file transfers
            filesize (int, optional): File size in bytes
            timestamp (str, optional): ISO timestamp (auto-generated if not provided)

        Returns:
            int: ID of the inserted message

        Example:
            >>> msg_id = db.save_message('alice', 'all', 'Hello!', 'TEXT')
            >>> print(f"Message saved with ID: {msg_id}")
        """
        # Use current time if timestamp not provided
        if not timestamp:
            timestamp = datetime.now().isoformat()

        with self.get_connection() as conn:
            cursor = conn.cursor()

            cursor.execute('''
                INSERT INTO messages (sender, recipient, content, message_type,
                                     filename, filesize, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (sender, recipient, content, message_type, filename, filesize, timestamp))

            # Get the ID of the inserted row
            message_id = cursor.lastrowid

            self._log(f"Message saved: ID={message_id}, type={message_type}, from={sender}")

            return message_id

    def get_messages(
        self,
        limit: int = 50,
        offset: int = 0,
        sender: Optional[str] = None,
        recipient: Optional[str] = None,
        message_type: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Retrieve messages from the database.

        Fetches message history with optional filtering by sender, recipient,
        or message type. Results are ordered by timestamp (newest first).

        Args:
            limit (int): Maximum number of messages to return (default: 50)
            offset (int): Number of messages to skip (default: 0)
            sender (str, optional): Filter by sender username
            recipient (str, optional): Filter by recipient
            message_type (str, optional): Filter by message type

        Returns:
            List[Dict[str, Any]]: List of message dictionaries

        Example:
            >>> messages = db.get_messages(limit=10, sender='alice')
            >>> for msg in messages:
            ...     print(f"{msg['sender']}: {msg['content']}")
        """
        with self.get_connection() as conn:
            cursor = conn.cursor()

            # Build query with optional filters
            query = "SELECT * FROM messages WHERE 1=1"
            params = []

            if sender:
                query += " AND sender = ?"
                params.append(sender)

            if recipient:
                query += " AND recipient = ?"
                params.append(recipient)

            if message_type:
                query += " AND message_type = ?"
                params.append(message_type)

            # Order by timestamp (newest first) and apply pagination
            query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
            params.extend([limit, offset])

            cursor.execute(query, params)

            # Convert rows to dictionaries
            messages = [dict(row) for row in cursor.fetchall()]

            self._log(f"Retrieved {len(messages)} messages")

            # Reverse to get chronological order (oldest first)
            return list(reversed(messages))

    def get_conversation(
        self,
        user1: str,
        user2: str,
        limit: int = 50
    ) -> List[Dict[str, Any]]:
        """
        Get conversation between two users.

        Retrieves all messages exchanged between two specific users,
        including both directions.

        Args:
            user1 (str): First username
            user2 (str): Second username
            limit (int): Maximum messages to return

        Returns:
            List[Dict[str, Any]]: Conversation messages
        """
        with self.get_connection() as conn:
            cursor = conn.cursor()

            cursor.execute('''
                SELECT * FROM messages
                WHERE (sender = ? AND recipient = ?)
                   OR (sender = ? AND recipient = ?)
                ORDER BY timestamp DESC
                LIMIT ?
            ''', (user1, user2, user2, user1, limit))

            messages = [dict(row) for row in cursor.fetchall()]
            return list(reversed(messages))

    def save_user(self, username: str, is_online: bool = True) -> None:
        """
        Save or update user information.

        Creates a new user record or updates existing user's last seen
        and online status.

        Args:
            username (str): Username to save/update
            is_online (bool): Whether the user is currently online
        """
        with self.get_connection() as conn:
            cursor = conn.cursor()

            # Try to insert new user, update if exists
            cursor.execute('''
                INSERT INTO users (username, is_online, last_seen)
                VALUES (?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(username) DO UPDATE SET
                    is_online = excluded.is_online,
                    last_seen = CURRENT_TIMESTAMP
            ''', (username, 1 if is_online else 0))

            self._log(f"User saved/updated: {username}, online={is_online}")

    def set_user_offline(self, username: str) -> None:
        """
        Mark a user as offline.

        Updates the user's online status and last seen timestamp.

        Args:
            username (str): Username to mark offline
        """
        with self.get_connection() as conn:
            cursor = conn.cursor()

            cursor.execute('''
                UPDATE users
                SET is_online = 0, last_seen = CURRENT_TIMESTAMP
                WHERE username = ?
            ''', (username,))

            self._log(f"User marked offline: {username}")

    def get_online_users(self) -> List[str]:
        """
        Get list of currently online users.

        Returns:
            List[str]: List of online usernames
        """
        with self.get_connection() as conn:
            cursor = conn.cursor()

            cursor.execute('''
                SELECT username FROM users WHERE is_online = 1
            ''')

            return [row['username'] for row in cursor.fetchall()]

    def increment_message_count(self, username: str) -> None:
        """
        Increment message count for a user.

        Tracks total messages sent by each user for statistics.

        Args:
            username (str): Username whose count to increment
        """
        with self.get_connection() as conn:
            cursor = conn.cursor()

            cursor.execute('''
                UPDATE users
                SET message_count = message_count + 1
                WHERE username = ?
            ''', (username,))

    def add_contact(self, owner: str, contact: str) -> bool:
        """
        Add a contact to user's contact list.

        Args:
            owner (str): Username who owns the contact list
            contact (str): Username to add as contact

        Returns:
            bool: True if contact was added, False if already exists
        """
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()

                cursor.execute('''
                    INSERT INTO contacts (owner_username, contact_username)
                    VALUES (?, ?)
                ''', (owner, contact))

                self._log(f"Contact added: {owner} -> {contact}")
                return True

        except sqlite3.IntegrityError:
            # Contact already exists
            return False

    def remove_contact(self, owner: str, contact: str) -> bool:
        """
        Remove a contact from user's contact list.

        Args:
            owner (str): Username who owns the contact list
            contact (str): Username to remove

        Returns:
            bool: True if contact was removed
        """
        with self.get_connection() as conn:
            cursor = conn.cursor()

            cursor.execute('''
                DELETE FROM contacts
                WHERE owner_username = ? AND contact_username = ?
            ''', (owner, contact))

            return cursor.rowcount > 0

    def get_contacts(self, username: str) -> List[str]:
        """
        Get user's contact list.

        Args:
            username (str): Username whose contacts to retrieve

        Returns:
            List[str]: List of contact usernames
        """
        with self.get_connection() as conn:
            cursor = conn.cursor()

            cursor.execute('''
                SELECT contact_username FROM contacts
                WHERE owner_username = ?
                ORDER BY contact_username
            ''', (username,))

            return [row['contact_username'] for row in cursor.fetchall()]

    def get_user_stats(self, username: str) -> Optional[Dict[str, Any]]:
        """
        Get statistics for a user.

        Args:
            username (str): Username to get stats for

        Returns:
            Dict containing user statistics, or None if user not found
        """
        with self.get_connection() as conn:
            cursor = conn.cursor()

            cursor.execute('''
                SELECT * FROM users WHERE username = ?
            ''', (username,))

            row = cursor.fetchone()
            return dict(row) if row else None

    def clear_all_messages(self) -> int:
        """
        Clear all messages from the database.

        WARNING: This permanently deletes all message history.

        Returns:
            int: Number of messages deleted
        """
        with self.get_connection() as conn:
            cursor = conn.cursor()

            cursor.execute('SELECT COUNT(*) FROM messages')
            count = cursor.fetchone()[0]

            cursor.execute('DELETE FROM messages')

            self._log(f"Cleared {count} messages from database", "warning")

            return count


# Module-level convenience functions
_db_instance = None


def get_database() -> DatabaseManager:
    """
    Get the singleton database instance.

    Returns:
        DatabaseManager: Database manager instance
    """
    global _db_instance
    if _db_instance is None:
        _db_instance = DatabaseManager()
        _db_instance.initialize_database()
    return _db_instance


# Test the database when run directly
if __name__ == '__main__':
    print("\n=== Database Module Test ===\n")

    # Create test database
    db = DatabaseManager('test_chat.db')
    db.initialize_database()

    # Test saving messages
    print("1. Testing message saving:")
    msg_id1 = db.save_message('alice', 'all', 'Hello everyone!', 'TEXT')
    msg_id2 = db.save_message('bob', 'all', 'Hi Alice!', 'TEXT')
    msg_id3 = db.save_message('alice', 'bob', 'Private message', 'PRIVATE')
    print(f"   Saved messages with IDs: {msg_id1}, {msg_id2}, {msg_id3}")

    # Test retrieving messages
    print("\n2. Testing message retrieval:")
    messages = db.get_messages(limit=10)
    for msg in messages:
        print(f"   [{msg['message_type']}] {msg['sender']} -> {msg['recipient']}: {msg['content']}")

    # Test user operations
    print("\n3. Testing user operations:")
    db.save_user('alice', is_online=True)
    db.save_user('bob', is_online=True)
    db.save_user('charlie', is_online=False)
    online = db.get_online_users()
    print(f"   Online users: {online}")

    # Test contacts
    print("\n4. Testing contacts:")
    db.add_contact('alice', 'bob')
    db.add_contact('alice', 'charlie')
    contacts = db.get_contacts('alice')
    print(f"   Alice's contacts: {contacts}")

    # Clean up test database
    print("\n5. Cleaning up:")
    os.remove('test_chat.db')
    print("   Test database removed")

    print("\n=== Test Complete ===")
