"""
server.py - Multi-threaded TCP Chat Server

This module implements the server-side component of the chat application.
It handles multiple client connections using threading, routes messages
between clients, and manages the online user list.

Architecture:
- Main thread: Accepts new client connections
- Client threads: One thread per connected client for handling messages
- Uses TCP sockets for reliable, ordered message delivery

Threading Model:
- Each client connection spawns a dedicated handler thread
- Shared data (client list) is protected by locks for thread safety
- Server can handle multiple simultaneous connections (configurable)

Author: Student
Date: January 2026
Course: B205 Computer Networks
Institution: Gisma University of Applied Sciences
"""

import socket
import threading
import json
import sys
import os
from typing import Dict, Optional, Tuple
from datetime import datetime

# Add current directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import project modules
from config import Config
from logger_config import setup_logging, get_server_logger
from protocol import (
    Message, MessageType, encode_message, decode_message,
    decode_length_prefix, LENGTH_PREFIX_SIZE, encode_dict,
    create_join_message, create_leave_message, create_users_message,
    create_error_message
)
from database import DatabaseManager


class ChatServer:
    """
    Multi-threaded TCP chat server for handling multiple client connections.

    This server accepts incoming connections, manages connected clients,
    and routes messages between them. It uses a threading model where
    each client connection is handled by a dedicated thread.

    Attributes:
        host (str): Server hostname/IP address to bind to
        port (int): Server port number
        max_connections (int): Maximum simultaneous connections
        buffer_size (int): Socket receive buffer size
        clients (Dict[str, socket.socket]): Connected clients {username: socket}
        clients_lock (threading.Lock): Lock for thread-safe client list access
        server_socket (socket.socket): Main server socket
        running (bool): Server running state flag
        logger: Logger instance for server events
        db (DatabaseManager): Database manager for message persistence

    Methods:
        start(): Start the server and begin accepting connections
        stop(): Gracefully stop the server
        broadcast(): Send message to all connected clients
        send_to_client(): Send message to specific client
        handle_client(): Handle individual client connection (thread target)

    Example:
        >>> server = ChatServer()
        >>> server.start()  # Blocks until server stops
    """

    def __init__(self, host: str = None, port: int = None):
        """
        Initialize the ChatServer with configuration settings.

        Args:
            host (str, optional): Server host address. Uses config if not specified.
            port (int, optional): Server port number. Uses config if not specified.
        """
        # Load configuration
        self.config = Config()
        server_config = self.config.get_server_config()

        # Set server parameters (use provided values or config defaults)
        self.host = host or server_config['host']
        self.port = port or server_config['port']
        self.max_connections = server_config['max_connections']
        self.buffer_size = server_config['buffer_size']

        # Initialize client tracking
        # Dictionary maps username to their socket connection
        self.clients: Dict[str, socket.socket] = {}

        # Lock for thread-safe access to clients dictionary
        # Required because multiple threads may modify the dict simultaneously
        self.clients_lock = threading.Lock()

        # Server socket (will be created in start())
        self.server_socket: Optional[socket.socket] = None

        # Server state flag
        self.running = False

        # Setup logging
        setup_logging()
        self.logger = get_server_logger()

        # Initialize database for message persistence
        self.db = DatabaseManager()
        self.db.initialize_database()

        self.logger.info(f"ChatServer initialized: {self.host}:{self.port}")

    def start(self) -> None:
        """
        Start the server and begin accepting client connections.

        Creates the server socket, binds to the configured address,
        and enters the main accept loop. Each new client connection
        spawns a handler thread.

        This method blocks until the server is stopped.
        """
        try:
            # Create TCP socket
            # AF_INET: IPv4 addressing
            # SOCK_STREAM: TCP (connection-oriented, reliable)
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            # Allow socket address reuse (prevents "Address already in use" error)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            # Bind socket to address
            self.server_socket.bind((self.host, self.port))

            # Start listening for connections
            # max_connections sets the backlog queue size
            self.server_socket.listen(self.max_connections)

            self.running = True
            self.logger.info(f"Server started on {self.host}:{self.port}")
            print(f"\n[SERVER] Chat server running on {self.host}:{self.port}")
            print("[SERVER] Waiting for connections...\n")

            # Main accept loop
            self._accept_connections()

        except OSError as e:
            self.logger.error(f"Failed to start server: {e}")
            print(f"[ERROR] Failed to start server: {e}")
            raise

        except KeyboardInterrupt:
            self.logger.info("Server stopped by keyboard interrupt")
            print("\n[SERVER] Shutting down...")

        finally:
            self.stop()

    def _accept_connections(self) -> None:
        """
        Accept loop for new client connections.

        Continuously accepts new connections and spawns handler threads.
        Runs until self.running is set to False.
        """
        while self.running:
            try:
                # Accept new connection (blocks until connection received)
                client_socket, address = self.server_socket.accept()

                self.logger.info(f"New connection from {address}")
                print(f"[SERVER] New connection from {address}")

                # Create and start handler thread for this client
                # daemon=True ensures thread dies when main thread exits
                client_thread = threading.Thread(
                    target=self._handle_client,
                    args=(client_socket, address),
                    daemon=True
                )
                client_thread.start()

            except OSError:
                # Socket closed, server stopping
                if self.running:
                    self.logger.warning("Accept error, server may be stopping")
                break

    def _handle_client(self, client_socket: socket.socket, address: Tuple[str, int]) -> None:
        """
        Handle a single client connection.

        This method runs in a separate thread for each connected client.
        It handles the initial username registration, then enters a
        receive loop for messages.

        Args:
            client_socket (socket.socket): Client's socket connection
            address (Tuple[str, int]): Client's address (ip, port)
        """
        username = None

        try:
            # First message from client should be their username
            username = self._receive_username(client_socket)

            if not username:
                client_socket.close()
                return

            # Check if username is already taken
            with self.clients_lock:
                if username in self.clients:
                    # Send error and close connection
                    error_msg = create_error_message("Username already taken")
                    self._send_message(client_socket, error_msg)
                    client_socket.close()
                    self.logger.warning(f"Username '{username}' rejected (already taken)")
                    return

                # Register the client
                self.clients[username] = client_socket

            # Update database
            self.db.save_user(username, is_online=True)

            self.logger.info(f"User '{username}' connected from {address}")
            print(f"[SERVER] User '{username}' connected")

            # Notify all clients about new user
            join_msg = create_join_message(username)
            self._broadcast(join_msg, exclude=username)

            # Send updated user list to all clients
            self._broadcast_user_list()

            # Enter message receive loop
            self._receive_loop(client_socket, username)

        except Exception as e:
            self.logger.error(f"Error handling client {username or address}: {e}")

        finally:
            # Clean up when client disconnects
            self._disconnect_client(username, client_socket)

    def _receive_username(self, client_socket: socket.socket) -> Optional[str]:
        """
        Receive and validate the username from a new client.

        The first message from a connecting client should contain
        their desired username.

        Args:
            client_socket (socket.socket): Client's socket

        Returns:
            str: The validated username, or None if invalid
        """
        try:
            # Receive length prefix
            length_data = self._receive_exactly(client_socket, LENGTH_PREFIX_SIZE)
            if not length_data:
                return None

            # Decode message length
            msg_length = decode_length_prefix(length_data)

            # Receive message data
            msg_data = self._receive_exactly(client_socket, msg_length)
            if not msg_data:
                return None

            # Parse message
            message = decode_message(msg_data)

            # Validate it's a JOIN message with username
            if message.msg_type == MessageType.JOIN and message.sender:
                username = message.sender.strip()
                # Basic validation: non-empty, reasonable length
                if username and 1 <= len(username) <= 20:
                    return username

            return None

        except Exception as e:
            self.logger.error(f"Error receiving username: {e}")
            return None

    def _receive_loop(self, client_socket: socket.socket, username: str) -> None:
        """
        Main receive loop for a connected client.

        Continuously receives and processes messages from the client
        until the connection is closed or an error occurs.

        Args:
            client_socket (socket.socket): Client's socket
            username (str): Client's username
        """
        while self.running:
            try:
                # Receive length prefix (4 bytes)
                length_data = self._receive_exactly(client_socket, LENGTH_PREFIX_SIZE)
                if not length_data:
                    # Connection closed
                    break

                # Decode message length
                msg_length = decode_length_prefix(length_data)

                # Receive the full message
                msg_data = self._receive_exactly(client_socket, msg_length)
                if not msg_data:
                    break

                # Parse and handle the message
                message = decode_message(msg_data)
                self._process_message(message, username)

            except ConnectionResetError:
                self.logger.info(f"Connection reset by {username}")
                break

            except Exception as e:
                self.logger.error(f"Error receiving from {username}: {e}")
                break

    def _receive_exactly(self, sock: socket.socket, num_bytes: int) -> Optional[bytes]:
        """
        Receive exactly the specified number of bytes from a socket.

        TCP may deliver data in chunks, so we need to loop until
        we have received the expected amount.

        Args:
            sock (socket.socket): Socket to receive from
            num_bytes (int): Exact number of bytes to receive

        Returns:
            bytes: Received data, or None if connection closed
        """
        data = b''
        while len(data) < num_bytes:
            try:
                chunk = sock.recv(num_bytes - len(data))
                if not chunk:
                    # Connection closed
                    return None
                data += chunk
            except Exception:
                return None
        return data

    def _process_message(self, message: Message, sender: str) -> None:
        """
        Process a received message and route it appropriately.

        Handles different message types: TEXT messages are broadcast,
        PRIVATE messages are sent to specific recipients, FILE/PHOTO
        messages are handled for transfer.

        Args:
            message (Message): The received message
            sender (str): Username of the sender
        """
        self.logger.debug(f"Processing message from {sender}: {message.msg_type}")

        # Ensure sender field is correct
        message.sender = sender

        # Save message to database (except some types)
        if message.msg_type in [MessageType.TEXT, MessageType.PRIVATE,
                                MessageType.FILE, MessageType.PHOTO]:
            self.db.save_message(
                sender=sender,
                recipient=message.recipient,
                content=message.content[:1000] if message.msg_type == MessageType.TEXT else "[File]",
                message_type=message.msg_type.value,
                filename=message.filename,
                filesize=message.filesize,
                timestamp=message.timestamp
            )
            self.db.increment_message_count(sender)

        # Route message based on type
        if message.msg_type == MessageType.TEXT:
            # Broadcast text message to all users
            self._broadcast(message)
            print(f"[CHAT] {sender}: {message.content}")

        elif message.msg_type == MessageType.PRIVATE:
            # Send to specific recipient
            recipient = message.recipient
            if recipient in self.clients:
                self._send_to_client(recipient, message)
                # Also send back to sender for confirmation
                self._send_to_client(sender, message)
                print(f"[PRIVATE] {sender} -> {recipient}: {message.content}")
            else:
                # Recipient not online
                error = create_error_message(f"User '{recipient}' is not online")
                self._send_to_client(sender, error)

        elif message.msg_type in [MessageType.FILE, MessageType.PHOTO]:
            # Handle file/photo transfer
            print(f"[FILE] {sender} sent {message.filename} ({message.filesize} bytes)")
            if message.recipient == "all":
                self._broadcast(message)
            else:
                self._send_to_client(message.recipient, message)
                self._send_to_client(sender, message)

        elif message.msg_type == MessageType.LEAVE:
            # Client requesting to leave
            pass  # Will be handled by disconnect

    def _broadcast(self, message: Message, exclude: str = None) -> None:
        """
        Broadcast a message to all connected clients.

        Sends the message to every client except optionally excluded ones.
        Uses a copy of the clients dict to avoid issues if clients
        disconnect during broadcast.

        Args:
            message (Message): Message to broadcast
            exclude (str, optional): Username to exclude from broadcast
        """
        # Get a copy of clients to avoid modification during iteration
        with self.clients_lock:
            clients_copy = dict(self.clients)

        for username, client_socket in clients_copy.items():
            if username != exclude:
                self._send_message(client_socket, message)

    def _send_to_client(self, username: str, message: Message) -> bool:
        """
        Send a message to a specific client.

        Args:
            username (str): Target client's username
            message (Message): Message to send

        Returns:
            bool: True if message was sent successfully
        """
        with self.clients_lock:
            if username in self.clients:
                return self._send_message(self.clients[username], message)
        return False

    def _send_message(self, client_socket: socket.socket, message: Message) -> bool:
        """
        Send an encoded message over a socket.

        Args:
            client_socket (socket.socket): Target socket
            message (Message): Message to send

        Returns:
            bool: True if send was successful
        """
        try:
            encoded = encode_message(message)
            client_socket.sendall(encoded)
            return True
        except Exception as e:
            self.logger.error(f"Error sending message: {e}")
            return False

    def _broadcast_user_list(self) -> None:
        """
        Broadcast the current online user list to all clients.

        Called when users join or leave to keep everyone's
        contact list synchronized.
        """
        with self.clients_lock:
            users = list(self.clients.keys())

        users_msg = create_users_message(users)
        self._broadcast(users_msg)

    def _disconnect_client(self, username: str, client_socket: socket.socket) -> None:
        """
        Handle client disconnection cleanup.

        Removes client from tracking, updates database, notifies
        other users, and closes the socket.

        Args:
            username (str): Disconnected client's username
            client_socket (socket.socket): Client's socket
        """
        if username:
            # Remove from clients dict
            with self.clients_lock:
                if username in self.clients:
                    del self.clients[username]

            # Update database
            self.db.set_user_offline(username)

            # Notify other users
            leave_msg = create_leave_message(username)
            self._broadcast(leave_msg)
            self._broadcast_user_list()

            self.logger.info(f"User '{username}' disconnected")
            print(f"[SERVER] User '{username}' disconnected")

        # Close socket
        try:
            client_socket.close()
        except Exception:
            pass

    def stop(self) -> None:
        """
        Stop the server gracefully.

        Closes all client connections and the server socket.
        """
        self.running = False

        # Close all client connections
        with self.clients_lock:
            for username, client_socket in self.clients.items():
                try:
                    client_socket.close()
                except Exception:
                    pass
            self.clients.clear()

        # Close server socket
        if self.server_socket:
            try:
                self.server_socket.close()
            except Exception:
                pass

        self.logger.info("Server stopped")
        print("[SERVER] Server stopped")

    def get_online_users(self) -> list:
        """
        Get list of currently online users.

        Returns:
            list: List of online usernames
        """
        with self.clients_lock:
            return list(self.clients.keys())


def main():
    """
    Main entry point for running the chat server.

    Creates a ChatServer instance and starts it.
    Handles keyboard interrupt for graceful shutdown.
    """
    print("\n" + "=" * 50)
    print("  B205 Computer Networks - Chat Server")
    print("  Gisma University of Applied Sciences")
    print("=" * 50 + "\n")

    try:
        # Create and start server
        server = ChatServer()
        server.start()

    except KeyboardInterrupt:
        print("\n[SERVER] Interrupted by user")

    except Exception as e:
        print(f"\n[ERROR] Server error: {e}")
        raise


# Run server when module is executed directly
if __name__ == '__main__':
    main()
