"""
client.py - Tkinter GUI Chat Client

This module implements the client-side component of the chat application.
It provides a graphical user interface using Tkinter for sending and
receiving messages, transferring files, and viewing online users.

GUI Components:
- Chat display area: Shows all messages with timestamps
- Message input: Text entry for composing messages
- Online users panel: Sidebar showing connected users
- File/Photo buttons: For sending files and images
- Status bar: Shows connection status

Threading Model:
- Main thread: Handles GUI events and updates
- Receiver thread: Continuously receives messages from server
- Uses queue for thread-safe GUI updates

Author: Student
Date: January 2026
Course: B205 Computer Networks
Institution: Gisma University of Applied Sciences
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox, simpledialog
import socket
import threading
import queue
import json
import sys
import os
from datetime import datetime
from typing import Optional, Callable
import io

# Add current directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import project modules
from config import Config
from logger_config import setup_logging, get_client_logger
from protocol import (
    Message, MessageType, encode_message, decode_message,
    decode_length_prefix, LENGTH_PREFIX_SIZE,
    create_text_message, create_join_message, create_leave_message,
    create_file_message, create_photo_message, create_private_message
)
from file_handler import FileHandler

# Try to import PIL for image display
try:
    from PIL import Image, ImageTk
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False
    print("[WARNING] PIL not installed. Image display will be limited.")


class ChatClient:
    """
    Tkinter-based GUI chat client.

    This class provides the graphical interface for the chat application,
    handling user input, displaying messages, and managing the connection
    to the chat server.

    Attributes:
        host (str): Server hostname to connect to
        port (int): Server port number
        username (str): Current user's username
        socket (socket.socket): Connection to server
        connected (bool): Connection state flag
        running (bool): Application running state
        message_queue (queue.Queue): Queue for thread-safe message passing
        root (tk.Tk): Main Tkinter window
        logger: Logger instance

    Methods:
        connect(): Establish connection to server
        disconnect(): Close connection gracefully
        send_message(): Send a text message
        send_file(): Send a file to the chat
        send_photo(): Send a photo to the chat

    Example:
        >>> client = ChatClient()
        >>> client.run()  # Start the GUI application
    """

    def __init__(self):
        """
        Initialize the ChatClient with configuration and GUI setup.

        Sets up logging, loads configuration, and prepares the GUI
        but does not start it yet.
        """
        # Setup logging
        setup_logging()
        self.logger = get_client_logger()

        # Load configuration
        self.config = Config()
        client_config = self.config.get_client_config()
        self.host = client_config['default_server']
        self.port = client_config['default_port']
        self.timeout = client_config['connection_timeout']

        # Connection state
        self.socket: Optional[socket.socket] = None
        self.connected = False
        self.running = True
        self.username = ""

        # Thread-safe queue for GUI updates
        self.message_queue = queue.Queue()

        # File handler for transfers
        self.file_handler = FileHandler()

        # Online users list
        self.online_users = []

        # Store PhotoImage references to prevent garbage collection
        self._image_refs = []

        # GUI will be created in setup_gui()
        self.root = None

        self.logger.info("ChatClient initialized")

    def run(self):
        """
        Start the chat client application.

        Creates the GUI, prompts for connection details, and starts
        the main event loop.
        """
        # Create main window
        self.root = tk.Tk()
        self.root.title("Chat Application - B205 Computer Networks")
        self.root.geometry("900x600")
        self.root.minsize(700, 500)

        # Setup GUI components
        self._setup_gui()

        # Prompt for username and connect
        self._prompt_connection()

        # Start message queue processor
        self._process_queue()

        # Handle window close
        self.root.protocol("WM_DELETE_WINDOW", self._on_closing)

        # Start main loop
        self.root.mainloop()

    def _setup_gui(self):
        """
        Create and arrange all GUI components.

        Sets up the main layout with chat area, input field,
        online users panel, and control buttons.
        """
        # Configure grid weights for resizing
        self.root.grid_columnconfigure(0, weight=1)
        self.root.grid_rowconfigure(0, weight=1)

        # Main frame
        main_frame = ttk.Frame(self.root, padding="5")
        main_frame.grid(row=0, column=0, sticky="nsew")
        main_frame.grid_columnconfigure(0, weight=1)
        main_frame.grid_rowconfigure(0, weight=1)

        # Create paned window for resizable panels
        paned = ttk.PanedWindow(main_frame, orient=tk.HORIZONTAL)
        paned.grid(row=0, column=0, sticky="nsew")

        # Left panel: Chat area
        left_frame = ttk.Frame(paned)
        left_frame.grid_columnconfigure(0, weight=1)
        left_frame.grid_rowconfigure(0, weight=1)

        # Chat display area (scrolled text widget)
        self.chat_display = scrolledtext.ScrolledText(
            left_frame,
            wrap=tk.WORD,
            state=tk.DISABLED,
            font=("Consolas", 10),
            bg="#f5f5f5"
        )
        self.chat_display.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)

        # Configure text tags for different message types
        self.chat_display.tag_configure("system", foreground="#666666", font=("Consolas", 10, "italic"))
        self.chat_display.tag_configure("username", foreground="#0066cc", font=("Consolas", 10, "bold"))
        self.chat_display.tag_configure("my_message", foreground="#006600")
        self.chat_display.tag_configure("private", foreground="#990099")
        self.chat_display.tag_configure("error", foreground="#cc0000")
        self.chat_display.tag_configure("timestamp", foreground="#999999", font=("Consolas", 8))

        # Input frame
        input_frame = ttk.Frame(left_frame)
        input_frame.grid(row=1, column=0, sticky="ew", padx=5, pady=5)
        input_frame.grid_columnconfigure(0, weight=1)

        # Message input field
        self.message_input = ttk.Entry(input_frame, font=("Arial", 11))
        self.message_input.grid(row=0, column=0, sticky="ew", padx=(0, 5))
        self.message_input.bind("<Return>", lambda e: self._send_message())

        # Send button
        self.send_button = ttk.Button(input_frame, text="Send", command=self._send_message)
        self.send_button.grid(row=0, column=1)

        # File buttons frame
        button_frame = ttk.Frame(left_frame)
        button_frame.grid(row=2, column=0, sticky="ew", padx=5, pady=5)

        # Send file button
        self.file_button = ttk.Button(button_frame, text="Send File", command=self._send_file)
        self.file_button.pack(side=tk.LEFT, padx=2)

        # Send photo button
        self.photo_button = ttk.Button(button_frame, text="Send Photo", command=self._send_photo)
        self.photo_button.pack(side=tk.LEFT, padx=2)

        paned.add(left_frame, weight=3)

        # Right panel: Online users
        right_frame = ttk.LabelFrame(paned, text="Online Users", padding="5")

        # Users listbox
        self.users_listbox = tk.Listbox(right_frame, font=("Arial", 10))
        self.users_listbox.pack(fill=tk.BOTH, expand=True)
        self.users_listbox.bind("<Double-1>", self._on_user_double_click)

        paned.add(right_frame, weight=1)

        # Status bar at bottom
        self.status_var = tk.StringVar(value="Not connected")
        status_bar = ttk.Label(
            main_frame,
            textvariable=self.status_var,
            relief=tk.SUNKEN,
            anchor=tk.W
        )
        status_bar.grid(row=1, column=0, sticky="ew", pady=(5, 0))

    def _prompt_connection(self):
        """
        Prompt user for username and server details.

        Shows a dialog to get the username before connecting.
        """
        # Create connection dialog
        dialog = tk.Toplevel(self.root)
        dialog.title("Connect to Server")
        dialog.geometry("300x180")
        dialog.transient(self.root)
        dialog.grab_set()

        # Center dialog
        dialog.geometry("+%d+%d" % (
            self.root.winfo_rootx() + 300,
            self.root.winfo_rooty() + 200
        ))

        # Username field
        ttk.Label(dialog, text="Username:").pack(pady=(20, 5))
        username_entry = ttk.Entry(dialog, width=30)
        username_entry.pack(pady=5)
        username_entry.focus()

        # Server field
        ttk.Label(dialog, text="Server:").pack(pady=5)
        server_frame = ttk.Frame(dialog)
        server_frame.pack(pady=5)

        server_entry = ttk.Entry(server_frame, width=20)
        server_entry.insert(0, self.host)
        server_entry.pack(side=tk.LEFT)

        ttk.Label(server_frame, text=":").pack(side=tk.LEFT)

        port_entry = ttk.Entry(server_frame, width=6)
        port_entry.insert(0, str(self.port))
        port_entry.pack(side=tk.LEFT)

        def on_connect():
            """Handle connect button click."""
            username = username_entry.get().strip()
            server = server_entry.get().strip()
            port = port_entry.get().strip()

            if not username:
                messagebox.showerror("Error", "Please enter a username")
                return

            if not 1 <= len(username) <= 20:
                messagebox.showerror("Error", "Username must be 1-20 characters")
                return

            self.username = username
            self.host = server
            self.port = int(port)

            dialog.destroy()
            self._connect()

        # Connect button
        ttk.Button(dialog, text="Connect", command=on_connect).pack(pady=15)

        # Handle Enter key
        username_entry.bind("<Return>", lambda e: on_connect())

        # Wait for dialog
        self.root.wait_window(dialog)

    def _connect(self):
        """
        Establish connection to the chat server.

        Creates socket, connects to server, sends username,
        and starts the receiver thread.
        """
        try:
            self._update_status("Connecting...")

            # Create TCP socket
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(self.timeout)

            # Connect to server
            self.socket.connect((self.host, self.port))

            # Send username (JOIN message)
            join_msg = create_join_message(self.username)
            self.socket.sendall(encode_message(join_msg))

            # Connection successful
            self.connected = True
            self.socket.settimeout(None)  # Remove timeout for normal operation

            # Update GUI
            self._update_status(f"Connected as {self.username}")
            self.root.title(f"Chat - {self.username}")
            self._add_system_message(f"Connected to {self.host}:{self.port}")

            # Start receiver thread
            receiver_thread = threading.Thread(target=self._receive_loop, daemon=True)
            receiver_thread.start()

            self.logger.info(f"Connected to server as {self.username}")

        except socket.timeout:
            self._handle_connection_error("Connection timed out")

        except ConnectionRefusedError:
            self._handle_connection_error("Connection refused - is the server running?")

        except Exception as e:
            self._handle_connection_error(str(e))

    def _handle_connection_error(self, error: str):
        """Handle connection errors."""
        self.logger.error(f"Connection error: {error}")
        self._update_status("Connection failed")
        messagebox.showerror("Connection Error", error)

    def _receive_loop(self):
        """
        Continuously receive messages from the server.

        Runs in a separate thread. Puts received messages
        in the queue for GUI thread to process.
        """
        while self.running and self.connected:
            try:
                # Receive length prefix
                length_data = self._receive_exactly(LENGTH_PREFIX_SIZE)
                if not length_data:
                    break

                # Decode message length
                msg_length = decode_length_prefix(length_data)

                # Receive message data
                msg_data = self._receive_exactly(msg_length)
                if not msg_data:
                    break

                # Parse message and queue for GUI
                message = decode_message(msg_data)
                self.message_queue.put(("message", message))

            except Exception as e:
                if self.running and self.connected:
                    self.logger.error(f"Receive error: {e}")
                    self.message_queue.put(("error", str(e)))
                break

        # Connection lost
        if self.running:
            self.message_queue.put(("disconnected", None))

    def _receive_exactly(self, num_bytes: int) -> Optional[bytes]:
        """Receive exactly num_bytes from socket."""
        data = b''
        while len(data) < num_bytes:
            chunk = self.socket.recv(num_bytes - len(data))
            if not chunk:
                return None
            data += chunk
        return data

    def _process_queue(self):
        """
        Process messages from the queue.

        Called periodically by Tkinter to handle messages
        from the receiver thread in the GUI thread.
        """
        try:
            while True:
                msg_type, data = self.message_queue.get_nowait()

                if msg_type == "message":
                    self._handle_message(data)
                elif msg_type == "error":
                    self._add_system_message(f"Error: {data}", "error")
                elif msg_type == "disconnected":
                    self._handle_disconnect()

        except queue.Empty:
            pass

        # Schedule next check
        if self.running:
            self.root.after(100, self._process_queue)

    def _handle_message(self, message: Message):
        """
        Handle a received message and update GUI.

        Args:
            message (Message): The received message
        """
        if message.msg_type == MessageType.TEXT:
            self._add_chat_message(message.sender, message.content, message.timestamp)

        elif message.msg_type == MessageType.PRIVATE:
            is_mine = message.sender == self.username
            prefix = f"[PM to {message.recipient}]" if is_mine else f"[PM from {message.sender}]"
            self._add_private_message(prefix, message.content, message.timestamp)

        elif message.msg_type == MessageType.JOIN:
            self._add_system_message(message.content)

        elif message.msg_type == MessageType.LEAVE:
            self._add_system_message(message.content)

        elif message.msg_type == MessageType.USERS:
            # Update online users list
            users = json.loads(message.content)
            self._update_users_list(users)

        elif message.msg_type == MessageType.ERROR:
            self._add_system_message(message.content, "error")

        elif message.msg_type == MessageType.FILE:
            self._handle_file_message(message)

        elif message.msg_type == MessageType.PHOTO:
            self._handle_photo_message(message)

    def _add_chat_message(self, sender: str, content: str, timestamp: str = None):
        """Add a chat message to the display."""
        self.chat_display.config(state=tk.NORMAL)

        # Add timestamp
        time_str = self._format_timestamp(timestamp)
        self.chat_display.insert(tk.END, f"[{time_str}] ", "timestamp")

        # Add sender name
        tag = "my_message" if sender == self.username else "username"
        self.chat_display.insert(tk.END, f"{sender}: ", tag)

        # Add message content
        self.chat_display.insert(tk.END, f"{content}\n")

        self.chat_display.config(state=tk.DISABLED)
        self.chat_display.see(tk.END)

    def _add_private_message(self, prefix: str, content: str, timestamp: str = None):
        """Add a private message to the display."""
        self.chat_display.config(state=tk.NORMAL)

        time_str = self._format_timestamp(timestamp)
        self.chat_display.insert(tk.END, f"[{time_str}] ", "timestamp")
        self.chat_display.insert(tk.END, f"{prefix} ", "private")
        self.chat_display.insert(tk.END, f"{content}\n")

        self.chat_display.config(state=tk.DISABLED)
        self.chat_display.see(tk.END)

    def _add_system_message(self, content: str, tag: str = "system"):
        """Add a system message to the display."""
        self.chat_display.config(state=tk.NORMAL)
        self.chat_display.insert(tk.END, f"*** {content} ***\n", tag)
        self.chat_display.config(state=tk.DISABLED)
        self.chat_display.see(tk.END)

    def _format_timestamp(self, timestamp: str = None) -> str:
        """Format timestamp for display."""
        if timestamp:
            try:
                dt = datetime.fromisoformat(timestamp)
                return dt.strftime("%H:%M")
            except:
                pass
        return datetime.now().strftime("%H:%M")

    def _update_users_list(self, users: list):
        """Update the online users listbox."""
        self.online_users = users
        self.users_listbox.delete(0, tk.END)
        for user in sorted(users):
            display = f"{user} (you)" if user == self.username else user
            self.users_listbox.insert(tk.END, display)

    def _update_status(self, status: str):
        """Update the status bar."""
        self.status_var.set(status)

    def _send_message(self):
        """Send a text message."""
        content = self.message_input.get().strip()
        if not content or not self.connected:
            return

        # Clear input
        self.message_input.delete(0, tk.END)

        # Create and send message
        message = create_text_message(self.username, content)

        try:
            self.socket.sendall(encode_message(message))
        except Exception as e:
            self._add_system_message(f"Failed to send: {e}", "error")

    def _send_file(self):
        """Send a file to the chat."""
        if not self.connected:
            messagebox.showwarning("Not Connected", "Please connect first")
            return

        # Open file dialog
        file_path = filedialog.askopenfilename(
            title="Select File to Send",
            filetypes=[
                ("All Allowed", "*.txt;*.pdf;*.doc;*.docx;*.zip"),
                ("Text Files", "*.txt"),
                ("PDF Files", "*.pdf"),
                ("All Files", "*.*")
            ]
        )

        if not file_path:
            return

        self._send_file_internal(file_path, is_photo=False)

    def _send_photo(self):
        """Send a photo to the chat."""
        if not self.connected:
            messagebox.showwarning("Not Connected", "Please connect first")
            return

        # Open file dialog for images
        file_path = filedialog.askopenfilename(
            title="Select Photo to Send",
            filetypes=[
                ("Image Files", "*.png;*.jpg;*.jpeg;*.gif;*.bmp"),
                ("PNG", "*.png"),
                ("JPEG", "*.jpg;*.jpeg"),
                ("All Files", "*.*")
            ]
        )

        if not file_path:
            return

        self._send_file_internal(file_path, is_photo=True)

    def _send_file_internal(self, file_path: str, is_photo: bool):
        """Internal method to send a file or photo."""
        try:
            # Validate and encode file
            valid, error = self.file_handler.validate_file(file_path)
            if not valid:
                messagebox.showerror("Error", error)
                return

            encoded_data, file_info = self.file_handler.encode_file(file_path)

            # Create message
            if is_photo:
                message = create_photo_message(
                    self.username,
                    file_info['filename'],
                    encoded_data,
                    file_info['size']
                )
            else:
                message = create_file_message(
                    self.username,
                    file_info['filename'],
                    encoded_data,
                    file_info['size']
                )

            # Send message
            self.socket.sendall(encode_message(message))

            self._add_system_message(
                f"Sent {'photo' if is_photo else 'file'}: {file_info['filename']} "
                f"({file_info['size_formatted']})"
            )

        except Exception as e:
            messagebox.showerror("Error", f"Failed to send: {e}")

    def _handle_file_message(self, message: Message):
        """Handle received file message."""
        self._add_system_message(
            f"{message.sender} sent file: {message.filename} ({message.filesize} bytes)"
        )

        # Ask to save
        if messagebox.askyesno("File Received", f"Save {message.filename}?"):
            try:
                saved_path = self.file_handler.decode_file(
                    message.content,
                    message.filename
                )
                messagebox.showinfo("Saved", f"File saved to:\n{saved_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save: {e}")

    def _handle_photo_message(self, message: Message):
        """Handle received photo message."""
        self._add_chat_message(message.sender, f"[Photo: {message.filename}]", message.timestamp)

        # Try to display image inline if PIL available
        if PIL_AVAILABLE:
            try:
                # Decode image data
                image_data = self.file_handler.decode_to_bytes(message.content)

                # Create PIL Image
                image = Image.open(io.BytesIO(image_data))

                # Resize for display (max 300px)
                max_size = 300
                ratio = min(max_size / image.width, max_size / image.height)
                if ratio < 1:
                    new_size = (int(image.width * ratio), int(image.height * ratio))
                    image = image.resize(new_size, Image.Resampling.LANCZOS)

                # Convert to PhotoImage
                photo = ImageTk.PhotoImage(image)

                # Keep reference
                self._image_refs.append(photo)

                # Add to chat display
                self.chat_display.config(state=tk.NORMAL)
                self.chat_display.image_create(tk.END, image=photo)
                self.chat_display.insert(tk.END, "\n")
                self.chat_display.config(state=tk.DISABLED)
                self.chat_display.see(tk.END)

            except Exception as e:
                self.logger.error(f"Failed to display image: {e}")

    def _on_user_double_click(self, event):
        """Handle double-click on user in list for private message."""
        selection = self.users_listbox.curselection()
        if not selection:
            return

        selected_user = self.users_listbox.get(selection[0])
        # Remove "(you)" suffix if present
        selected_user = selected_user.replace(" (you)", "")

        if selected_user == self.username:
            return

        # Prompt for private message
        content = simpledialog.askstring(
            "Private Message",
            f"Message to {selected_user}:"
        )

        if content:
            message = create_private_message(self.username, selected_user, content)
            try:
                self.socket.sendall(encode_message(message))
            except Exception as e:
                self._add_system_message(f"Failed to send: {e}", "error")

    def _handle_disconnect(self):
        """Handle disconnection from server."""
        self.connected = False
        self._update_status("Disconnected")
        self._add_system_message("Disconnected from server", "error")
        self.users_listbox.delete(0, tk.END)

    def _on_closing(self):
        """Handle window close event."""
        if self.connected:
            # Send leave message
            try:
                leave_msg = create_leave_message(self.username)
                self.socket.sendall(encode_message(leave_msg))
            except:
                pass

            # Close socket
            try:
                self.socket.close()
            except:
                pass

        self.running = False
        self.connected = False
        self.root.destroy()


def main():
    """Main entry point for the chat client."""
    print("\n" + "=" * 50)
    print("  B205 Computer Networks - Chat Client")
    print("  Gisma University of Applied Sciences")
    print("=" * 50 + "\n")

    client = ChatClient()
    client.run()


if __name__ == '__main__':
    main()
