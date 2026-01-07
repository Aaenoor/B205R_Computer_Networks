# B205 Computer Networks - Chat Application

A comprehensive multi-user chat application demonstrating advanced networking and communication protocols using Python.

## Project Overview

This project implements a real-time messaging application with the following features:
- **Real-time text messaging** between multiple users
- **Photo transfer** with inline image display
- **File transfer** supporting various file types
- **Contact management** with online users list
- **Message history** stored in SQLite database
- **Modern GUI** built with Tkinter


### Why Client-Server over P2P?
- Centralized message routing and user management
- No NAT traversal or hole-punching required
- Simpler contact management
- Server can persist message history

### Why TCP over UDP?
- Reliable, ordered message delivery
- Built-in connection state management
- Essential for file transfers (no lost data)
- Flow control and congestion handling


## Requirements

### System Requirements
- Python 3.8 or higher
- Windows, macOS, or Linux

### Python Dependencies
```
Pillow>=9.0.0    # For image handling in GUI
```

All other modules used are from Python's standard library:
- `socket` - Network communication
- `threading` - Multi-threaded server
- `tkinter` - GUI framework
- `sqlite3` - Database
- `json` - Message serialization
- `base64` - File encoding
- `configparser` - Configuration management
- `logging` - Application logging

## Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/[username]/b205-chat-application.git
   cd b205-chat-application
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Configure settings (optional):**
   Edit `config.ini` to change server host, port, or other settings:
   ```ini
   [SERVER]
   host = localhost
   port = 5000
   max_connections = 10
   ```

## Usage

### Starting the Server

1. Open a terminal/command prompt
2. Navigate to the project directory
3. Run:
   ```bash
   python src/server.py
   ```
4. The server will start and display:
   ```
   ==================================================
     B205 Computer Networks - Chat Server
     Gisma University of Applied Sciences
   ==================================================

   [SERVER] Chat server running on localhost:5000
   [SERVER] Waiting for connections...
   ```

### Starting the Client

1. Open another terminal (keep server running)
2. Run:
   ```bash
   python src/client.py
   ```
3. Enter your username when prompted
4. The chat window will open

### Running Multiple Clients

To test with multiple users:
1. Keep the server running
2. Open multiple terminals
3. Run `python src/client.py` in each
4. Enter different usernames for each client

## Features Guide

### Sending Text Messages
1. Type your message in the input field at the bottom
2. Press Enter or click "Send"
3. Message appears in all connected clients

### Sending Private Messages
1. Select a user from the "Online Users" panel on the right
2. Check the "Private Message" checkbox
3. Type and send your message
4. Only the selected user will receive it

### Sending Photos
1. Click the "Photo" button
2. Select an image file (PNG, JPG, GIF, etc.)
3. The photo will be displayed inline in the chat

### Sending Files
1. Click the "File" button
2. Select any allowed file type
3. Recipients will be notified and can download the file

### Viewing Online Users
- The right panel shows all currently connected users
- Users appear when they join and disappear when they leave
- Click a username to send private messages

## Configuration

Edit `config.ini` to customize:

| Setting | Description | Default |
|---------|-------------|---------|
| `host` | Server IP address | localhost |
| `port` | Server port number | 5000 |
| `max_connections` | Maximum simultaneous clients | 10 |
| `max_file_size` | Maximum file size for transfers | 10MB |
| `log_level` | Logging verbosity | INFO |

## Message Protocol

The application uses a JSON-based protocol with length-prefixed framing:

```
[4 bytes: length][N bytes: JSON message]
```

### Message Format
```json
{
  "type": "TEXT|FILE|PHOTO|JOIN|LEAVE|USERS|PRIVATE|ERROR",
  "sender": "username",
  "recipient": "all|specific_username",
  "content": "message text or base64 encoded data",
  "filename": "optional_filename.ext",
  "filesize": 12345,
  "timestamp": "2026-01-04T12:00:00"
}
```

### Message Types
| Type | Description |
|------|-------------|
| TEXT | Regular chat message |
| FILE | File transfer |
| PHOTO | Image transfer (displayed inline) |
| JOIN | User joined notification |
| LEAVE | User left notification |
| USERS | Online users list update |
| PRIVATE | Direct message to specific user |
| ERROR | Error notification |

## Database Schema

SQLite database stores message history:

```sql
-- Messages table
CREATE TABLE messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender TEXT NOT NULL,
    recipient TEXT NOT NULL,
    content TEXT,
    message_type TEXT NOT NULL,
    filename TEXT,
    filesize INTEGER,
    timestamp DATETIME
);

-- Users table
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    first_seen DATETIME,
    last_seen DATETIME,
    is_online INTEGER,
    message_count INTEGER
);

-- Contacts table
CREATE TABLE contacts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_username TEXT NOT NULL,
    contact_username TEXT NOT NULL,
    added_at DATETIME
);
```

## Logging

The application logs events to both console and file:
- Log files are stored in the `logs/` directory
- Server logs: `logs/chat_server_YYYYMMDD.log`
- Client logs: `logs/chat_client_YYYYMMDD.log`

Log levels can be configured in `config.ini`.

## Troubleshooting

### "Address already in use" error
The server port is still bound. Wait a few seconds or change the port in `config.ini`.

### Client cannot connect
1. Ensure the server is running
2. Check that host/port match in `config.ini`
3. Check firewall settings

### File transfer fails
1. Verify file size is under the limit (default 10MB)
2. Ensure file type is in the allowed extensions list

