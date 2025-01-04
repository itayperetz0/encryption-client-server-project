# Secure File Transfer System

## Overview
A secure client-server application for transferring files with encryption and integrity verification. The system implements a custom network protocol with RSA and AES encryption, ensuring secure file transfer between clients and server.

## Features
- Secure client registration and authentication
- RSA public/private key encryption for key exchange
- AES encryption for file transfers
- CRC-based file integrity verification
- Multi-threaded server supporting multiple concurrent clients
- Automatic file chunking for large file transfers
- Robust error handling and retry mechanisms

## System Architecture

### Components
1. **Server**
   - Handles client registration and authentication
   - Manages client sessions and file transfers
   - Verifies file integrity using CRC
   - Stores received files securely

2. **Client**
   - Manages user registration and authentication
   - Handles file encryption and transfer
   - Implements automatic retry on transfer failures
   - Provides status feedback during transfers

3. **Network Protocol**
   - Custom implementation with specific message types
   - Secure key exchange mechanism
   - File transfer with chunking support
   - Error handling and status reporting

### Protocol Messages
- 1025: New user registration
- 1026: Public key exchange
- 1027: Returning user authentication
- 1028: File transfer
- 1029: File verification
- 1030: CRC failure notification
- 1031: Transfer failure notification

## Setup and Configuration

### Prerequisites
- Windows operating system
- C++ compiler with C++17 support
- Winsock2 library
- Visual Studio (recommended)

### Configuration Files
1. **port.info**
   - Contains server port number
   - Must be in the same directory as executable

2. **transfer.info**
   - Format:
     ```
     [IP]:[PORT]
     [CLIENT_NAME]
     [FILE_PATH_1]
     [FILE_PATH_2]
     ...
     ```

3. **me.info** (created after first registration)
   - Stores client information
   - Contains UUID and encrypted keys

### Building
1. Clone the repository
2. Open the solution in Visual Studio
3. Build the solution in Release mode
4. Server and client executables will be created

## Usage

### Starting the Server
1. Ensure port.info exists with correct port number
2. Run the server executable
3. Server will create required directories automatically

### Running the Client
1. Create transfer.info with appropriate settings
2. Run the client executable
3. Follow the prompts for registration/authentication
4. Files will be transferred automatically

### File Transfer Process
1. Client registers/authenticates with server
2. RSA key exchange occurs
3. AES key is generated for file encryption
4. Files are encrypted and sent in chunks
5. Server verifies each chunk with CRC
6. Transfer status is reported to user

## Error Handling
- Automatic retry for failed transfers (up to 4 attempts)
- CRC verification for file integrity
- Graceful handling of network disconnections
- Clear error messages and status reporting

## Security Features
- RSA encryption for key exchange
- AES encryption for file content
- Unique UUID for each client
- Secure storage of keys and client information
- CRC-based integrity verification

## Project Structure
```
├── server/
│   ├── server.py
│   ├── network.py
│   └── port.info
├── client/
│   ├── client.cpp
│   ├── network.cpp
│   └── transfer.info
└── README.md
```

## Troubleshooting

### Common Issues
1. **Connection Failed**
   - Verify port.info contains correct port
   - Check server is running
   - Verify IP address in transfer.info

2. **Authentication Failed**
   - Ensure client name is unique
   - Check me.info exists for returning users

3. **Transfer Failed**
   - Verify file paths in transfer.info
   - Check for sufficient disk space
   - Ensure stable network connection

### Debug Logs
- Server logs connection attempts and transfers
- Client reports detailed transfer status
- Check console output for error messages

## Contributing
1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License
[Your License Here]
