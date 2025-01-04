"""
Network Protocol Implementation

This module implements a network protocol for secure file transfer operations.
It handles various response codes and their corresponding payload structures:

Response Codes:
- 1600: New user registration successful
- 1601: Registration failed (user exists)
- 1602: Send encrypted AES key
- 1603: File content CRC
- 1604: Success acknowledgment
- 1605: Returning user AES key
- 1606: Returning user UUID
- 1607: General error
- 1609: General error without payload

All responses follow a standard format:
- Header: Version (1 byte), Code (2 bytes), Payload Size (4 bytes)
- Payload: Variable structure depending on response code
"""

import struct

class Network_protocol:
    """
    Implements network protocol for secure file transfer operations.
    
    Handles message formatting, encoding, and creation of response packets
    according to the protocol specification.
    """
    
    def __init__(self):
        """
        Initialize protocol handler with default response structure.
        
        Attributes:
            response (dict): Contains protocol version and placeholder for code and payload
        """
        self.response = {
            'Version': 3,
            'Code': None,
            'Payload size': None,
        }
    
    def res_1600(self, uuid):
        """
        Create response for successful user registration.
        
        Args:
            uuid (bytes): 16-byte UUID assigned to the new user
            
        Returns:
            tuple: (header, payload) where header contains protocol metadata
                  and payload contains the UUID
        """
        self.response['Code'] = 1600
        self.response['Payload size'] = 16
        self.response['Payload'] = uuid
        header = struct.pack('<BHI', self.response['Version'], 
                           self.response['Code'], 
                           self.response['Payload size'])
        payload = struct.pack('<16s', self.response['Payload'])
        return header, payload
    
    def res_1601(self):
        """
        Create response for failed registration (user already exists).
        
        Returns:
            tuple: (header, None) where header contains protocol metadata
                  and no payload is needed
        """
        self.response['Code'] = 1601
        self.response['Payload size'] = 0
        header = struct.pack('<BHI', self.response['Version'], 
                           self.response['Code'], 
                           self.response['Payload size'])
        return header, None  
    
    def res_1607(self):
        """
        Create response for general error condition.
        
        Returns:
            tuple: (header, None) where header contains protocol metadata
                  and no payload is needed
        """
        self.response['Code'] = 1607
        self.response['Payload size'] = 0
        header = struct.pack('<BHI', self.response['Version'], 
                           self.response['Code'], 
                           self.response['Payload size'])
        return header, None      
    
    def res_1606(self, uuid):
        """
        Create response for returning user, including their UUID.
        
        Args:
            uuid (bytes): 16-byte UUID of the returning user
            
        Returns:
            tuple: (header, payload) where header contains protocol metadata
                  and payload contains the UUID
        """
        self.response['Code'] = 1606
        uuid_size = 16
        self.response['Payload size'] = uuid_size
        header = struct.pack('<BHI', self.response['Version'], 
                           self.response['Code'], 
                           self.response['Payload size']) 
        payload = uuid
        return header, payload
    
    def res_1604(self, uuid):
        """
        Create response for successful operation acknowledgment.
        
        Args:
            uuid (bytes): 16-byte UUID of the user
            
        Returns:
            tuple: (header, payload) where header contains protocol metadata
                  and payload contains the UUID
        """
        self.response['Code'] = 1604
        uuid_size = 16
        self.response['Payload size'] = uuid_size
        header = struct.pack('<BHI', self.response['Version'], 
                           self.response['Code'], 
                           self.response['Payload size'])
        payload = struct.pack('<16s', uuid)
        return header, payload
    
    def res_1602_1605(self, client_uuid, encrypted_key, res_num):
        """
        Create response containing encrypted AES key.
        Used for both new (1602) and returning (1605) users.
        
        Args:
            client_uuid (bytes): 16-byte UUID of the client
            encrypted_key (bytes): Encrypted AES key
            res_num (int): Response code (1602 or 1605)
            
        Returns:
            tuple: (header, payload) where header contains protocol metadata
                  and payload contains UUID and encrypted key
        """
        self.response['Code'] = res_num
        uuid_size = 16
        encrypted_key_size = len(encrypted_key)
        self.response['Payload size'] = uuid_size + encrypted_key_size
        header = struct.pack('<BHI', self.response['Version'], 
                           self.response['Code'], 
                           self.response['Payload size']) 
        payload = struct.pack('<16s128s', client_uuid, encrypted_key)
        return header, payload
    
    def res_1609(self):
        """
        Create response for general error without payload.
        
        Returns:
            tuple: (header, None) where header contains protocol metadata
                  and no payload is needed
        """
        self.response['Code'] = 1609
        self.response['Payload size'] = 0
        header = struct.pack('<BHI', self.response['Version'], 
                           self.response['Code'], 
                           self.response['Payload size'])
        return header, None
    
    def res_1603(self, uuid, content_size, file_name, crc):
        """
        Create response containing file CRC information.
        
        Args:
            uuid (bytes): 16-byte UUID of the client
            content_size (int): Size of the file content
            file_name (str): Name of the file being processed
            crc (int): Calculated CRC value
            
        Returns:
            tuple: (header, payload) where header contains protocol metadata
                  and payload contains file information and CRC
        """
        self.response['Code'] = 1603
        self.response['Payload size'] = 279  # Fixed size: 16 + 4 + 255 + 4
        file_name = file_name.ljust(255, '\0').encode()
        header = struct.pack('<BHI', self.response['Version'], 
                           self.response['Code'], 
                           self.response['Payload size'])
        payload = struct.pack('<16sI255sI', uuid, content_size, file_name, crc)
        return header, payload
