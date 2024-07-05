# owner Itay Peretz
# ID 207007329

import struct

class Network_protocol:
    
    def __init__(self):
        # Initialize response dict
        self.response = {'Version': 3, 'Code': None, 'Payload size': None, }
    
   
    
    # Response method for code 1600
    def res_1600(self, uuid):
        self.response['Code'] = 1600
        self.response['Payload size'] = 16
        self.response['Payload'] = uuid
        header = struct.pack('<BHI', self.response['Version'], self.response['Code'], self.response['Payload size'])
        payload = struct.pack('<16s', self.response['Payload'])
        return header, payload
    
    # Response method for code 1601
    def res_1601(self):
        self.response['Code'] = 1601
        self.response['Payload size'] = 0
        header = struct.pack('<BHI', self.response['Version'], self.response['Code'], self.response['Payload size'])
        return header, None  
    
    # Response method for code 1607
    def res_1607(self):
        self.response['Code'] = 1607
        self.response['Payload size'] = 0
        header = struct.pack('<BHI', self.response['Version'], self.response['Code'], self.response['Payload size'])
        return header, None      
    
    
    
    # Response method for code 1606
    def res_1606(self, uuid):
        self.response['Code'] = 1606
        uuid_size = 16
        self.response['Payload size'] = uuid_size
        header = struct.pack('<BHI', self.response['Version'], self.response['Code'], self.response['Payload size']) 
        payload = uuid
        return header, payload
    
    
    # Response method for code 1604
    def res_1604(self, uuid):
        self.response['Code'] = 1604
        uuid_size = 16
        self.response['Payload size'] = uuid_size
        header = struct.pack('<BHI', self.response['Version'], self.response['Code'], self.response['Payload size'])
        payload = struct.pack('<16s', uuid)
        return header, payload
    
    
    
    # Response method for code 1605
    def res_1602_1605(self,client_uuid , encrypted_key,res_num):
        self.response['Code'] = res_num
        uuid_size = 16
        encrypted_key_size = len(encrypted_key)
        self.response['Payload size'] = uuid_size + encrypted_key_size
        header = struct.pack('<BHI', self.response['Version'], self.response['Code'], self.response['Payload size']) 
        payload = struct.pack('<16s128s', client_uuid, encrypted_key)
        return header, payload
    
    # Response method for code 1609
    def res_1609(self):
        self.response['Code'] = 1609
        self.response['Payload size'] = 0
        header = struct.pack('<BHI', self.response['Version'], self.response['Code'], self.response['Payload size'])
        return header, None
    
    
    # Resonse method for code 1603
    def res_1603(self,uuid, content_size, file_name, crc):
        self.response['Code'] = 1603
        self.response['Payload size'] = 279
        file_name = file_name.ljust(255, '\0').encode()
        header = struct.pack('<BHI', self.response['Version'], self.response['Code'], self.response['Payload size'])
        payload = struct.pack('<16sI255sI', uuid, content_size, file_name, crc )
        return header, payload