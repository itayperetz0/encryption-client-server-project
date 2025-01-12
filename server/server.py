# owner Itay Peretz
"""
Secure File Transfer Server Implementation

This module implements a multi-threaded server that handles secure file transfers using 
encryption (RSA and AES) and verification (CRC). It supports user registration, authentication,
and secure file transfer operations.

The server handles different types of requests identified by specific codes:
- 1025: New user registration
- 1026: Public key exchange
- 1027: Returning user authentication
- 1028: File transfer
- 1029: File verification
- 1030: CRC failure notification
- 1031: Transfer failure notification
"""

import base64
import binascii
import os
import socket
import struct
import threading
import time
import sys

sys.path.append(os.getcwd() + "\\..")
sys.path.append(os.getcwd())
from network_protocol import Network_protocol
from generatekey import Key_generator
from encrypt import Encrypt
from cksum import Cksum


class Server:
    def __init__(self):
        # Initialize variables
        self.port_num = None
        self.massage_server = None
        self.clients = []
        self.net_protocol = Network_protocol()
        self.key_generator = Key_generator()
        self.encrypt = Encrypt()
        self.cksum = Cksum()
        
    def collect_port_num(self):
        try:
            with open(os.getcwd() + "\\server\\port.info", "r") as port_info:
                self.port_num = int(port_info.read())
                print("Loaded port number successfully")        
        except FileNotFoundError:
            try: 
                with open(os.getcwd() + "\\port.info", "r") as port_info:
                    self.port_num = int(port_info.read())
                    print("Loaded port number successfully")
            except:        
                print("Error: port.info file not found")
                print("Working on default port number 1256")
                self.port_num = 1256
                exit()
                
    def create_directory(self, path_to_dir,dir_name):
        try:
            os.mkdir(os.path.join(path_to_dir,'server',dir_name))
            print(f"Directory '{dir_name}' created successfully.")
        except FileExistsError:
            print(f"Directory '{dir_name}' already exists. No action taken.")
        except:
            try:
                os.mkdir(os.path.join(path_to_dir,dir_name))
                print(f"Directory '{dir_name}' created successfully.")
            except FileExistsError:
                print(f"Directory '{dir_name}' already exists. No action taken.")
   
    def register_user(self, client_name, request_time):  
        client_uuid = self.key_generator.generate_random_uuid()
        hexa_client_uuid = binascii.hexlify(client_uuid).decode('utf-8')  
        self.clients.append({'UUID': client_uuid, 'Name': client_name, 'Public Key': None, 'LastSeen': request_time, 'AES Key': None , 'files': {}})
        return client_uuid
    
    def find_client(self, client_name):
        for client in self.clients:
            if client['Name'] == client_name:
                return client
        return None
    
    def find_client_by_uuid(self, client_uuid):
        for client in self.clients:
            if client['UUID'] == client_uuid:
                return client
        return None
    
    def create_aes_key_for_client(self, client_socket, client,res_num):
        aes_key = self.key_generator.generate_AES_key()
        client['AES Key'] = aes_key
        base64_data = base64.b64encode(aes_key)
        base64_data = base64_data.decode('utf-8')
        print ("AES key sent: " +base64_data)
        
        encrypted_aes_key = self.encrypt.encrypt_rsa_public(client['Public Key'], aes_key)
        header, payload = self.net_protocol.res_1602_1605(client['UUID'] , encrypted_aes_key,res_num)
        client_socket.sendall(header)
        client_socket.sendall(payload)
        print(f"User {client['Name']} found sending back encrypted AES key") 
        
    def recive_req_content(self, client_socket):
        request_header_size = 24
        header = client_socket.recv(request_header_size)
        client_id, version , code, payload_size,compiler_padding = struct.unpack('<16sBHIB', header)   
        payload = client_socket.recv(payload_size)
        print(len(payload))
        request_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        print(request_time)
        return client_id, version, code, payload_size, payload, request_time
    
    def write_packet_to_disk_and_handle_excption(self, client, file_name,client_socket):
        file_name_string = file_name.decode('utf-8').strip('\0')
        try:
            with open(os.path.join(os.getcwd(),'server files', file_name_string), 'wb') as file:
                file.write(client['files'][file_name_string]['Decrypted Content'])
                return True
        except:
            print(f"Error: Could not write file {file_name_string}")
            client_socket.sendall(self.net_protocol.res_1607(client['UUID']))
            return False 

    def handle_client_requests(self, client_socket, client_address): 
        try:
            while True:
                # Receive the header of a request
                client_id, version, code, payload_size, payload, request_time = self.recive_req_content(client_socket)
                
                if code == 1025:
                    print(f"User sent a request with code 1025")
                    client_name = payload.decode().rstrip('\0')
                    failed = False
                    if self.clients:
                        for client in self.clients:
                            if client['Name'] == client_name:
                                header, payload = self.net_protocol.res_1601()
                                client_socket.sendall(header)
                                failed = True
                                break
                    if not failed:
                        costumer_uuid = self.register_user(client_name, request_time)
                        print(f"New Client {client_name} has been registered")
                        print(f"Client UUID: {binascii.hexlify(costumer_uuid).decode('utf-8')}")
                        header, payload = self.net_protocol.res_1600(costumer_uuid)
                        client_socket.sendall(header)
                        client_socket.sendall(payload)  
                        
                if code == 1026:
                    client_name , client_public_key = struct.unpack('<255s160s', payload)      
                    client_name = client_name.decode().strip('\0')
                    print(f"User {client_name} sent a request with code 1026")
                    client = self.find_client(client_name)
                    if client:
                        client['Public Key'] = client_public_key
                        client_public_key = base64.b64encode(client_public_key)
                        client_public_key = client_public_key.decode('utf-8')
                        print(f"User {client_name} sent a public key: {client_public_key}")
                        self.create_aes_key_for_client(client_socket, client,1602)
                    else:
                        header, payload = self.net_protocol.res_1601()
                        client_socket.sendall(header)
                        client_socket.sendall(payload)
                        print(f"User {client_name} not found")    
                        
                if code == 1027:
                    client_name = payload
                    client_name = client_name.decode().strip('\0')
                    print(f"User {client_name} sent a request with code 1027")
                    client = self.find_client(client_name)
                    if client is None:
                        costumer_uuid = self.register_user(client_name, request_time)
                        header, payload = self.net_protocol.res_1606(costumer_uuid)
                        client_socket.sendall(header)
                        client_socket.sendall(payload)
                        print(f"User {client_name} not found, registring as new user and sending back UUID")
                        print(f"New Client {client_name} has been registered")
                        print(f"Client UUID: {binascii.hexlify(costumer_uuid).decode('utf-8')}")
                    else:
                        print('user found - sending AES key for files encryption')
                        self.create_aes_key_for_client(client_socket, client,1605)
                    
                if code == 1028:   
                    client = self.find_client_by_uuid(client_id)
                    if client is None:
                        client_socket.sendall(self.net_protocol.res_1607(client_id))
                        continue
                    print(f"User {client['Name']} sent a request with code 1028")
                    massege_len = payload_size-4-4-4-255
                    massege_len = str(massege_len)
                    content_size , orig_file_size, current_packet_num, packets_number, file_name, encrypted_massege_content = struct.unpack('<II2s2s255s'+massege_len+'s', payload) 
                    file_name = file_name.decode().strip('\0')   
                    current_packet_num = int.from_bytes(current_packet_num, byteorder='little')
                    packets_number = int.from_bytes(packets_number, byteorder='little')
                                  
                    print(f"User {client['Name']} sent packet number {current_packet_num} of file {file_name}")
                    if current_packet_num <= packets_number:
                        if current_packet_num == 1:
                            if not file_name in client['files']:
                                client['files'].update({file_name: {'CRC': None , 'Orig Size': orig_file_size,'Decrypted Size': content_size, 'Content':[encrypted_massege_content]}})
                            else:
                                client['files'][file_name] = {'CRC': None , 'Orig Size': orig_file_size,'Decrypted Size': content_size, 'Content': [encrypted_massege_content]}
                        else:
                            if current_packet_num > len(client['files'][file_name]['Content'])+1:
                                print(f"User {client['Name']} sent an invalid 1028 request,{file_name.decode('utf-8').strip('\0')} packet number: {current_packet_num} but last packet was {len(client['files'][file_name]['Content'])} server expected packet number {len(client['files'][file_name]['Content'])+1}")
                                client_socket.sendall(self.net_protocol.res_1607(client_id))
                                continue
                            else:
                                if len(client['files'][file_name]['Content']) == current_packet_num:
                                    client['files'][file_name]['Content'][current_packet_num-1] = encrypted_massege_content
                                else:
                                    client['files'][file_name]['Content'].append(encrypted_massege_content)
                                    
                    if current_packet_num == packets_number:
                        try:
                            self.decrypt_file_content(client,file_name)
                        except:
                            header , payload = self.net_protocol.res_1607()
                            client_socket.sendall(header)
                            continue
                        try:
                            crc = self.cksum.get_CRC(client['files'][file_name]['Decrypted Content'])
                        except:
                            client_socket.sendall(self.net_protocol.res_1607(client_id))
                            continue
                        header, payload = self.net_protocol.res_1603(client['UUID'], content_size, file_name, crc)
                        client_socket.sendall(header)
                        client_socket.sendall(payload)
                    elif current_packet_num > packets_number:    
                        print(f"User {client['Name']} sent a request with code 1028, packet number: {current_packet_num} is greater than total packets number: {packets_number}")
                        client_socket.sendall(self.net_protocol.res_1607(client_id)) 
                
                if code == 1029:
                    client = self.find_client_by_uuid(client_id)
                    if client is None:
                        client_socket.sendall(self.net_protocol.res_1607(client_id))
                        continue
                    print(f"User {client['Name']} sent a request with code 1029")
                    file_name = payload
                    file_name_string = file_name.decode().strip('\0')
                    if not self.write_packet_to_disk_and_handle_excption(client, file_name,client_socket):
                        continue
                    print(client['Name'] + ' crc verified and file ' +file_name_string +' is accepted and valid')
                    print(f"packet of {file_name_string} has been written to disk")
                    header, payload  = self.net_protocol.res_1604(client['UUID'])  
                    client_socket.sendall(header)
                    client_socket.sendall(payload)
                               
                if code == 1030:
                    client = self.find_client_by_uuid(client_id)
                    if client is None:
                        client_socket.sendall(self.net_protocol.res_1607(client_id))
                        continue
                    print(f"User {client['Name']} sent a request with code 1030")
                    print(f"User {client['Name']} send a request with crc failure code 1030, waiting for file resend with 1028") 
                
                if code == 1031:
                    client = self.find_client_by_uuid(client_id)
                    if client is None:
                        client_socket.sendall(self.net_protocol.res_1607(client_id))
                        continue   
                    print(f"User {client['Name']} sent a request with code 1031")    
                    header, payload = self.net_protocol.res_1604()               
                    client_socket.sendall(header)
                    client_socket.sendall(payload)
                    print(f"User {client['Name']} has failed to send file 4 times")  
                 
        finally:
            print(f"User finished his requests closing connection")                           
            client_socket.close()
            return self.clients   
    
    def decrypt_file_content(self, client, file_name):
        encrypted_content = b''
        for content in client['files'][file_name]['Content']:
            encrypted_content = encrypted_content + content
        massage_content_bytes = self.encrypt.decrypt_aes_cbc(client['AES Key'], encrypted_content)
        client['files'][file_name]['Decrypted Content'] = massage_content_bytes
        
                    
def main():
    server = Server()
    server.collect_port_num()
    server.create_directory(os.getcwd(), "server files")
    try:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind(('127.0.0.1', server.port_num))
        server_socket.listen(5)
        print('-----------------------------------------------------')
        print("             Server is running")
        print('-----------------------------------------------------')
        print(f"Server listening on {socket.gethostname()}:{server.port_num}\n\n")
    except:
        print("Error: Could not create a socket")
        sys.exit()
    
    try:
        client_threads = []
        while True:
            # Accept a connection from a client
            client_socket, client_address = server_socket.accept()
            # Start a new thread to handle the client
            client_thread = threading.Thread(target=server.handle_client_requests, args=(client_socket, client_address))
            client_thread.start()
            client_threads.append(client_thread)
        
    except BaseException:
        print("Server shutting down.")
    finally:
        for client in client_threads:
            client.join()
        save_clients_in_db(clients)
        print("Server shutting down.")


if __name__ == "__main__":
    main()
