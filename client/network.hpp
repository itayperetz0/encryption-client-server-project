#ifndef NETWORK_HPP
#define NETWORK_HPP

#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS

#include <winsock2.h>
#pragma comment(lib, "ws2_32.lib")
#include <vector>

struct Header {
    uint8_t uuid[16];    // ID of 16 bytes
    uint8_t version;   // Version of one byte
    uint16_t code;     // Code of 2 bytes
    uint32_t payload_size;     // Size of 4 bytes
};

struct Req1028Payload {
    uint32_t encrypted_content_size;
    uint32_t orig_file_size;
    uint16_t packet_num;
    uint16_t total_packets;
    char file_name[255];
    char packet_data[1024];
};
    
 
#define CLIENT_NAME_PADDING 255
#define PUB_KEY_LEN 160
#define UUID_LEN 16
#define CLIENT_NAME_LEN 16
#define RES_HEADER_LEN 7
#define AES_LEN 48
#define ENCRYPT_AES_LEN 128

class Network {
public:

    Network();

    bool connect_to_server(int port, std::string ip_address);
    
    bool req_1025(std::string client_name, char* uuid);
    bool req_1026(std::string client_name, std::string uuid, std::string pub_key,std::string &private_key, std::string& files_key);
    int req_1027(std::string client_name , char* client_uuid, std::string& private_key, std::string& files_key);
    int req_1028(std::string client_uuid, std::string encrypted_content, int orig_file_size, std::string file_name, unsigned int& crc);
    bool req_1029(std::string client_uuid,std::string file_name);
    bool req_1030(std::string client_uuid,std::string file_name);
    bool req_1031(std::string client_uuid,std::string file_name);
    bool end_communication();
    
    

private:
  
   Header header;
   Req1028Payload req1028_payload;
   bool sendHeader();
   SOCKET client_socket;
   std::string padStringTo255Bytes(std::string input);
   std::vector<uint8_t> stringToLittleEndian(const std::string& str);
   int recive_1600_and_1601_res(char* client_uuid);
   int recive_1602_res(std::string client_uuid, std::string &private_key, std::string& files_key);
   int recive_1603_and_1607_res(unsigned int& server_crc);
   int recive_1605_and_1606_res(char* client_uuid, std::string& private_key, std::string& files_key);
   std::string accept_1602_1605_payload(int res_num, std::string& private_key);
   bool send_1029_1030_1031_payload(std::string file_name);   
   bool recive_1604_res(std::string client_uuid);
   
   

};

#endif  NETWORK_HPP
