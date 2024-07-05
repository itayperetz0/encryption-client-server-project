#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS

#include <winsock2.h>
#include <iostream>
#include "network.hpp"
#include "RSAWrapper.h"
#include "Base64Wrapper.h"
#include <string>
#include <cstdint> 

#pragma comment(lib, "ws2_32.lib")

#define CLIENT_VER 3
#define CRC_LEN 4
#define UUID_LEN 16
#define CLIENT_NAME_LEN 16
#define RES_HEADER_LEN 7
#define CONTENT_SIZE_LEN 4
#define ORIG_FILE_SIZE_LEN 4
#define PACKETS_NUM_LEN 4
#define FILE_NAME_LEN 255
#define PACKET_SIZE 1024






Network::Network() {
	this->header.version = CLIENT_VER;
}

bool Network::connect_to_server(int port, std::string ip_address) {
	// Initialize Winsock
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
		std::cerr << "WSAStartup failed" << std::endl;
		return false;
	}

	// Create socket
	this->client_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (this->client_socket == INVALID_SOCKET) {
		std::cerr << "Failed to create socket" << std::endl;
		WSACleanup();
		return false;
	}

	// Server address

	sockaddr_in serverAddr;
	serverAddr.sin_family = AF_INET;
	serverAddr.sin_addr.s_addr = inet_addr((ip_address).c_str());
	serverAddr.sin_port = htons(port);

	// Connect to server
	if (connect(this->client_socket, reinterpret_cast<sockaddr*>(&serverAddr), sizeof(serverAddr)) == SOCKET_ERROR) {
		std::cerr << "Failed to connect to server" << std::endl;
		closesocket(this->client_socket);
		WSACleanup();
		return false;
	}
	return true;
}

//this function end the communication with the server
bool Network::end_communication() {


	if (!(closesocket(this->client_socket) == SOCKET_ERROR)) {
		WSACleanup();
		return true;
	}
	return false;


}

//this function pad the string to 255 bytes
std::string Network::padStringTo255Bytes(std::string input) {
	// Ensure the input string is no longer than 255 bytes
	std::string paddedString = input.substr(0, 255);
	paddedString.size();

	// Append null terminators to fill remaining bytes
	paddedString.append(255 - input.length(), '\0');
	paddedString.size();

	return paddedString;
}

//this function recive the 1600 or 1601 response from the server
int Network::recive_1600_and_1601_res(char* client_uuid) {
	char buffer[RES_HEADER_LEN];
	int bytes_rec = recv(this->client_socket, buffer, sizeof(buffer), 0);
	if (bytes_rec == SOCKET_ERROR) {
		std::cerr << "Failed to receive 1600 or 1601 header" << std::endl;
		return 0;
	}
	char version = buffer[0];
	uint16_t code = *(uint16_t*)(buffer + 1);
	uint32_t payload_size = *(uint32_t*)(buffer + 3);

	if (code == 1601) {
		std::cout << "1601 - failed to register to server - client with same name already exists - please change client name in transfer.info and try again" << std::endl;
	}
	char payload[20] = {};
	bytes_rec = recv(this->client_socket, payload, payload_size, 0);
	strncpy(client_uuid, payload, UUID_LEN);
	std::cout << "1600 - registered successfuly";
	return 1600;
}

//this function recive the 1602 response from the server
int Network::recive_1602_res(std::string client_uuid, std::string& private_key, std::string& files_key)
{
	char buffer[RES_HEADER_LEN];
	int bytes_rec = recv(this->client_socket, buffer, sizeof(buffer), 0);
	if (bytes_rec == SOCKET_ERROR) {
		std::cerr << "Failed to receive 1602 header" << std::endl;
		return 0;
	}
	char version = buffer[0];
	uint16_t code = *(uint16_t*)(buffer + 1);
	uint32_t payload_size = *(uint32_t*)(buffer + 3);
	if (code == 1602) {//success - get the aes key
		files_key = this->accept_1602_1605_payload(1602, private_key);
		if (files_key == "0") {
			return 0;//as failed to recive 1602 payload
		}
		return 1602;
	}
	
}

//this function recive the 1603 or 1607 response from the server
int Network::recive_1603_and_1607_res(unsigned int& server_crc) {
	// Receive header
	char buffer[RES_HEADER_LEN];
	int bytes_rec = recv(this->client_socket, buffer, sizeof(buffer), 0);
	if (bytes_rec == SOCKET_ERROR) {
		std::cerr << "Failed to receive 1603 or 1607 header" << std::endl;
		return 0;
	}
	char version = buffer[0];
	uint16_t code = *(uint16_t*)(buffer + 1);
	uint32_t payload_size = *(uint32_t*)(buffer + 3);
	if (code == 1603) {//success - get the crc
		std::cout << "got 1603 response - packets received in server successfully" << std::endl;
		char buffer[UUID_LEN + CONTENT_SIZE_LEN + FILE_NAME_LEN + CRC_LEN] = {};
		int bytes = recv(this->client_socket, buffer, payload_size, 0);
		if (bytes == SOCKET_ERROR) {
			std::cerr << "Failed to receive 1603 payload" << std::endl;
			return 0;
		}
		std::string uuid(buffer, 16); // Extract the UUID
		unsigned int content_size;
		std::memcpy(&content_size, buffer + 16, sizeof(content_size)); // Extract content size
		char file_name[255];
		std::memcpy(file_name, buffer + 20, 255); // Extract file name
		unsigned int crc;
		std::memcpy(&crc, buffer + 275, sizeof(crc)); // Extract CRC
		server_crc = crc;
		return 1603;
	}
	if (code == 1607) {//faild to receive packet
		std::cout << "got 1607 - failed to receive packet" << std::endl;
		return 1607;
	}
	return 0;

}

//this function recive the 1604 response from the server
bool Network::recive_1604_res(std::string client_uuid) {
	char buffer[RES_HEADER_LEN];
	int bytes_rec = recv(this->client_socket, buffer, sizeof(buffer), 0);
	if (bytes_rec == SOCKET_ERROR) {
		std::cerr << "Failed to receive 1604 header" << std::endl;
		return false;
	}
	char version = buffer[0];
	uint16_t code = *(uint16_t*)(buffer + 1);
	uint32_t payload_size = *(uint32_t*)(buffer + 3); ;
	if (code == 1604) {
		char payload[UUID_LEN] = {};
		bytes_rec = recv(this->client_socket, payload, payload_size, 0);
		if (bytes_rec == SOCKET_ERROR) {
			std::cerr << "Failed to receive 1604 payload" << std::endl;
			return false;
		}
		std::string uuid = std::string(payload, UUID_LEN);
		if (uuid == client_uuid.substr(0, UUID_LEN)) {
			std::cout << "got 1604 - server recived 1029 or 1031 request successfully" << std::endl;
			return true;
		}
		return false;
	}
	return false;
}





//this function recive the 1605 or 1606 response from the server
int Network::recive_1605_and_1606_res(char* client_uuid, std::string& private_key, std::string& files_key) {
	char buffer[RES_HEADER_LEN];
	int bytes_rec = recv(this->client_socket, buffer, sizeof(buffer), 0);
	if (bytes_rec == SOCKET_ERROR) {
		std::cerr << "Failed to receive 1605 or 1606 header" << std::endl;
		return 0;
	}
	char version = buffer[0];
	uint16_t code = *(uint16_t*)(buffer + 1);
	uint32_t payload_size = *(uint32_t*)(buffer + 3);
	if (code == 1606) {//faild to reconnect to server
		std::cout << "1606 - failed to reconnect to server - client do not registerd in server" << std::endl;
		char payload[20] = {};
		bytes_rec = recv(this->client_socket, payload, payload_size, 0);
		strncpy(client_uuid, payload, UUID_LEN);
		return 1606;
	}
	if (code == 1605) {//success - get the aes key
		files_key = this->accept_1602_1605_payload(1605, private_key);
		if (files_key=="0") {
			return 0; //as failed to recive 1605 payload
		}
		return 1605;
	}


}

//this function send the 1025 request to the server
bool Network::req_1025(std::string client_name, char* uuid) {
	// Set header fields
	memcpy(this->header.uuid, "1111111111111111", sizeof(this->header.uuid));
	this->header.code = 1025;
	this->header.payload_size = 255;
	bool header = Network::sendHeader();
	if (!header) {
		std::cerr << "Failed to send header" + this->header.code << std::endl;
		return false;
	}
	// Send payload to server
	std::string payload = Network::padStringTo255Bytes(client_name);
	const char* paychar = payload.c_str();
	int result = send(this->client_socket, payload.c_str(), payload.size(), 0);
	if (result == SOCKET_ERROR) {
		std::cerr << "Failed to send payload" + this->header.code << std::endl;
		return false;
	}
	// Receive response from server
	int  rec_1600_res = Network::recive_1600_and_1601_res(uuid);
	if (!rec_1600_res) {
		return false;
	}



	return true;

}


bool Network::req_1026(std::string client_name, std::string client_uuid, std::string public_key, std::string& private_key, std::string& files_key) {
	// Set header fields
	memcpy(this->header.uuid, client_uuid.c_str(), sizeof(this->header.uuid));
	this->header.code = 1026;
	this->header.payload_size = PUB_KEY_LEN + CLIENT_NAME_PADDING;
	bool header = Network::sendHeader();
	if (!header) {
		std::cerr << "Failed to send header" + this->header.code << std::endl;
		return false;
	}
	// Send payload to server
	std::string name = Network::padStringTo255Bytes(client_name);
	std::string payload = name + public_key;
	int result = send(this->client_socket, payload.c_str(), this->header.payload_size, 0);
	if (result == SOCKET_ERROR) {
		std::cerr << "Failed to send payload" + this->header.code << std::endl;
		return false;
	}
	std::cout << "public key sent successfuly"  << std::endl;
	// Receive response from server
	int rec_1602_res = Network::recive_1602_res(client_uuid, private_key, files_key);
	if (!rec_1602_res) {

		return false;
	}
	std::cout << "AES key recived encrypted from server and after decription is: "<< Base64Wrapper::encode(files_key) << std::endl;
	return true;
}

//this function send the 1027 request to the server
int Network::req_1027(std::string client_name, char* client_uuid, std::string& private_key, std::string& files_key) {
	// Set header fields
	memcpy(this->header.uuid, client_uuid, sizeof(this->header.uuid));
	this->header.code = 1027;
	this->header.payload_size = 255;
	bool header = Network::sendHeader();
	if (!header) {
		std::cerr << "Failed to send header" + this->header.code << std::endl;
		return 0;
	}
	// Send payload to server
	std::string payload = Network::padStringTo255Bytes(client_name);
	const char* paychar = payload.c_str();
	int result = send(this->client_socket, paychar, this->header.payload_size, 0);
	if (result == SOCKET_ERROR) {
		std::cerr << "Failed to send payload" + this->header.code << std::endl;
		return 0;
	}
	// Receive response from server
	int rec_1605_and_1606_res = Network::recive_1605_and_1606_res(client_uuid, private_key, files_key);
	if (!rec_1605_and_1606_res) {//faild to reconnect to server
		return 0;
	}
	if (rec_1605_and_1606_res == 1606)
	{//faild to reconnect to server
		std::cout << "reconnect to server failed - client registerd as new client" << std::endl;
		return 1606;
	}
	if (rec_1605_and_1606_res == 1605)
	{//success - got the aes key
		std::cout << "reconnect success - server found client name";
		return 1605;
	}
}

//this function send the 1028 request to the server
int Network::req_1028(std::string client_uuid, std::string encrypted_content, int orig_file_size, std::string file_name, unsigned int& crc) {
	// Set header fields
	memcpy(this->header.uuid, client_uuid.c_str(), sizeof(this->header.uuid));
	int encrypted_content_len = encrypted_content.size();
	int content_remain_to_deliver = encrypted_content_len;
	this->header.code = 1028;
	size_t offset = 0;
	//send all the packets with header and payload
	while (content_remain_to_deliver > 0) {
		int delivered_content = min(PACKET_SIZE, content_remain_to_deliver);
		this->header.payload_size = CONTENT_SIZE_LEN + ORIG_FILE_SIZE_LEN + PACKETS_NUM_LEN + FILE_NAME_LEN + delivered_content;
		bool header = Network::sendHeader();
		if (!header) {
			std::cerr << "Failed to send header" + this->header.code << std::endl;
			return 0;
		}
		std::string packet = encrypted_content.substr(offset, delivered_content);
		this->req1028_payload.packet_num = offset / PACKET_SIZE + 1;
		this->req1028_payload.total_packets = encrypted_content_len / PACKET_SIZE + 1;
		this->req1028_payload.orig_file_size = orig_file_size;
		this->req1028_payload.encrypted_content_size = encrypted_content_len;
		memcpy(this->req1028_payload.file_name, file_name.c_str()+ 0, file_name.size()+1);
		memcpy(this->req1028_payload.packet_data, packet.c_str(), delivered_content);
		char payload[sizeof(Req1028Payload) - 1];
		memset(payload, 0, sizeof(Req1028Payload) - 1);

		memcpy(payload, &(this->req1028_payload.encrypted_content_size), sizeof(this->req1028_payload.encrypted_content_size));
		memcpy(payload + sizeof(this->req1028_payload.encrypted_content_size), &(this->req1028_payload.orig_file_size), sizeof(this->req1028_payload.orig_file_size));
		memcpy(payload + sizeof(this->req1028_payload.encrypted_content_size) + sizeof(this->req1028_payload.orig_file_size), &(this->req1028_payload.packet_num), sizeof(this->req1028_payload.packet_num));
		memcpy(payload + sizeof(this->req1028_payload.encrypted_content_size) + sizeof(this->req1028_payload.orig_file_size) + sizeof(this->req1028_payload.packet_num), &(this->req1028_payload.total_packets), sizeof(this->req1028_payload.total_packets));
		memcpy(payload + sizeof(this->req1028_payload.encrypted_content_size) + sizeof(this->req1028_payload.orig_file_size) + sizeof(this->req1028_payload.packet_num) + sizeof(this->req1028_payload.total_packets), this->req1028_payload.file_name, sizeof(this->req1028_payload.file_name));
		memcpy(payload + sizeof(this->req1028_payload.encrypted_content_size) + sizeof(this->req1028_payload.orig_file_size) + sizeof(this->req1028_payload.packet_num) + sizeof(this->req1028_payload.total_packets) + sizeof(this->req1028_payload.file_name), this->req1028_payload.packet_data, delivered_content);
		int result = send(this->client_socket, payload, this->header.payload_size, 0);

		if (result == SOCKET_ERROR) {
			std::cerr << "Failed to send payload" + this->header.code << std::endl;
			return 0;
		}
		offset += delivered_content;
		content_remain_to_deliver -= delivered_content;
		std::cout << "packet number: " << this->req1028_payload.packet_num << " out of: " << this->req1028_payload.total_packets << " sent" <<std::endl;
	}
	// Receive response from server
	int rec_1603_res = Network::recive_1603_and_1607_res(crc);
	if (rec_1603_res == 1603) {
		return 1;
	}
	else {
		return 0;
	}
}

//this function send the 1029 request to the server
bool Network::req_1029(std::string client_uuid, std::string file_name) {
	// Set header fields
	memcpy(this->header.uuid, client_uuid.c_str(), sizeof(this->header.uuid));
	this->header.code = 1029;
	this->header.payload_size = FILE_NAME_LEN;
	bool header = Network::sendHeader();
	if (!header) {
		std::cerr << "Failed to send header" + this->header.code << std::endl;
		return false;
	}
	// Send payload to server
	if (!send_1029_1030_1031_payload(file_name)) {
		return false;
	}
	// Receive response from server
	bool valid_1604 = this->recive_1604_res(client_uuid);
	if (!valid_1604) {
		return false;
	}
	return true;



}

//this function send the payload of the 1029,1030,1031 requests
bool Network::send_1029_1030_1031_payload(std::string file_name) {
	char payload[255] = {0};
	memcpy(payload, file_name.c_str(), file_name.size());
	int result = send(this->client_socket, payload, sizeof(payload), 0);
	if (result == SOCKET_ERROR) {
		std::cerr << "Failed to send payload" + this->header.code << std::endl;
		return false;
	}

	return true;

}

//this function send the 1030 request to the server
bool Network::req_1030(std::string client_uuid, std::string file_name) {
	// Set header fields
	memcpy(this->header.uuid, client_uuid.c_str(), sizeof(this->header.uuid));
	this->header.code = 1030;
	this->header.payload_size = FILE_NAME_LEN;
	bool header = Network::sendHeader();
	if (!header) {
		std::cerr << "Failed to send header" + this->header.code << std::endl;
		return false;
	}
	// Send payload to server
	if (!send_1029_1030_1031_payload(file_name)) {
		return false;
	}

	return true;
}

//this function send the 1031 request to the server
bool Network::req_1031(std::string client_uuid, std::string file_name) {
	// Set header fields
	memcpy(this->header.uuid, client_uuid.c_str(), sizeof(this->header.uuid));
	this->header.code = 1031;
	this->header.payload_size = FILE_NAME_LEN;
	bool header = Network::sendHeader();
	if (!header) {
		std::cerr << "Failed to send header" + this->header.code << std::endl;
		return false;
	}
	// Send payload to server
	if (!send_1029_1030_1031_payload(file_name)) {
		return false;
	}
	// Receive response from server
	bool valid_1604 = this->recive_1604_res(client_uuid);
	if (!valid_1604) {
		return false;
	}
	return true;
}



//this function send the headers of all requests to the server
bool Network::sendHeader() {
	if (client_socket == INVALID_SOCKET) {
		std::cerr << "Not connected to server" << std::endl;
		return false;
	}

	// Serialize header into a byte array
	char buffer[sizeof(Header)];
	memset(buffer, 0, sizeof(Header)); // Initialize buffer


	// Copy header fields to buffer in little-endian order
	memcpy(buffer, this->header.uuid, sizeof(this->header.uuid));
	buffer[sizeof(this->header.uuid)] = header.version;
	memcpy(buffer + sizeof(this->header.uuid) + sizeof(header.version), &(this->header.code), sizeof(this->header.code));
	memcpy(buffer + sizeof(this->header.uuid) + sizeof(header.version) + sizeof(this->header.code), &(this->header.payload_size), sizeof(this->header.payload_size));

	// Send header to server
	int result = send(this->client_socket, buffer, sizeof(buffer), 0);
	if (result == SOCKET_ERROR) {
		std::cerr << "Failed to send header" << std::endl;
		closesocket(client_socket);
		WSACleanup();
		return false;
	}

	return true;
}

//this function convert string to little endian vector
std::vector<uint8_t> Network::stringToLittleEndian(const std::string& str)
{
	std::vector<uint8_t> result;

	// Convert each character of the string to uint8_t and store in little-endian order
	for (size_t i = 0; i < str.size(); ++i) {
		result.push_back(static_cast<uint8_t>(str[i]));
	}

	return result;

}

//this function accept the 1602 or 1605 payload from the server
std::string Network::accept_1602_1605_payload(int res_num, std::string& private_key) {
	char payload_buffer[UUID_LEN + ENCRYPT_AES_LEN];
	int bytes_rec = recv(this->client_socket, payload_buffer, 16, 0);
	if (bytes_rec == SOCKET_ERROR) {
		std::cerr << "Failed to receive " << res_num << " payload" << std::endl;
		return "0";//as failed
	}
	std::string uuid = std::string(payload_buffer, UUID_LEN);
	bytes_rec = recv(this->client_socket, payload_buffer, ENCRYPT_AES_LEN, 0);
	std::string aes_key_encrypted = std::string(payload_buffer, 128);
	RSAPrivateWrapper privateWrapper(private_key);
	std::string oriv = privateWrapper.getPrivateKey();
	std::string aes_key = privateWrapper.decrypt(aes_key_encrypted);
	std::cout << "got 1602 or 1605 - got AES key from server";
	return aes_key;
}