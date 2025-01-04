#include <iostream>
#include <string>
#include <fstream>
#include <filesystem>

#include "input_validation.hpp"
#include "network.hpp"
#include "RSAWrapper.h"
#include "Base64Wrapper.h"
#include "AESWrapper.h"

/**
 * @brief Constants for client configuration and operation
 */
#define NEW_REGISTER 1
#define NUM_KEY_LINES 12
#define AES_KEY_LEN 32

using namespace std;
namespace fs = std::filesystem;

string get_crc(std::string fname);  // Forward declaration

/**
 * @class Client
 * @brief Main client class for secure file transfer operations
 */
class Client {
public:
    /**
     * @brief Default constructor initializing client with empty values
     */
    Client() : client_name(""), server_port(0), network() {}

    /**
     * @brief Registers client with the server
     */
    int registerClient() {
        bool valid_connect = this->network.connect_to_server(this->server_port, this->server_ip);
        if (!valid_connect) {
            return 0;
        }
        char uuid[16];
        bool valid_req = this->network.req_1025(this->client_name, uuid);
        if (!valid_req) {
            return -1;
        }
        (this->client_uuid).assign(uuid);
        cout << "Client registered in server with user name: " << this->client_name << std::endl;
        string hexa_uuid = bytesToHex(uuid, UUID_LEN);
        cout << "Client registered in server and got UUID: " << hexa_uuid << std::endl;
        return 1;
    }

    /**
     * @brief Saves private key to file in executable directory
     */
    bool save_priv_key(char* argv, string privateKey) {
        string exec_path(argv);
        string priv_64 = Base64Wrapper::encode(privateKey);
        if (!saveToFileInExecutableDirectory("priv.key", exec_path, priv_64)) {
            return false;
        }
        return true;
    }

    /**
     * @brief Saves client information to me.info file
     */
    bool save_me_info(char* argv, string privateKey) {
        string exec_path(argv);
        string hexa_uuid = bytesToHex((this->client_uuid).c_str(), 16);
        string priv_64 = Base64Wrapper::encode(privateKey);
        string data = this->client_name + "\n" + hexa_uuid + "\n" + priv_64;
        if (!saveToFileInExecutableDirectory("me.info", exec_path, data)) {
            return false;
        }
        return true;
    }

    /**
     * @brief Reads and validates me.info file
     */
    bool read_me_info_file(char* executable_path, InputValidator validator) {
        fs::path exe_path = fs::canonical(fs::path(executable_path)).remove_filename();
        fs::path me_info_path = exe_path / "me.info";
        ifstream me_info_file(me_info_path);
        if (me_info_file.is_open()) {
            string line;
            getline(me_info_file, line);
            bool valid_name = validator.isValidName(line);
            if (!valid_name) {
                cout << "Invalid client name" << endl;
                return false;
            }
            this->client_name = line;
            getline(me_info_file, line);
            bool valid_uuid = validator.isValidUUID(line);
            if (!valid_uuid) {
                cout << "Invalid UUID" << endl;
                return false;
            }
            this->client_uuid = this->hexToBytes(line);
            std::string prv_key;
            for (int i = 0; i < NUM_KEY_LINES; i++) {
                getline(me_info_file, line);
                bool valid_private_key = validator.isValidPrivateKey(line);
                if (!valid_private_key) {
                    cout << "Invalid private key" << endl;
                    return false;
                }
                prv_key += line + '\n';
            }
            string byte_key = Base64Wrapper::decode(prv_key);
            this->client_private_key = byte_key;
            getline(me_info_file, line);
            if (!line.empty()) {
                cout << "Illegal format of me.info file" << endl;
                return false;
            }
            me_info_file.close();
            return true;
        }
        else {
            cout << "Unable to open me.info file" << endl;
            return false;
        }
    }

    /**
     * @brief Reads and validates private key file
     */
    bool read_priv_key(char* executable_path, InputValidator validator) {
        fs::path exe_path = fs::canonical(fs::path(executable_path)).remove_filename();
        fs::path priv_key_path = exe_path / "priv.key";
        ifstream priv_key_file(priv_key_path);
        if (priv_key_file.is_open()) {
            string prv_key = "";
            string line;
            for (int i = 0; i < NUM_KEY_LINES; i++) {
                getline(priv_key_file, line);
                bool valid_private_key = validator.isValidPrivateKey(line);
                if (!valid_private_key) {
                    cout << "Invalid private key" << endl;
                    return false;
                }
                prv_key += line + '\n';
            }
            prv_key = Base64Wrapper::decode(prv_key);
            this->client_private_key = prv_key;
            return true;
        }
        else {
            cout << "Unable to open priv.key file" << endl;
            return false;
        }
    }

    /**
     * @brief Reads and validates transfer.info file
     */
    bool read_transfer_info_file(char* executable_path, InputValidator validator) {
        fs::path exe_path = fs::canonical(fs::path(executable_path)).remove_filename();
        fs::path transfer_info_path = exe_path / "transfer.info";
        ifstream transfer_info_file(transfer_info_path);
        if (transfer_info_file.is_open()) {
            string line;
            getline(transfer_info_file, line);
            size_t pos = line.find_first_of(":");
            if (pos == std::string::npos) {
                cout << "Invalid format of transfer.info file- missing port number in first line" << endl;
                return false;
            }

            bool valid_ip = validator.isValidIPv4(line.substr(0, pos));
            if (!valid_ip) {
                std::cout << "Invalid IPv4 address" << std::endl;
                return false;
            }
            std::cout << "Valid IPv4 address" << std::endl;
            this->server_ip = line.substr(0, pos);

            bool valid_port = validator.isValidPort(line.substr(pos + 2));
            if (!valid_port) {
                std::cout << "Invalid port number" << std::endl;
                return false;
            }
            std::cout << "Valid port number" << std::endl;
            this->server_port = stoi(line.substr(pos + 1));

            getline(transfer_info_file, line);
            bool valid_name = validator.isValidName(line);
            if (!valid_name) {
                cout << "Invalid client name" << endl;
                return false;
            }
            this->client_name = line;
            bool first_file = true;
            int num_of_files = 0;
            while (num_of_files < 100) {
                line = "";
                getline(transfer_info_file, line);
                if (first_file) {
                    if (line.empty()) {
                        cout << "Missing file to send path, please update transfer.info and try again" << endl;
                        return false;
                    }
                }
                else {
                    if (line.empty()) {
                        cout << "number of files to send in transfer.info is: " << num_of_files << endl;
                        transfer_info_file.close();
                        this->num_of_files = num_of_files;
                        return true;
                    }
                }
                bool valid_path = validator.fileExistsInFolder(line);
                if (!valid_path) {
                    cout << "Invalid file path" << endl;
                    return false;
                }
                (this->client_files_path)[num_of_files] = line;
                num_of_files += 1;
                first_file = false;
            }
        }
        else {
            cout << "Unable to open transfer.info file" << endl;
            return false;
        }
        return true;
    }

    /**
     * @brief Sends public key to server
     */
    bool sendPublicKey(std::string& private_key, string publicKey) {
        cout << "Sending public key of client: " << client_name << std::endl;
        bool valid_1026 = this->network.req_1026(this->client_name, this->client_uuid, publicKey, private_key, this->client_aes_key);
        if (!valid_1026) {
            cout << "Failed with sending request 1026" << endl;
            return false;
        }
        return true;
    }

    /**
     * @brief Reconnects to server
     */
    int reconnect() {
        bool valid_connect = this->network.connect_to_server(this->server_port, this->server_ip);
        if (!valid_connect) {
            cout << "Failed with reconnection to server - server is off" << endl;
            exit(EXIT_FAILURE);
        }
        char uuid[17];
        uuid[16] = 0;
        strncpy_s(uuid, 17, (this->client_uuid).c_str(), UUID_LEN);
        int valid_req = this->network.req_1027(this->client_name, uuid, this->client_private_key, this->client_aes_key);
        if (!valid_req) {
            cout << "Failed with sending request 1027" << endl;
            exit(EXIT_FAILURE);
        }
        if (valid_req == 1605) {
            cout << "Reconnect to server success" << endl;
            return 1605;
        }
        if (valid_req == 1606) {
            string uuid_str(uuid, UUID_LEN);
            std::cout << "client uuid is: " << this->bytesToHex(uuid, UUID_LEN) << std::endl;
            this->client_uuid = uuid_str;
            std::cout << "need to pass 1026 request with public key" << std::endl;
            return 1606;
        }
        return 0;
    }

    /**
     * @brief Sends files to server
     */
    bool sendFile() {
        bool valid_read_file = this->read_files_content();
        if (!valid_read_file) {
            cout << "Failed to read client file" << endl;
        }
        const unsigned char* aes_key = reinterpret_cast<const unsigned char*>((this->client_aes_key).c_str());
        AESWrapper aesWrapper(aes_key, AES_KEY_LEN);
        bool failed_to_send_all = false;
        int i_file = 0;
        while (!this->client_files.empty()) {
            string file_content = (this->client_files).front();
            (this->client_files).erase((this->client_files).begin());
            int orig_file_size = (this->client_files_size).front();
            (this->client_files_size).erase((this->client_files_size).begin());
            file_content[orig_file_size] = '\0';
            string encrypted_content = aesWrapper.encrypt(file_content.c_str(), orig_file_size);
            string file_name = fs::path(this->client_files_path[i_file]).filename().string();
            string crc = get_crc(this->client_files_path[i_file]);
            int valid_send_file = 1;
            bool first_time = true;
            bool failed_to_send = false;
            i_file += 1;
            while (valid_send_file <= 4) {
                int i = valid_send_file;
                if (!first_time) {
                    this->network.req_1030(this->client_uuid, file_name);
                }
                else {
                    first_time = false;
                }
                unsigned int server_crc;
                valid_send_file += this->network.req_1028(this->client_uuid, encrypted_content, orig_file_size, file_name, server_crc);
                if (i == valid_send_file) {
                    cout << "Failed to send file - " << file_name << endl;
                    failed_to_send = true;
                    break;
                }
                if (stoul(crc) == server_crc) {
                    cout << "crc recived in 1603 is valid and match - File sent successfully" << endl;
                    std::cout << "sending 1029 request - files recived in server successfuly" << endl;
                    bool valid_1029 = this->network.req_1029(this->client_uuid, file_name);
                    if (!valid_1029) {
                        cout << "Failed to send request 1029" << endl;
                        break;
                    }
                    break;
                }
                if (valid_send_file == 4) {
                    cout << "Failed to send file - crc incorrect for the 4 times - done" << endl;
                    cout << "Sending 1031 to server" << endl;
                    bool valid_1031 = this->network.req_1031(this->client_uuid, file_name);
                    if (!valid_1031) {
                        cout << "Failed to send request 1031" << endl;
                        failed_to_send = true;
                        break;
                    }
                    failed_to_send = true;
                    break;
                }
            }
            if (!failed_to_send) {
                continue;
            }
            cout << "Failed to send: " << file_name << " resume with sending next file if exists" << endl;
            failed_to_send_all = true;
        }
        return failed_to_send_all;
    }

    /**
     * @brief Ends connection with server
     */
    bool end_communication() {
        if (this->network.end_communication()) {
            return true;
        }
        return false;
    }

private:
    string client_name;                 ///< Name of the client
    int server_port;                    ///< Port of the server
    int num_of_files;                   ///< Number of files to transfer
    string server_ip;                   ///< IP address of the server
    string client_uuid;                 ///< UUID of the client
    string client_private_key;          ///< Private key of the client
    string client_aes_key;              ///< AES key used by the client
    string client_files_path[100];      ///< Path of the client's files
    vector<string> client_files;        ///< Vector to store file contents
    vector<int> client_files_size;      ///< Vector to store file sizes
    Network network;                    ///< Network object for communication

    /**
     * @brief Saves file in the executable directory
     */
    bool saveToFileInExecutableDirectory(string filename, string exec_path, string data) {
        std::filesystem::path exePath = std::filesystem::absolute(std::filesystem::path(exec_path));
        std::filesystem::path filePath = exePath.parent_path() / filename;
        std::ofstream outputFile(filePath);
        if (!outputFile) {
            std::cerr << "Error: Failed to open file for writing: " << filePath << std::endl;
            return false;
        }
        outputFile << data;
        outputFile.close();
        std::cout << "File " + filename + " saved successfully : " << endl;
        return true;
    }

    /**
     * @brief Reads file content and stores it
     */
    bool read_files_content() {
        int i = 0;
        while (i < this->num_of_files) {
            ifstream client_file((this->client_files_path)[i], ios::binary);
            if (!client_file.is_open()) {
                std::cerr << "Error opening file." << std::endl;
                return false;
            }
            std::vector<char> bytes(std::istreambuf_iterator<char>(client_file), {});
            client_file.close();
            string file_content(bytes.begin(), bytes.end());
            (this->client_files).push_back(file_content);
            int file_size = file_content.size();
            this->client_files_size.push_back(file_size);
            i += 1;
        }
        return true;
    }

    /**
     * @brief Converts bytes to hexadecimal string
     */
    std::string bytesToHex(const char* bytes, size_t length) {
        std::string result;
        result.reserve(length * 2);

        for (size_t i = 0; i < length; ++i) {
            result += "0123456789abcdef"[((unsigned char)bytes[i] >> 4) & 0xF];
            result += "0123456789abcdef"[(unsigned char)bytes[i] & 0xF];
        }

        return result;
    }

    /**
     * @brief Converts hexadecimal string to bytes
     */
    std::string hexToBytes(const std::string& hexString) {
        std::string result;
        result.reserve(hexString.length() / 2);

        for (size_t i = 0; i < hexString.length(); i += 2) {
            unsigned char byte = 0;
            byte = (hexString[i] <= '9' ? hexString[i] - '0' : (hexString[i] | 32) - 'a' + 10) << 4;
            byte |= (hexString[i + 1] <= '9' ? hexString[i + 1] - '0' : (hexString[i + 1] | 32) - 'a' + 10);
            result.push_back(byte);
        }

        return result;
    }
};

/**
 * @brief Prompts user for next request
 */
void ask_for_next_req(string req_num) {
    string req = "send a file";
    if (req_num == "1026") {
        req = "send public key";
    }

    cout << "Please enter request number " << req_num << " to " << req << " to server or -1 to exit program" << endl;
    string request;
    cin >> request;

    if (request != req_num) {
        while (request != req_num) {
            cout << "Please enter request number " << req_num << " to " << req << " to server or -1 to exit program" << endl;
            cin >> request;

            if (request == "-1") {
                exit(EXIT_FAILURE);
            }
        }
    }
}

/**
 * @brief Main entry point
 */
int main(int argc, char* argv[]) {
    Client client;
    InputValidator validator;
    string request = "";

    if (!validator.fileExistsInExeFolder("transfer.info", argv[0])) {
        cout << "transfer.info file does not exist" << endl;
        exit(EXIT_FAILURE);
    }

    cout << "reading trasnfer.info file" << endl;
    if (!client.read_transfer_info_file(argv[0], validator)) {
        cout << "Invalid transfer.info file" << endl;
        exit(EXIT_FAILURE);
    }

    bool me_info = validator.fileExistsInExeFolder("me.info", argv[0]);
    int reconnect_res = NEW_REGISTER;

    if (!me_info) {
        cout << "me.info file does not exist" << endl;
        cout << "Requesting registration with 1025 request" << endl;
        cout << "Taking client details from transfer.info file and registering client with server" << endl;
        
        int valid_register = client.registerClient();
        if (!valid_register) {
            cout << "server is offline, please wait to server to work and try again" << endl;
            exit(EXIT_FAILURE);
        }
        if(valid_register == -1) {
            exit(EXIT_FAILURE);
        }
    } else {
        cout << "me.info file exists" << endl;
        if (!client.read_me_info_file(argv[0], validator)) {
            cout << "Invalid me.info file" << endl;
            exit(EXIT_FAILURE);
        }
        cout << "Requesting log back to server with 1027 request" << endl;
        if (!validator.fileExistsInExeFolder("priv.key", argv[0])) {
            cout << "priv.key file does not exist" << endl;
            exit(EXIT_FAILURE);
        }
        if (!client.read_priv_key(argv[0], validator)) {
            cout << "Private key is not valid" << endl;
            exit(EXIT_FAILURE);
        }
        reconnect_res = client.reconnect();
    }

    if(reconnect_res == 1606 || reconnect_res == NEW_REGISTER) {
        request = "1026";
        ask_for_next_req(request);
        RSAPrivateWrapper privateKeyWrapper;
        std::string privateKey = privateKeyWrapper.getPrivateKey();
        std::string publicKey = privateKeyWrapper.getPublicKey();
        if (!client.save_priv_key(argv[0], privateKey)) {
            return false;
        }
        if (!client.save_me_info(argv[0], privateKey)) {
            return false;
        } 
        bool valid_send = client.sendPublicKey(privateKey, publicKey);
        if (!valid_send) {
            client.end_communication();
            exit(EXIT_FAILURE);
        }
    }

    request = "1028";
    ask_for_next_req(request);
    bool send_file = validator.fileExistsInExeFolder("priv.key", argv[0]);
    if (!send_file) {
        cout << "priv.key file does not exist" << endl;
        client.end_communication();
        exit(EXIT_FAILURE);
    }

    bool failed_to_transfer = client.sendFile();
    if (failed_to_transfer) {
        cout << "Failed to send files" << endl;
        client.end_communication();
        exit(EXIT_FAILURE);
    }
    cout << "All files sent successfully" << endl;

    bool end_comm = client.end_communication();
    if (!end_comm) {
        cout << "Failed to end communication" << endl;
        exit(EXIT_FAILURE);
    }
    cout << "Communication ended successfully" << endl;
    exit(EXIT_SUCCESS);
    return 0;
}
