#include <iostream>
#include <string>
#include <fstream>
#include <filesystem>

#include "input_validation.hpp"
#include "network.hpp"
#include "RSAWrapper.h"
#include "Base64Wrapper.h"
#include "AESWrapper.h"

#define NEW_REGISTER 1
#define NUM_KEY_LINES 12
#define AES_KEY_LEN 32
using namespace std;

namespace fs = std::filesystem;
string get_crc(std::string fname);

class Client
{

public:

    /**
 * Initializes a client object with default values.
 */
    Client() : client_name(""), server_port(0), network() {}

    /**
     * Registers the client with the server.
     * @return True if registration is successful, false otherwise.
     */
    int registerClient() {
        bool valid_connect = this->network.connect_to_server(this->server_port, this->server_ip);
        if (!valid_connect) {
            return 0;//as connection failure
        }
        char uuid[16];
        bool valid_req = this->network.req_1025(this->client_name, uuid);
        if (!valid_req) {
            return -1;//as registration failure
        }
        (this->client_uuid).assign(uuid);
        cout << "Client registered in server with user name: " << this->client_name << std::endl;
        string hexa_uuid = bytesToHex(uuid, UUID_LEN);
        cout << "Client registered in server and got UUID: " << hexa_uuid << std::endl;
        return 1;//as success
    }

    /**
     * Saves the private key to a file in the executable directory.
     * @param argv The argument vector from the command line.
     * @param privateKey The private key to save.
     * @return True if the private key is successfully saved, false otherwise.
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
     * Saves client information (name, UUID, private key) to a file in the executable directory.
     * @param argv The argument vector from the command line.
     * @param privateKey The private key to save.
     * @return True if the client information is successfully saved, false otherwise.
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
     * Reads client information from the "me.info" file.
     * @param executable_path The path of the executable.
     * @param validator An instance of InputValidator for validating input.
     * @return True if client information is successfully read, false otherwise.
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
     * Reads the private key from the "priv.key" file.
     * @param executable_path The path of the executable.
     * @param validator An instance of InputValidator for validating input.
     * @return True if the private key is successfully read, false otherwise.
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
 * Reads transfer information from the "transfer.info" file.
 * @param executable_path The path of the executable.
 * @param validator An instance of InputValidator for validating input.
 * @return True if the transfer information is successfully read, false otherwise.
 */
    bool read_transfer_info_file(char* executable_path, InputValidator validator)
    {
        fs::path exe_path = fs::canonical(fs::path(executable_path)).remove_filename();
        // get me.info file
        fs::path transfer_info_path = exe_path / "transfer.info";
        ifstream transfer_info_file(transfer_info_path);
        if (transfer_info_file.is_open())
        {
            string line;
            getline(transfer_info_file, line);
            size_t pos = line.find_first_of(":");
            if (pos == std::string::npos)
            {
                cout << "Invalid format of transfer.info file- missing port number in first line" << endl;
                return false;
            }

            bool valid_ip = validator.isValidIPv4(line.substr(0, pos));
            if (!valid_ip)
            {
                std::cout << "Invalid IPv4 address" << std::endl;
                return false;
            }
            std::cout << "Valid IPv4 address" << std::endl;
            this->server_ip = line.substr(0, pos);

            bool valid_port = validator.isValidPort(line.substr(pos + 2));
            if (!valid_port)
            {
                std::cout << "Invalid port number" << std::endl;
                return false;
            }
            std::cout << "Valid port number" << std::endl;
            this->server_port = stoi(line.substr(pos + 1));

            getline(transfer_info_file, line);
            bool valid_name = validator.isValidName(line);
            if (!valid_name)
            {
                cout << "Invalid client name" << endl;
                return false;
            }
            this->client_name = line;
            bool first_file = true;
            int num_of_files = 0;
            while (num_of_files <100) {
                line = "";
                getline(transfer_info_file, line);
                if (first_file) {
                    if (line.empty())
                    {
                        cout << "Missing file to send path, please update transfer.info and try again" << endl;
                        return false;
                    }
                }
                else {
                    if (line.empty())
                    {
                        cout << "number of files to send in transfer.info is: " << num_of_files << endl;
                        transfer_info_file.close();
                        this->num_of_files = num_of_files;
              
                        return true;
                    }
                }
                bool valid_path = validator.fileExistsInFolder(line);
                if (!valid_path)
                {
                    cout << "Invalid file path" << endl;
                    return false;
                }
                (this->client_files_path)[num_of_files] = line;
                num_of_files += 1;
                first_file = false;

            }
            
        }
        else
        {
            cout << "Unable to open transfer.info file" << endl;
            return false;
        }
    }

    /**
     * Sends the public key of the client to the server.
     * @param private_key The private key of the client.
     * @param publicKey The public key to send.
     */
    bool sendPublicKey(std::string& private_key, string publicKey) {
        cout << "Sending public key of client: " << client_name << std::endl;
        bool valid_1026 = this->network.req_1026(this->client_name, this->client_uuid, publicKey, private_key, this->client_aes_key);//aes_key sent to be saved inside func
        if (!valid_1026) {
            cout << "Failed with sending request 1026" << endl;
            return false;
        }
        return true;
        
    }

    /**
     * Reconnects to the server.
     * @return The status code of the reconnection attempt.
     */
    int reconnect() {
        bool valid_connect = this->network.connect_to_server(this->server_port, this->server_ip);
        if (!valid_connect) {
            cout << "Failed with reconnection to server - server is off" << endl;
            exit(EXIT_FAILURE);
        }
        char uuid[17];
        uuid[16] = 0;
        strncpy_s(uuid,17,(this->client_uuid).c_str(), UUID_LEN);
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
            string uuid_str(uuid,UUID_LEN);
            std::cout << "client uuid is: " << this->bytesToHex(uuid,UUID_LEN) << std::endl;
            this->client_uuid = uuid_str;
            std::cout << "need to pass 1026 request with public key" << std::endl;
           
            return 1606;
        }
        return 0;//got unexpected response
    }

    /**
     * Sends files to the server.
     * @return True if all files are sent successfully, false otherwise.
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
            cout << "Failed to send: " << file_name << " resume with sending next file if exists" <<endl;
            failed_to_send_all = true;
        }
        return failed_to_send_all;
    }

    /**
     * Ends communication with the server.
     * @return True if communication is successfully ended, false otherwise.
     */
    bool end_communication() {
        if (this->network.end_communication()) {
            return true;
        }
        return false;
    }

    
    

private:
    // Client attributes
    string client_name;                 // Name of the client
    int server_port;                    // Port of the server
    int num_of_files;
    string server_ip;                   // IP address of the server
    string client_uuid;                 // UUID of the client
    string client_private_key;          // Private key of the client
    string client_aes_key;              // AES key used by the client
    string client_files_path[100];            // Path of the client's file
    vector<string> client_files;        // Vector to store file contents
    vector<int> client_files_size;      // Vector to store file sizes
    Network network;                    // Network object for communication


    /**
 * Saves data to a file in the directory of the executable.
 * @param filename The name of the file to save.
 * @param exec_path The path of the executable.
 * @param data The data to write to the file.
 * @return True if the file is successfully saved, false otherwise.
 */
    bool saveToFileInExecutableDirectory(string filename, string exec_path, string data) {
        // Get the absolute path of the executable
        std::filesystem::path exePath = std::filesystem::absolute(std::filesystem::path(exec_path));
        // Create the file path by appending the filename to the parent directory of the executable
        std::filesystem::path filePath = exePath.parent_path() / filename;
        // Open the file for writing
        std::ofstream outputFile(filePath);
        // Check if the file is opened successfully
        if (!outputFile) {
            std::cerr << "Error: Failed to open file for writing: " << filePath << std::endl;
            return false;
        }
        // Write data to the file
        outputFile << data;
        // Close the file
        outputFile.close();

        std::cout << "File " + filename + " saved successfully : " << endl;
        return true;
    }

    /**
     * Reads the content of a file and stores it.
     * @return True if the file content is successfully read, false otherwise.
     */
    bool read_files_content() {
        int i = 0;
        while (i < this->num_of_files) {
            // Open the file for reading in binary mode
            ifstream client_file((this->client_files_path)[i], ios::binary);
            // Check if the file is opened successfully
            if (!client_file.is_open()) {
                std::cerr << "Error opening file." << std::endl;
                return false;
            }
            // Read the content of the file into a vector of characters
            std::vector<char> bytes(std::istreambuf_iterator<char>(client_file), {});
            // Close the file
            client_file.close();
            // Convert the vector of characters to a string
            string file_content(bytes.begin(), bytes.end());
            // Store the file content
            (this->client_files).push_back(file_content);
            // Store the size of the file
            int file_size = file_content.size();
            this->client_files_size.push_back(file_size);
            i += 1;
        }
        return true;
        
    }

    /**
     * Converts a byte array to its hexadecimal representation.
     * @param bytes The byte array to convert.
     * @param length The length of the byte array.
     * @return The hexadecimal representation of the byte array.
     */
    std::string bytesToHex(const char* bytes, size_t length) {
        std::string result;
        result.reserve(length * 2); // Each byte is represented by two hexadecimal characters

        for (size_t i = 0; i < length; ++i) {
            // Convert each byte to its hexadecimal representation
            result += "0123456789abcdef"[((unsigned char)bytes[i] >> 4) & 0xF];
            result += "0123456789abcdef"[(unsigned char)bytes[i] & 0xF];
        }

        return result;
    }

    std::string hexToBytes(const std::string& hexString) {
        std::string result;
        result.reserve(hexString.length() / 2);

        for (size_t i = 0; i < hexString.length(); i += 2) {
            unsigned char byte = 0;
            // Convert two hexadecimal characters to a byte
            byte = (hexString[i] <= '9' ? hexString[i] - '0' : (hexString[i] | 32) - 'a' + 10) << 4;
            byte |= (hexString[i + 1] <= '9' ? hexString[i + 1] - '0' : (hexString[i + 1] | 32) - 'a' + 10);
            result.push_back(byte);
        }

        return result;
    }

};


// Function to prompt the user for the next request
void ask_for_next_req(string req_num) {
    // Determine the request description based on the request number
    string req = "send a file";
    if (req_num == "1026") {
        req = "send public key";
    }

    // Prompt the user to enter the request number
    cout << "Please enter request number " << req_num << " to " << req << " to server or -1 to exit program" << endl;
    string request;
    cin >> request;

    // Continue prompting until the correct request number is entered or the user exits
    if (request != req_num)
    {
        while (request != req_num)
        {
            // Prompt again for the correct request number
            cout << "Please enter request number " << req_num << " to " << req <<" to server or -1 to exit program" << endl;
            cin >> request;

            // If the user chooses to exit, terminate the program
            if (request == "-1")
            {
                exit(EXIT_FAILURE);
            }
        }
    }
}


// Main function
int main(int argc, char* argv[])
{
    // Create a client instance and input validator
    Client client;
    InputValidator validator;
    string request = "";

    // Check if transfer.info file exists
    bool transfer_info = validator.fileExistsInExeFolder("transfer.info", argv[0]);
    if (!transfer_info)
    {
        cout << "transfer.info file does not exist" << endl;
        exit(EXIT_FAILURE);
    }

    // Read transfer information from file
    cout << "reading trasnfer.info file" << endl;
    bool valid_transfer_info = client.read_transfer_info_file(argv[0], validator);
    if (!valid_transfer_info)
    {
        cout << "Invalid transfer.info file" << endl;
        exit(EXIT_FAILURE);
    }

    bool me_info = validator.fileExistsInExeFolder("me.info", argv[0]);
    int reconnect_res = NEW_REGISTER;

    // Check if me.info file exists
    if (!me_info)
    {
        cout << "me.info file does not exist" << endl;
        cout << "Requesting registration with 1025 request" << endl;
        cout << "Taking client details from transfer.info file and registering client with server" << endl;
        // Register client with server
        int valid_register = client.registerClient();
        if (!valid_register) {
            cout << "server is offline, please wait to server to work and try again" << endl;
            exit(EXIT_FAILURE);
        }
        if(valid_register == -1){//as register failure
            exit(EXIT_FAILURE);
        }
        
    }
    else
    {
        cout << "me.info file exists" << endl;
        // Read client information from me.info file
        bool valid_me_info = client.read_me_info_file(argv[0], validator);
        if (!valid_me_info)
        {
            cout << "Invalid me.info file" << endl;
            exit(EXIT_FAILURE);
        }
        cout << "Requesting log back to server with 1027 request" << endl;
        bool priv_key = validator.fileExistsInExeFolder("priv.key", argv[0]);
        if(!priv_key)
        {
            cout << "priv.key file does not exist" << endl;
            exit(EXIT_FAILURE);
        }
        // Read private key from file
        bool valid_priv_key = client.read_priv_key(argv[0], validator);
        if (!valid_priv_key)
        {
            cout << "Private key is not valid" << endl;
            exit(EXIT_FAILURE);
        }

        // Attempt to reconnect to the server
        reconnect_res =  client.reconnect();
    }

    // If it's a new registration or reconnection failed, send public key
    if(reconnect_res == 1606 || reconnect_res == NEW_REGISTER)
    {
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
        bool valid_send = client.sendPublicKey(privateKey,publicKey);
        if (!valid_send) {
            client.end_communication();
            exit(EXIT_FAILURE);
        }
    }

    request = "1028";
    ask_for_next_req(request);
    bool send_file = validator.fileExistsInExeFolder("priv.key", argv[0]);
    if (!send_file)
    {
        cout << "priv.key file does not exist" << endl;
        client.end_communication();
        exit(EXIT_FAILURE);
    }

    // Send file to the server
    bool failed_to_transfer = client.sendFile();
    if (failed_to_transfer)
    {
        cout << "Failed to send files" << endl;
        client.end_communication();
        exit(EXIT_FAILURE);
    }
    cout << "All files sent successfully" << endl;

    // End communication with the server
    bool end_comm = client.end_communication();
    if (!end_comm)
    {
        cout << "Failed to end communication" << endl;
        exit(EXIT_FAILURE);
    }
    cout << "Communication ended successfully" << endl;
    exit(EXIT_SUCCESS);
    return 0;
}
