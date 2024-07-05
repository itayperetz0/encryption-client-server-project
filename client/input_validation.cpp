#include "input_validation.hpp"
#include <regex>
#include <filesystem>
namespace fs = std::filesystem;

// Constructor
InputValidator::InputValidator()
{
}

// Validate IPv4 address
bool InputValidator::isValidIPv4(const std::string& ip)
{
    // Regular expression for IPv4 address
    std::regex pattern("^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$");

    // Match the input string against the regular expression
    return std::regex_match(ip, pattern);
}

// Check if a file exists in the folder where the executable resides
bool InputValidator::fileExistsInExeFolder(std::string filename, std::string executable_path)
{
    // Get the path to the executable
    fs::path exe_path = fs::canonical(fs::path(executable_path)).remove_filename();

    fs::path file_path = exe_path / filename;

    // Check if the file exists
    return fs::exists(file_path);
}

// Validate client name
bool InputValidator::isValidName(const std::string& name)
{
    if (name.size() >= 100)
    {
        std::cerr << "Client name must be less than 255 characters" << std::endl;
        return false;
    }
    if (name.size() < 1) {
        std::cerr << "Client name must not be empty" << std::endl; // Fixed typo
    }
    return true;
}

// Check if a file exists in any folder
bool InputValidator::fileExistsInFolder(std::string filename)
{
    // Check if the file exists
    return fs::exists(filename);
}

// Validate private key (base64 encoded)
bool InputValidator::isValidPrivateKey(const std::string& input) {

    // Regular expression to match base64 encoded string
    static const std::regex base64_regex("^[A-Za-z0-9+/]+(={0,2})?");
    return std::regex_match(input, base64_regex);
}

// Validate UUID format
bool InputValidator::isValidUUID(const std::string& uuid) {
    std::string uuid_start = uuid.substr(0, 32);
    // Regular expression for UUID format (version 1, 2, 3, 4, or 5) with an optional '=' or '==' at the end
    std::regex pattern("[0-9a-f]{32}(={0,2})?");
    return std::regex_match(uuid_start, pattern);
}

// Validate port number
bool InputValidator::isValidPort(const std::string& port)
{
    try
    {
        // Convert string to integer
        int intValue = std::stoi(port);
        if (intValue < 0 || intValue > 65535)
        {
            std::cerr << "Port number out of range" << std::endl;
            return false;
        }
        return true;
    }
    catch (const std::invalid_argument& e)
    {
        std::cerr << "Invalid port number: " << e.what() << std::endl;
        return false;
    }
    catch (const std::out_of_range& e)
    {
        std::cerr << "Invalid port number: " << e.what() << std::endl;
        return false;
    }
}
