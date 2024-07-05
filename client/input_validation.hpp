#ifndef INPUT_VALIDATION_HPP
#define INPUT_VALIDATION_HPP

#include <vector>
#include <string>
#include <iostream>
#include <filesystem>
namespace fs = std::filesystem;

class InputValidator {
private:




public:
    InputValidator();
    bool fileExistsInFolder(std::string filename);
    bool isValidName(const std::string& name);
    bool isValidUUID(const std::string& uuid);
    bool isValidPrivateKey(const std::string& input);
    bool isValidIPv4(const std::string& ip);
    bool fileExistsInExeFolder(std::string filename, std::string executable_path);
    bool isValidPort(const std::string& port);
};

#endif  // INPUT_VALIDATION_HPP