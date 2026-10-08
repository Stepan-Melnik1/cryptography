#pragma once
#include <string>

// CSR
std::string CSR_encrypt(const std::string &msg, int key);
std::string CSR_decrypt(const std::string &msg, int key);

// CSK
std::string CSK_keygen(std::string word);
std::string CSK_encrypt(const std::string &msg, const std::string &word);
std::string CSK_decrypt(const std::string &msg, const std::string &word);

// VGN
std::string VGN_encrypt(const std::string &msg, const std::string &key);
std::string VGN_decrypt(const std::string &msg, const std::string &key);