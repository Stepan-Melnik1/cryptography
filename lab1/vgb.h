#pragma once
#include <string>

// Прототипы функций для битового Виженера и работы с файлами
std::string VGB_encrypt(const std::string &msg, const std::string &key, char op_type);
std::string VGB_decrypt(const std::string &msg, const std::string &key, char op_type);
std::string VGB_exclud(const std::string &text);
unsigned long long VGB_random(long long seed, size_t length);

// Функции для работы с файлами
bool VGB_encrypt_file(const std::string &filename, const std::string &key, char op_type);
bool VGB_decrypt_file(const std::string &filename, const std::string &key, char op_type);