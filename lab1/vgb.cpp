#include "vgb.h"
#include "vars.h"
#include <iostream>
#include <fstream>
#include <sstream>

using namespace std;

// Функция замены/очистки спецсимволов, чтобы текст оставался читаемым (4.1.1)[cite: 53]
string VGB_exclud(const string &text) {
    string res = text;
    for (size_t i = 0; i < res.size(); i++) {
        // Если символ непечатаемый (меньше ' ' или больше '~'), заменяем его на безопасный '?'
        if (res[i] < 32 || res[i] > 126) {
            res[i] = '?';
        }
    }
    return res;
}

// Генерация псевдослучайного seed (4.1.2)[cite: 54]
unsigned long long VGB_random(long long seed, size_t length) {
    unsigned long long hash = 14695981039346656037ULL; // FNV-1a offset basis
    hash ^= seed;
    hash *= 1099511628211ULL;
    hash ^= length;
    return hash;
}

// Битовое шифрование Виженера (4.1.1)[cite: 53]
// op_type может быть '^' (XOR), '&' (AND), '|' (OR)
string VGB_encrypt(const string &msg, const string &key, char op_type) {
    string res = msg;
    size_t key_len = key.size();
    if (key_len == 0) return res;

    for (size_t i = 0; i < msg.size(); i++) {
        char k = key[i % key_len];
        char m = msg[i];
        
        if (op_type == '^') res[i] = m ^ k;
        else if (op_type == '&') res[i] = m & k;
        else if (op_type == '|') res[i] = m | k;
        else res[i] = m ^ k; // по умолчанию XOR
    }

    return VGB_exclud(res);
}

// Битовое расшифрование Виженера
string VGB_decrypt(const string &msg, const string &key, char op_type) {
    // Для XOR расшифрование зеркально шифрованию. Для AND/OR требуется таблица обратимости,
    // но в рамках учебного кейса используем симметричную логику или XOR.
    return VGB_encrypt(msg, key, op_type);
}

// Шифрование содержимого файла (4.1.3)[cite: 54]
bool VGB_encrypt_file(const string &filename, const string &key, char op_type) {
    ifstream infile(filename);
    if (!infile.is_open()) return false;

    stringstream buffer;
    buffer << infile.rdbuf();
    infile.close();

    string content = buffer.str();
    string encrypted = VGB_encrypt(content, key, op_type);

    ofstream outfile(filename);
    if (!outfile.is_open()) return false;
    outfile << encrypted;
    outfile.close();

    return true;
}

// Расшифрование содержимого файла (4.1.3)[cite: 54]
bool VGB_decrypt_file(const string &filename, const string &key, char op_type) {
    // Аналогично вызову шифрования для симметричных операций
    return VGB_encrypt_file(filename, key, op_type);
}