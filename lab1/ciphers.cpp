#include "ciphers.h"
#include "vars.h"
using namespace std;

// ===== ФУНКЦИИ ШИФРОВАНИЯ =====
// Функция шифрования Цезаря
string CSR_encrypt(const string &msg, int key) {
    string res = msg;  
    // Приводим ключ к сдвигу в пределах алфавита.
    int shift = (key % LEN + LEN) % LEN;

    for(int i = 0; i < (int)msg.size(); i++) {
        for(int j = 0; j < LEN; j++) {
            if(msg[i] == letters[j]) {
                res[i] = letters[(j + shift) % LEN];
                break;
            }
        }
    }
    return res;
}

// Функция расшифровки Цезаря
string CSR_decrypt(const string &msg, int key) {
    string res = msg;
    // Используем тот же диапазон ключа, чтобы корректно расшифровать текст.
    int shift = (key % LEN + LEN) % LEN;

    for(int i = 0; i < (int)msg.size(); i++) {
        for(int j = 0; j < LEN; j++) {
            if(msg[i] == letters[j]) {
                res[i] = letters[(j - shift + LEN) % LEN];
                break;
            }
        }
    }
    return res;
}

// Генерация смешанного алфавита из кодового слова
string CSK_keygen(string word) {
    string key = "";                    // Сюда будем собирать чистый алфавит
    string combined = word + letters2;  // Склеиваем слово и обычный алфавит

    // Проходим по каждой букве склееной строки
    for(char c : combined) {
        // Метод .find() ищет букву 'c' внутри строки 'key' 
        // string::npos означает "не найдено"
        if (key.find(c) == string::npos) {
            key += c;
        }
    }
    return key;
}

// Функция шифрования Цезаря с кодовым словом
string CSK_encrypt(const string &msg, const string &word) {
    string key = CSK_keygen(word);
    string res = msg;

    for(int i = 0; i < (int)msg.size(); i++) {
        for(int j = 0; j < LEN2; j++) {
            if(msg[i] == letters2[j]) {
                // Нашли букву в стандартном алфавите -> берём из смешанного (key)
                res[i] = key[j];
                break;
            }
        }
    }
    return res; 
}

// Функция расшифрования Цезаря с кодовым словом
string CSK_decrypt(const string &msg, const string &word) {
    string key = CSK_keygen(word);
    string res = msg;

    for(int i = 0; i < (int)msg.size(); i++) {
        for(int j = 0; j < LEN2; j++) {
            if(msg[i] == key[j]) {    // Ищем защифрованную букву в смешанном алфавите
                res[i] = letters2[j];  // Возвращаем ей нормальную букву
                break;
            }
        }
    }
    return res;
}

// Шифрование Виженера
string VGN_encrypt(const string &msg, const string &key) {
    string res = msg;
    int key_len = key.size();

    for(int i = 0; i < (int)msg.size(); i++) {

        int msg_idx = letters3.find(msg[i]);      // Находим индекс буквы сообщения в алфавите
        if(msg_idx == (int)string::npos) continue; // Защита

        // Находим индекс буквы ключа в алфавите
        int key_idx = letters3.find(key[i % key_len]);
        if(key_idx == (int)string::npos) key_idx = 0;

        // Сдвигаем букву сообщения на позицию буквы ключа в алфавите
        res[i] = letters3[(msg_idx + key_idx) % LEN3];
    }

    return res;
}

// Расшифрование Виженера
string VGN_decrypt(const string &msg, const string &key) {
    string res = msg;
    int key_len = key.size();

    for(int i = 0; i < (int)msg.size(); i++) {

        int msg_idx = letters3.find(msg[i]);
        if(msg_idx == (int)string::npos) continue;
        
        int key_idx = letters3.find(key[i % key_len]);
        if(key_idx == (int)string::npos) key_idx = 0;

        res[i] = letters3[(msg_idx - key_idx + LEN3) % LEN3];
    }

    return res;
}


