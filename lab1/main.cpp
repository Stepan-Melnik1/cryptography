#include <iostream>
#include <string>
using namespace std;

// Наш алфавит и его длина
const string letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const int LEN = letters.size();

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
    string key = "";                   // Сюда будем собирать чистый алфавит
    string combined = word + letters;  // Склеиваем слово и обычный алфавит

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

// Функция расшифрования Цезаря с кодовым словом
string CSK_encrypt(const string &msg, const string &word) {
    string key = CSK_keygen(word);
    string res = msg;

    for(int i = 0; i < (int)msg.size(); i++) {
        for(int j = 0; j < LEN; j++) {
            if(msg[i] == letters[j]) {
                // Нашли букву в стандартном алфавите -> берём из смешанного (key)
                res[i] = key[j];
                break;
            }
        }
    }
    return res; 
}

string CSK_decrypt(const string &msg, const string &word) {
    string key = CSK_keygen(word);
    string res = msg;

    for(int i = 0; i < (int)msg.size(); i++) {
        for(int j = 0; j < LEN; j++) {
            if(msg[i] == key[j]) {    // Ищем защифрованную букву в смешанном алфавите
                res[i] = letters[j];  // Возвращаем ей нормальную букву
                break;
            }
        }
    }
    return res;
}


int main(int argc, char *argv[]) {
    // Запоминаем имя программы, чтобы красиво выводить ошибки
    string app = argv[0];  

    // Если пользователь ввёл только название программы (1 аргумент)
    if(argc == 1) {
        cout << app << ": no option and message" << endl;
        return 3;
    }

    // Если пользователь забыл либо флаг, либо текст (ввел всего 2 аргумент)
    if(argc == 2) {
        // Если первое слово начинается на дефис, 
        if(argv[1][0] == '-') {
            cout << app << ": no message" << endl;
        } else {
            cout << app << ": no option" << endl;
        }

        return 2;
    }

    // Проверяем, что пользователь не передал лишние аргументы.
    if(argc > 4) {
        cout << app << ": to many strings" << endl;
        return 4;
    }
    
    // Опция и сообщение
    string opt = argv[1];
    string msg = argv[2];

    
    // Ключи по умолчанию (как в методичке)
    int num_key = 7;             // Для обычного Цезаря
    string text_key = "MEETING"; // Для Цезаря с кодовым словом

    // Если пользователь передал свой ключ (4-й аргумент)
    if(argc == 4) {
        text_key = argv[3];  // Запоминаем как текст

        // Переводим кодовое слово в заглавные буквы (защита от дурака)
        for(char &ch : text_key) {
            if(ch >= 'a' && ch <= 'z') ch = char(ch - 'a' + 'A');
        }
    }

    // Подготовка текста: переводим все буквы в заглавные 
    for (char &ch : msg) {
        if(ch >= 'a' && ch <= 'z') {
            ch = char(ch - 'a' + 'A');  // Пример: 97 - 97 + 65 = 65
        }
    }

    // Выбираем что делать в зависимости от флага
    if(opt == "-Ecsr") {
        if(argc == 4) num_key = stoi(argv[3]);
        cout << "Зашифровано: " << CSR_encrypt(msg, num_key) << endl;
    } 
    else if (opt == "-Dcsr") {
        if(argc == 4) num_key = stoi(argv[3]);
        cout << "Расшифровано: " << CSR_decrypt(msg, num_key) << endl;
    } 
    else if(opt == "-Ecsk") {
        cout << "key: " << text_key << endl;
        cout << "enc: " << CSK_encrypt(msg, text_key) << endl;
    } else if(opt == "-Dcsk") {
        cout << "key: " << text_key << endl;
        cout << "dec: " << CSK_decrypt(msg, text_key) << endl;
    }
    else {
        cout << app << ": illegal option: " << opt << endl;
        return 1;
    }

    return 0;
}

