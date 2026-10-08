#include <iostream>
#include <string>
#include "ciphers.h" // Подключаем меню с функциями
using namespace std;

// g++ main.cpp ciphers.cpp vars.cpp -o crypto && ./crypto -Evgn "Hello World 2026!" "Secret_Key"
// ===== Точка входа =====
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
        cout << app << ": too many strings" << endl;
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

    }

    // Выбираем что делать в зависимости от флага
    if(opt == "-Ecsr") {
        if(argc == 4) num_key = stoi(argv[3]);
        cout << "Зашифровано: " << CSR_encrypt(msg, num_key) << endl;
    } else if (opt == "-Dcsr") {
        if(argc == 4) num_key = stoi(argv[3]);
        cout << "Расшифровано: " << CSR_decrypt(msg, num_key) << endl;
    } else if(opt == "-Ecsk") {
        cout << "key: " << text_key << endl;
        cout << "enc: " << CSK_encrypt(msg, text_key) << endl;
    } else if(opt == "-Dcsk") {
        cout << "key: " << text_key << endl;
        cout << "dec: " << CSK_decrypt(msg, text_key) << endl;
    } else if(opt == "-Evgn") {
        cout << "key: " << text_key << endl;
        cout << "enc: " << VGN_encrypt(msg, text_key) << endl;
    } else if (opt == "-Dvgn") {
        cout << "key: " << text_key << endl;
        cout << "dec: " << VGN_decrypt(msg, text_key) << endl;
    } else {
        cout << app << ": illegal option: " << opt << endl;
        return 1;
    }

    return 0;
}
