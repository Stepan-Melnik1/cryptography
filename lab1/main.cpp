#include <iostream>
#include <string>
#include "ciphers.h" // Подключаем меню с функциями
#include "galois.h"
#include "expmod.h"
#include "invmod.h"
#include "logdis.h"
#include "vgb.h"
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
    } else if(opt == "-gf") {
        unsigned char a = 0x57; // Значение по умолчанию из примера 3.1.4
        unsigned char b = 0x83; // Значение по умолчанию из примера 3.1.4

        // Если пользователь передал свои шестнадцатеричные числа в аргументах (argv[2] и argv[3])
        if(argc == 4) {
            a = (unsigned char)stoul(argv[2], nullptr, 16);
            b = (unsigned char)stoul(argv[3], nullptr, 16);
            cout << "Using custom input values from arguments." << endl;
        } else {
            cout << "Using standard reference example from 3.1.4 (FIPS-197):" << endl;
        }

        unsigned char res_peasant = gf_mult_peasant(a, b);
    
        precompute_tables();
        unsigned char res_table = gf_mult_table(a, b);

        cout << "Galois Field GF(2^8) Multiplication Test:" << endl;
        cout << "  Peasant Mult (0x" << hex << uppercase << (int)a << " * 0x" << (int)b << ") = 0x" << (int)res_peasant;
        if (a == 0x57 && b == 0x83 && res_peasant == 0xC1) {
            cout << " [CORRECT - matches 0xC1]" << endl;
        } else {
            cout << endl;
        }
        cout << "  Table Mult   (0x" << (int)a << " * 0x" << (int)b << ") = 0x" << (int)res_table << endl;

    } else if(opt == "-ME") {
        if(argc < 6) {
            cout << app << ": usage: ./crypto -ME <method> <a> <k> <n>" << endl;
            cout << "Methods: rlbe, lrbe, ml, swe" << endl;
            return 2;
        }
        string method = argv[2];
        long long a = stoll(argv[3]);
        long long k = stoll(argv[4]);
        long long n = stoll(argv[5]);
        long long res = 0;

        if(method == "rlbe") res = mod_pow_rtl(a, k, n);
        else if(method == "lrbe") res = mod_pow_ltr(a, k, n);
        else if(method == "ml") res = montgomery_ladder(a, k, n);
        else if(method == "swe") res = sliding_window_pow(a, k, n, 3);
        else {
            cout << app << ": unknown expmod method: " << method << endl;
            return 1;
        }
        cout << "Result: " << res << endl;

    } else if(opt == "-MI") {

        if(argc < 5) {
            cout << app << ": usage: ./crypto -MI <method> <b> <n>" << endl;
            cout << "Methods: eea, ferma, gcd" << endl;
            return 2;
        }

        string method = argv[2];
        int b = stoi(argv[3]);
        int n = stoi(argv[4]);
        int res = -1;

        if(method == "eea") res = mod_inverse_eea(b, n);
        else if(method == "ferma") res = mod_inverse_fermat(b, n);
        else if(method == "gcd") res = mod_inverse_binary_gcd(b, n);
        else {
            cout << app << ": unknown invmod method: " << method << endl;
            return 1;
        }

        if(res == -1) {
            cout << "The modular inverse of b modulo n does not exist." << endl;
        } else {
            cout << "Result: " << res << endl;
        }
    } else if(opt == "-DL") {

        if(argc < 6) {
            cout << app << ": usage: ./crypto -DL <method> <g> <h> <p>" << endl;
            cout << "Methods: br, bsgs, pollard, ph, ic" << endl;
            return 2;
        }

        string method = argv[2];
        int g = stoi(argv[3]);
        int h = stoi(argv[4]);
        int p = stoi(argv[5]);
        int res = -1;

        if(method == "br") res = brute_force_dlog(g, h, p, 32000);
        else if(method == "bsgs") res = bsgs_dlog(g, h, p);
        else if(method == "pollard") res = pollard_rho_dlog(g, h, p, p - 1);
        else if(method == "ph") res = pohlig_hellman_dlog(g, h, p, p - 1);
        else if(method == "ic") res = index_calculus_dlog(g, h, p);
        else {
            cout << app << ": unknown logdis method: " << method << endl;
            return 1;
        }

        if(res == -1) {
            cout << "No solution found." << endl;
        } else {
            cout << "Result: " << res << endl;
        }

    } else if(opt == "-Evgb") {

        if(argc < 4) {
            cout << app << ": usage: ./crypto -Evgb <message> <key>" << endl;
            return 2;
        }
        string message = argv[2];
        string key = argv[3];
        cout << "Encrypted (XOR): " << VGB_encrypt(message, key, '^') << endl;

    } else if(opt == "-Fvgb") {

        if(argc < 4) {
            cout << app << ": usage: ./crypto -Fvgb <filename> <key>" << endl;
            return 2;
        }
        string filename = argv[2];
        string key = argv[3];
        if(VGB_encrypt_file(filename, key, '^')) {
            cout << "File " << filename << " successfully encrypted/processed." << endl;
        } else {
            cout << "Error opening file: " << filename << endl;
        }
        
    } else {
        cout << app << ": illegal option: " << opt << endl;
        return 1;
    }

    return 0;
}
