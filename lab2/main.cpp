#include "crypto.h"
#include <iomanip>
#include <exception>
#include <stdexcept>

// Преобразование числа в байтовый ключ
vector<uint8_t> createKey(uint64_t key) {
    vector<uint8_t> result;

    for (int i = 0; i < 8; i++) {
        result.push_back((key >> (i * 8)) & 255);
    }

    return result;
}

// Вывод зашифрованных данных в HEX
void printHex(const vector<uint8_t> &data) {
    for (uint8_t byte : data) {
        cout << uppercase << hex
             << setw(2) << setfill('0')
             << (int)byte;
    }

    cout << dec << endl;
}

// Преобразование HEX в массив байтов
vector<uint8_t> hexToBytes(const string &hex) {
    if (hex.empty() || hex.size() % 2 != 0) {
        throw invalid_argument("Invalid HEX string");
    }

    vector<uint8_t> result;

    for (size_t i = 0; i < hex.size(); i += 2) {
        size_t processed = 0;

        unsigned long byte = stoul(
            hex.substr(i, 2),
            &processed,
            16
        );

        if (processed != 2 || byte > 255) {
            throw invalid_argument("Invalid HEX byte");
        }

        result.push_back(byte);
    }

    return result;
}

// Проверка RC2 по официальным тестам RFC 2268
bool testRC2() {

    // Тест №1
    vector<uint8_t> key1(8, 0);

    string plaintext(8, '\0');

    vector<uint8_t> expected1 = {
        0xEB, 0xB7, 0x73, 0xF9,
        0x93, 0x27, 0x8E, 0xFF
    };

    vector<uint8_t> encrypted1 =
        RC2_encrypt(plaintext, key1, 63);

    if (encrypted1 != expected1) {
        return false;
    }

    string decrypted1 =
        RC2_decrypt(encrypted1, key1, plaintext.size(), 63);

    if (decrypted1 != plaintext) {
        return false;
    }


    // Тест №2
    vector<uint8_t> key2 = {0x88};

    vector<uint8_t> expected2 = {
        0x61, 0xA8, 0xA2, 0x44,
        0xAD, 0xAC, 0xCC, 0xF0
    };

    vector<uint8_t> encrypted2 =
        RC2_encrypt(plaintext, key2, 64);

    if (encrypted2 != expected2) {
        return false;
    }

    string decrypted2 =
        RC2_decrypt(encrypted2, key2, plaintext.size(), 64);

    if (decrypted2 != plaintext) {
        return false;
    }

    // Тест №3: сообщение длиннее одного блока
    string message = "HELLO WORLD!";
    
    vector<uint8_t> encrypted3 = RC2_encrypt(message, key2, 64);
    
    string decrypted3 = RC2_decrypt(encrypted3, key2, message.size(), 64);
    
    if (decrypted3 != message) {
        return false;
    }
    
    // Тест №4: пустое сообщение
    string emptyMessage;
    
    vector<uint8_t> encrypted4 = RC2_encrypt(emptyMessage, key2, 64);
    
    string decrypted4 = RC2_decrypt(encrypted4, key2, 0, 64);
    
    if (decrypted4 != emptyMessage) {
        return false;
    }
    
    // Тест №5: сообщение с нулями в конце
    string zeroMessage("ABC\0\0", 5);
    
    vector<uint8_t> encrypted5 = RC2_encrypt(zeroMessage, key2, 64);
    
    string decrypted5 = RC2_decrypt(encrypted5, key2, zeroMessage.size(), 64);
    
    if (decrypted5 != zeroMessage) {
        return false;
    }
    
    return true;
}

// Проверка ECDH по примеру из методички
bool testECDH() {

    int p = 17;
    int curveA = 2;
    int curveB = 2;
    int n = 19;

    ECPoint G = {5, 1, false};

    // Закрытые ключи из примера
    int a = 6;
    int b = 15;

    // Открытые ключи
    ECPoint A = pointMultiply(a, G, curveA, p);
    ECPoint B = pointMultiply(b, G, curveA, p);

    // Общие секретные точки
    ECPoint keyAlice = pointMultiply(
        a, B, curveA, p
    );

    ECPoint keyBob = pointMultiply(
        b, A, curveA, p
    );

    // Проверяем открытые ключи
    if (A.infinity || A.x != 16 || A.y != 13) {
        return false;
    }

    if (B.infinity || B.x != 3 || B.y != 16) {
        return false;
    }

    // Проверяем общий секрет
    if (keyAlice.infinity || keyBob.infinity) {
        return false;
    }

    if (keyAlice.x != 9 || keyAlice.y != 1) {
        return false;
    }

    if (keyAlice.x != keyBob.x ||
        keyAlice.y != keyBob.y) {
        return false;
    }

    // Проверяем порядок точки
    ECPoint check = pointMultiply(n, G, curveA, p);

    if (!check.infinity) {
        return false;
    }

    return true;
}

int main(int argc, char* argv[]) {
    try {
        // Проверяем RC2
        if (!testRC2()) {
            throw runtime_error("RC2 RFC 2268 test failed!");
        }

        if (!testECDH()) {
            throw runtime_error("ECDH test failed!");
        }
        cout << "ECDH test: PASSED\n";

        // Проверяем наличие команды
        if (argc < 2) {
            cout << "Usage:\n";
            cout << "./crypto -Edhrc2 MESSAGE\n";
            cout << "./crypto -Ddhrc2\n";
            cout << "./crypto -Eecdhrc2 MESSAGE\n";
            cout << "./crypto -Decdhrc2\n";
            return 1;
        }

        string mode = argv[1];

        // РЕЖИМ ШИФРОВАНИЯ
        if (mode == "-Edhrc2") {

            if (argc != 3) {
                throw invalid_argument("Message is missing");
            }

            // Получаем сообщение из аргументов
            string message = argv[2];

            // Генерируем общий ключ DH
            DHResult dh = DH_keygen();

            // Преобразуем ключ в байты
            vector<uint8_t> key = createKey(dh.key);

            // Шифруем сообщение
            vector<uint8_t> encrypted = RC2_encrypt(message, key);

            // Выводим результат
            cout << "enc: ";
            printHex(encrypted);

            cout << "key: " << dh.key << endl;
        } else if (mode == "-Eecdhrc2") {    // РЕЖИМ ШИФРОВАНИЯ ECDH
        
            if (argc != 3) {
                throw invalid_argument("Message is missing");
            }
        
            // Получаем сообщение
            string message = argv[2];
        
            // Переменные параметров кривой
            int p;
            int curveA;
            int curveB;
            int gx;
            int gy;
            int n;
        
            cout << "Enter p, curveA, curveB, Gx, Gy, n:\n";
        
            // Вводим параметры
            if (!(cin >> p >> curveA >> curveB >> gx >> gy >> n)) {
                throw invalid_argument("Invalid curve parameters");
            }
        
            // Создаём точку-генератор
            ECPoint G = {gx, gy, false};
        
            // Генерируем общий секрет ECDH
            ECDHResult ecdh = ECDH_keygen(
                p,
                curveA,
                curveB,
                G,
                n
            );
        
            // Преобразуем общую точку в одно число
            uint64_t ecdhKey =
                (uint64_t)ecdh.sharedKey.x * ecdh.p +
                ecdh.sharedKey.y;
        
            // Преобразуем число в байтовый ключ
            vector<uint8_t> key = createKey(ecdhKey);
        
            // Шифруем сообщение
            vector<uint8_t> encrypted =
                RC2_encrypt(message, key);
        
            // Выводим результат
            cout << "enc: ";
            printHex(encrypted);
        
            cout << "key: " << ecdhKey << endl;
        } else if (mode == "-Ddhrc2" || mode == "-Decdhrc2") {     // РЕЖИМ ДЕШИФРОВАНИЯ

            if (argc != 2) {
                throw invalid_argument("Unexpected arguments");
            }

            string encryptedHex;
            uint64_t sharedKey;

            // Получаем зашифрованное сообщение
            getline(cin, encryptedHex);

            // Получаем общий ключ
            cout << "key: ";
            cin >> sharedKey;

            // Преобразуем HEX обратно в байты
            vector<uint8_t> encrypted = hexToBytes(encryptedHex);

            // Восстанавливаем байтовый ключ
            vector<uint8_t> key = createKey(sharedKey);

            // Дешифруем сообщение
            // Передаём размер дополненного сообщения
            string decrypted = RC2_decrypt(
                encrypted,
                key,
                encrypted.size()
            );

            // Удаляем нули, добавленные padding()
            while (!decrypted.empty() && decrypted.back() == '\0') {
                decrypted.pop_back();
            }

            // Выводим исходное сообщение
            cout << "dec: " << decrypted << endl;
        }

        else {
            throw invalid_argument("Unknown command");
        }
    }
    catch (const exception &e) {
        cerr << "Error: " << e.what() << endl;
        return 1;
    }

    return 0;
}