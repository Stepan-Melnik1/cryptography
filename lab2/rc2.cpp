#include "crypto.h"
#include <stdexcept>

// Официальная таблица перестановок RC2 (RFC 2268)
static const uint8_t pitable[256] = {
    0xd9, 0x78, 0xf9, 0xc4, 0x19, 0xdd, 0xb5, 0xed,
    0x28, 0xe9, 0xfd, 0x79, 0x4a, 0xa0, 0xd8, 0x9d,
    0xc6, 0x7e, 0x37, 0x83, 0x2b, 0x76, 0x53, 0x8e,
    0x62, 0x4c, 0x64, 0x88, 0x44, 0x8b, 0xfb, 0xa2,
    0x17, 0x9a, 0x59, 0xf5, 0x87, 0xb3, 0x4f, 0x13,
    0x61, 0x45, 0x6d, 0x8d, 0x09, 0x81, 0x7d, 0x32,
    0xbd, 0x8f, 0x40, 0xeb, 0x86, 0xb7, 0x7b, 0x0b,
    0xf0, 0x95, 0x21, 0x22, 0x5c, 0x6b, 0x4e, 0x82,
    0x54, 0xd6, 0x65, 0x93, 0xce, 0x60, 0xb2, 0x1c,
    0x73, 0x56, 0xc0, 0x14, 0xa7, 0x8c, 0xf1, 0xdc,
    0x12, 0x75, 0xca, 0x1f, 0x3b, 0xbe, 0xe4, 0xd1,
    0x42, 0x3d, 0xd4, 0x30, 0xa3, 0x3c, 0xb6, 0x26,
    0x6f, 0xbf, 0x0e, 0xda, 0x46, 0x69, 0x07, 0x57,
    0x27, 0xf2, 0x1d, 0x9b, 0xbc, 0x94, 0x43, 0x03,
    0xf8, 0x11, 0xc7, 0xf6, 0x90, 0xef, 0x3e, 0xe7,
    0x06, 0xc3, 0xd5, 0x2f, 0xc8, 0x66, 0x1e, 0xd7,
    0x08, 0xe8, 0xea, 0xde, 0x80, 0x52, 0xee, 0xf7,
    0x84, 0xaa, 0x72, 0xac, 0x35, 0x4d, 0x6a, 0x2a,
    0x96, 0x1a, 0xd2, 0x71, 0x5a, 0x15, 0x49, 0x74,
    0x4b, 0x9f, 0xd0, 0x5e, 0x04, 0x18, 0xa4, 0xec,
    0xc2, 0xe0, 0x41, 0x6e, 0x0f, 0x51, 0xcb, 0xcc,
    0x24, 0x91, 0xaf, 0x50, 0xa1, 0xf4, 0x70, 0x39,
    0x99, 0x7c, 0x3a, 0x85, 0x23, 0xb8, 0xb4, 0x7a,
    0xfc, 0x02, 0x36, 0x5b, 0x25, 0x55, 0x97, 0x31,
    0x2d, 0x5d, 0xfa, 0x98, 0xe3, 0x8a, 0x92, 0xae,
    0x05, 0xdf, 0x29, 0x10, 0x67, 0x6c, 0xba, 0xc9,
    0xd3, 0x00, 0xe6, 0xcf, 0xe1, 0x9e, 0xa8, 0x2c,
    0x63, 0x16, 0x01, 0x3f, 0x58, 0xe2, 0x89, 0xa9,
    0x0d, 0x38, 0x34, 0x1b, 0xab, 0x33, 0xff, 0xb0,
    0xbb, 0x48, 0x0c, 0x5f, 0xb9, 0xb1, 0xcd, 0x2e,
    0xc5, 0xf3, 0xdb, 0x47, 0xe5, 0xa5, 0x9c, 0x77,
    0x0a, 0xa6, 0x20, 0x68, 0xfe, 0x7f, 0xc1, 0xad
};

// Циклический сдвиг влево
uint16_t ROL(uint16_t value, int shift) {
    return (value << shift) | (value >> (16 - shift));
}

// Циклический сдвиг вправо
uint16_t ROR(uint16_t value, int shift) {
    return (value >> shift) | (value << (16 - shift));
}

// Операция перемешивания
void mixing(
    uint16_t &R0,
    uint16_t &R1,
    uint16_t &R2,
    uint16_t &R3,
    const vector<uint16_t> &xkey,
    int &j
) {
    R0 = ROL(R0 + (R1 & ~R3) + (R2 & R3) + xkey[j++], 1);
    R1 = ROL(R1 + (R2 & ~R0) + (R3 & R0) + xkey[j++], 2);
    R2 = ROL(R2 + (R3 & ~R1) + (R0 & R1) + xkey[j++], 3);
    R3 = ROL(R3 + (R0 & ~R2) + (R1 & R2) + xkey[j++], 5);
}

// Операция наложения
void mashing(
    uint16_t &R0,
    uint16_t &R1,
    uint16_t &R2,
    uint16_t &R3,
    const vector<uint16_t> &xkey
) {
    R0 += xkey[R3 & 63];
    R1 += xkey[R0 & 63];
    R2 += xkey[R1 & 63];
    R3 += xkey[R2 & 63];
}

// Дополнение сообщения до размера блока 8 байт
vector<uint8_t> padding(const string &data) {
    vector<uint8_t> result(data.begin(), data.end());

    // Даже пустое сообщение должно содержать один блок
    if (result.empty()) {
        result.resize(8, 0);
    }

    // Добавляем нули до кратности 8
    while (result.size() % 8 != 0) {
        result.push_back(0);
    }

    return result;
}

// Расширение ключа RC2
vector<uint16_t> keyexp(
    const vector<uint8_t> &key,
    int effective_bits
) {
    // Проверяем параметры
    if (key.empty() || key.size() > 128 ||
        effective_bits < 1 || effective_bits > 1024) {
        throw invalid_argument("Invalid RC2 key parameters");
    }

    vector<uint8_t> L(128);

    // Размер исходного ключа
    size_t T = key.size();

    // Копируем исходный ключ
    for (size_t i = 0; i < T; i++) {
        L[i] = key[i];
    }

    // Расширяем ключ до 128 байтов
    for (size_t i = T; i < 128; i++) {
        L[i] = pitable[(L[i - 1] + L[i - T]) & 255];
    }

    // Вычисляем количество байтов эффективного ключа
    int T8 = (effective_bits + 7) / 8;

    // Вычисляем маску
    int TM = 255 >> (8 * T8 - effective_bits);

    // Применяем маску
    L[128 - T8] = pitable[L[128 - T8] & TM];

    // Обратное расширение
    for (int i = 127 - T8; i >= 0; i--) {
        L[i] = pitable[L[i + 1] ^ L[i + T8]];
    }

    // Преобразуем 128 байтов в 64 слова по 16 бит
    vector<uint16_t> xkey(64);

    for (int i = 0; i < 64; i++) {
        xkey[i] = L[2 * i] | (L[2 * i + 1] << 8);
    }

    return xkey;
}

// Шифрование RC2
vector<uint8_t> RC2_encrypt(
    const string &data,
    const vector<uint8_t> &key,
    int effective_bits
) {
    // Если длина не задана, используем полную длину ключа
    if (effective_bits == 0) {
        effective_bits = key.size() * 8;
    }

    // Расширяем ключ
    vector<uint16_t> xkey = keyexp(key, effective_bits);

    // Дополняем сообщение
    vector<uint8_t> bytes = padding(data);

    vector<uint8_t> encrypted;

    // Обрабатываем блоки по 8 байт
    for (size_t pos = 0; pos < bytes.size(); pos += 8) {

        uint16_t R0 = bytes[pos] | (bytes[pos + 1] << 8);
        uint16_t R1 = bytes[pos + 2] | (bytes[pos + 3] << 8);
        uint16_t R2 = bytes[pos + 4] | (bytes[pos + 5] << 8);
        uint16_t R3 = bytes[pos + 6] | (bytes[pos + 7] << 8);

        int j = 0;

        // 16 раундов Mixing
        for (int round = 0; round < 16; round++) {

            mixing(R0, R1, R2, R3, xkey, j);

            // Mashing после 5-го и 11-го раундов
            if (round == 4 || round == 10) {
                mashing(R0, R1, R2, R3, xkey);
            }
        }

        // Записываем результат
        uint16_t registers[4] = {R0, R1, R2, R3};

        for (int i = 0; i < 4; i++) {
            encrypted.push_back(registers[i] & 255);
            encrypted.push_back(registers[i] >> 8);
        }
    }

    return encrypted;
}

// Дешифрование RC2
string RC2_decrypt(
    const vector<uint8_t> &data,
    const vector<uint8_t> &key,
    size_t original_size,
    int effective_bits
) {
    // Проверяем размер зашифрованных данных
    if (data.empty() || data.size() % 8 != 0) {
        throw invalid_argument("Invalid encrypted data size");
    }

    // Проверяем ожидаемый размер сообщения после padding
    size_t expected_size = original_size;

    if (expected_size == 0) {
        expected_size = 8;
    }
    else if (expected_size % 8 != 0) {
        expected_size += 8 - expected_size % 8;
    }

    if (data.size() != expected_size) {
        throw invalid_argument("Original message size does not match");
    }

    // Автоматически определяем длину эффективного ключа
    if (effective_bits == 0) {
        effective_bits = key.size() * 8;
    }

    // Расширяем ключ
    vector<uint16_t> xkey = keyexp(key, effective_bits);

    vector<uint8_t> decrypted;

    // Обрабатываем каждый блок по 8 байт
    for (size_t pos = 0; pos < data.size(); pos += 8) {

        uint16_t R0 = data[pos] | (data[pos + 1] << 8);
        uint16_t R1 = data[pos + 2] | (data[pos + 3] << 8);
        uint16_t R2 = data[pos + 4] | (data[pos + 5] << 8);
        uint16_t R3 = data[pos + 6] | (data[pos + 7] << 8);

        // Начинаем с последнего элемента ключа
        int j = 63;

        // 16 обратных раундов
        for (int round = 15; round >= 0; round--) {

            // Обратный Mixing

            R3 = ROR(R3, 5);
            R3 -= (R0 & ~R2) + (R1 & R2) + xkey[j--];

            R2 = ROR(R2, 3);
            R2 -= (R3 & ~R1) + (R0 & R1) + xkey[j--];

            R1 = ROR(R1, 2);
            R1 -= (R2 & ~R0) + (R3 & R0) + xkey[j--];

            R0 = ROR(R0, 1);
            R0 -= (R1 & ~R3) + (R2 & R3) + xkey[j--];

            // Обратный Mashing
            if (round == 11 || round == 5) {

                R3 -= xkey[R2 & 63];
                R2 -= xkey[R1 & 63];
                R1 -= xkey[R0 & 63];
                R0 -= xkey[R3 & 63];
            }
        }

        // Сохраняем расшифрованный блок
        uint16_t registers[4] = {R0, R1, R2, R3};

        for (int i = 0; i < 4; i++) {
            decrypted.push_back(registers[i] & 255);
            decrypted.push_back(registers[i] >> 8);
        }
    }

    // Возвращаем исходную длину сообщения
    decrypted.resize(original_size);

    return string(decrypted.begin(), decrypted.end());
}

