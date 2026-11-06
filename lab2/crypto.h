#ifndef CRYPTO_H
#define CRYPTO_H

#include <iostream>
#include <vector>
#include <string>
#include <cstdint>
#include <cstddef>

using namespace std;

// Результат обмена ключами Диффи-Хеллмана
struct DHResult {
    uint64_t p;
    uint64_t g;

    uint64_t a;
    uint64_t b;

    uint64_t A;
    uint64_t B;

    uint64_t key;
};

// Точка эллиптической кривой
struct ECPoint {
    int x;
    int y;
    bool infinity;
};

// Результат обмена ключами ECDH
struct ECDHResult {
    int p;
    int curveA;
    int curveB;
    int n;

    ECPoint G;

    int privateA;
    int privateB;

    ECPoint publicA;
    ECPoint publicB;

    ECPoint sharedKey;
};

// Функции Диффи-Хеллмана
uint64_t randnumgen(uint64_t min, uint64_t max);
bool primenumtest(uint64_t n);
uint64_t exponentiation(uint64_t base, uint64_t exp, uint64_t mod);
DHResult DH_keygen();

// Функции ECDH
int modInverse(int value, int mod);

ECPoint pointAdd(
    ECPoint P,
    ECPoint Q,
    int curveA,
    int p
);

ECPoint pointMultiply(
    int scalar,
    ECPoint point,
    int curveA,
    int p
);

ECDHResult ECDH_keygen(
    int p,
    int curveA,
    int curveB,
    ECPoint G,
    int n
);

// Вспомогательные функции RC2
uint16_t ROL(uint16_t value, int shift);
uint16_t ROR(uint16_t value, int shift);

void mixing(
    uint16_t &R0,
    uint16_t &R1,
    uint16_t &R2,
    uint16_t &R3,
    const vector<uint16_t> &xkey,
    int &j
);

void mashing(
    uint16_t &R0,
    uint16_t &R1,
    uint16_t &R2,
    uint16_t &R3,
    const vector<uint16_t> &xkey
);

vector<uint8_t> padding(const string &data);

vector<uint16_t> keyexp(
    const vector<uint8_t> &key,
    int effective_bits
);

// Основные функции RC2
vector<uint8_t> RC2_encrypt(
    const string &data,
    const vector<uint8_t> &key,
    int effective_bits = 0
);

string RC2_decrypt(
    const vector<uint8_t> &data,
    const vector<uint8_t> &key,
    size_t original_size,
    int effective_bits = 0
);

#endif