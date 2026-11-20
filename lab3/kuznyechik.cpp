// kuznyechik.cpp - «Кузнечик» (ГОСТ Р 34.12-2015): блок 128 бит, ключ 256 бит, 10 раундов.
// Байты блока лежат в том же порядке, что и в шестнадцатеричной записи стандарта:
// x[0] = a15 (старший байт), x[15] = a0.
#include <cstring>
#include "crypto-lab.h"

// Умножение в GF(2^8) по модулю x^8 + x^7 + x^6 + x + 1 (0x1C3).
static uint8_t gmul(uint8_t a, uint8_t b)
{
    uint8_t r = 0;
    while (b) {
        if (b & 1)
            r ^= a;
        uint8_t hi = a & 0x80;
        a <<= 1;
        if (hi)
            a ^= 0xC3;
        b >>= 1;
    }
    return r;
}

// Таблицы считаем один раз (при первом обращении) - так L работает в разы быстрее.
struct Tables {
    uint8_t pi_inv[256];
    uint8_t mul[BLOCK128][256];     // mul[i][x] = KUZ_LVEC[i] * x в GF(2^8)

    Tables()
    {
        for (int i = 0; i < 256; i++)
            pi_inv[KUZ_PI[i]] = static_cast<uint8_t>(i);
        for (std::size_t i = 0; i < BLOCK128; i++)
            for (int x = 0; x < 256; x++)
                mul[i][x] = gmul(KUZ_LVEC[i], static_cast<uint8_t>(x));
    }
};

static const Tables &tables()
{
    static const Tables t;
    return t;
}

static void xor16(Block128 &a, const Block128 &b)
{
    for (std::size_t i = 0; i < BLOCK128; i++)
        a[i] ^= b[i];
}

static void S(Block128 &x)
{
    for (auto &byte : x)
        byte = KUZ_PI[byte];
}

static void S_inv(Block128 &x)
{
    const Tables &t = tables();
    for (auto &byte : x)
        byte = t.pi_inv[byte];
}

// R: новый старший байт = l(x), остальные сдвигаются на байт вправо.
static void R(Block128 &x)
{
    const Tables &t = tables();
    uint8_t s = 0;
    for (std::size_t i = 0; i < BLOCK128; i++)
        s ^= t.mul[i][x[i]];
    std::memmove(&x[1], &x[0], BLOCK128 - 1);
    x[0] = s;
}

// Обратное к R. Последний коэффициент l равен 1, поэтому делить не нужно.
static void R_inv(Block128 &x)
{
    const Tables &t = tables();
    uint8_t s = x[0];
    std::memmove(&x[0], &x[1], BLOCK128 - 1);
    for (std::size_t i = 0; i + 1 < BLOCK128; i++)
        s ^= t.mul[i][x[i]];
    x[BLOCK128 - 1] = s;
}

// L = R^16
static void L(Block128 &x)
{
    for (int i = 0; i < 16; i++)
        R(x);
}

static void L_inv(Block128 &x)
{
    for (int i = 0; i < 16; i++)
        R_inv(x);
}

// Развёртывание ключа: K1||K2 -> 10 раундовых ключей (4 прохода по 8 раундов Фейстеля).
KuzRoundKeys KUZ_keyexp(const KuzKey &key)
{
    std::array<Block128, 32> C{};
    for (std::size_t i = 0; i < 32; i++) {        // C_i = L(Vec128(i)), i = 1..32
        C[i][BLOCK128 - 1] = static_cast<uint8_t>(i + 1);
        L(C[i]);
    }

    KuzRoundKeys RK{};
    std::copy_n(key.begin(), BLOCK128, RK[0].begin());
    std::copy_n(key.begin() + BLOCK128, BLOCK128, RK[1].begin());

    for (std::size_t j = 0; j < 4; j++) {
        Block128 a = RK[2 * j];
        Block128 b = RK[2 * j + 1];

        for (std::size_t r = 0; r < 8; r++) {     // (a, b) -> (L(S(a ^ C)) ^ b, a)
            Block128 t = a;
            xor16(t, C[8 * j + r]);
            S(t);
            L(t);
            xor16(t, b);
            b = a;
            a = t;
        }
        RK[2 * j + 2] = a;
        RK[2 * j + 3] = b;
    }
    return RK;
}

void KUZ_encrypt(const KuzRoundKeys &RK, Block128 &block)
{
    for (std::size_t i = 0; i + 1 < KUZ_ROUNDS; i++) {
        xor16(block, RK[i]);
        S(block);
        L(block);
    }
    xor16(block, RK[KUZ_ROUNDS - 1]);
}

void KUZ_decrypt(const KuzRoundKeys &RK, Block128 &block)
{
    xor16(block, RK[KUZ_ROUNDS - 1]);
    for (std::size_t i = KUZ_ROUNDS - 1; i-- > 0;) {   // i = 8, 7, ..., 0
        L_inv(block);
        S_inv(block);
        xor16(block, RK[i]);
    }
}
