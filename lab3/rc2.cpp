// rc2.cpp - RC2 (RFC 2268), ключ 128 бит, effective bits = 128.
// Нужен только для сравнения лавинного эффекта с лабораторной работой 02.
#include "crypto-lab.h"

static uint16_t rol16(uint16_t x, int n) { return static_cast<uint16_t>((x << n) | (x >> (16 - n))); }
static uint16_t ror16(uint16_t x, int n) { return static_cast<uint16_t>((x >> n) | (x << (16 - n))); }

static uint16_t u16(unsigned v) { return static_cast<uint16_t>(v); }

// 16 байт ключа -> 64 слова расширенного ключа K[0..63].
Rc2Subkeys RC2_keyexp(const Rc2Key &key)
{
    std::array<uint8_t, 128> L{};
    std::copy(key.begin(), key.end(), L.begin());

    for (std::size_t i = RC2_KEY_LEN; i < 128; i++)
        L[i] = RC2_PITABLE[static_cast<uint8_t>(L[i - 1] + L[i - RC2_KEY_LEN])];

    // T1 = 128 бит -> T8 = 16, TM = 0xFF
    L[128 - RC2_KEY_LEN] = RC2_PITABLE[L[128 - RC2_KEY_LEN]];
    for (int i = 127 - static_cast<int>(RC2_KEY_LEN); i >= 0; i--)
        L[i] = RC2_PITABLE[L[i + 1] ^ L[i + RC2_KEY_LEN]];

    Rc2Subkeys K{};
    for (std::size_t i = 0; i < 64; i++)
        K[i] = static_cast<uint16_t>(L[2 * i] | (L[2 * i + 1] << 8));
    return K;
}

void RC2_encrypt(const Rc2Subkeys &K, Block64 &block)
{
    uint16_t r0 = u16(block[0] | (block[1] << 8));
    uint16_t r1 = u16(block[2] | (block[3] << 8));
    uint16_t r2 = u16(block[4] | (block[5] << 8));
    uint16_t r3 = u16(block[6] | (block[7] << 8));

    for (int i = 0; i < 16; i++) {
        int j = i * 4;
        r0 = rol16(u16(r0 + K[j]     + (r3 & r2) + u16(~r3 & r1)), 1);
        r1 = rol16(u16(r1 + K[j + 1] + (r0 & r3) + u16(~r0 & r2)), 2);
        r2 = rol16(u16(r2 + K[j + 2] + (r1 & r0) + u16(~r1 & r3)), 3);
        r3 = rol16(u16(r3 + K[j + 3] + (r2 & r1) + u16(~r2 & r0)), 5);
        if (i == 4 || i == 10) {                 // mashing round
            r0 = u16(r0 + K[r3 & 63]);
            r1 = u16(r1 + K[r0 & 63]);
            r2 = u16(r2 + K[r1 & 63]);
            r3 = u16(r3 + K[r2 & 63]);
        }
    }

    block[0] = static_cast<uint8_t>(r0); block[1] = static_cast<uint8_t>(r0 >> 8);
    block[2] = static_cast<uint8_t>(r1); block[3] = static_cast<uint8_t>(r1 >> 8);
    block[4] = static_cast<uint8_t>(r2); block[5] = static_cast<uint8_t>(r2 >> 8);
    block[6] = static_cast<uint8_t>(r3); block[7] = static_cast<uint8_t>(r3 >> 8);
}

void RC2_decrypt(const Rc2Subkeys &K, Block64 &block)
{
    uint16_t r0 = u16(block[0] | (block[1] << 8));
    uint16_t r1 = u16(block[2] | (block[3] << 8));
    uint16_t r2 = u16(block[4] | (block[5] << 8));
    uint16_t r3 = u16(block[6] | (block[7] << 8));

    for (int i = 15; i >= 0; i--) {
        int j = i * 4;
        if (i == 4 || i == 10) {                 // сначала отменяем mashing
            r3 = u16(r3 - K[r2 & 63]);
            r2 = u16(r2 - K[r1 & 63]);
            r1 = u16(r1 - K[r0 & 63]);
            r0 = u16(r0 - K[r3 & 63]);
        }
        r3 = ror16(r3, 5);
        r3 = u16(r3 - K[j + 3] - (r2 & r1) - u16(~r2 & r0));
        r2 = ror16(r2, 3);
        r2 = u16(r2 - K[j + 2] - (r1 & r0) - u16(~r1 & r3));
        r1 = ror16(r1, 2);
        r1 = u16(r1 - K[j + 1] - (r0 & r3) - u16(~r0 & r2));
        r0 = ror16(r0, 1);
        r0 = u16(r0 - K[j]     - (r3 & r2) - u16(~r3 & r1));
    }

    block[0] = static_cast<uint8_t>(r0); block[1] = static_cast<uint8_t>(r0 >> 8);
    block[2] = static_cast<uint8_t>(r1); block[3] = static_cast<uint8_t>(r1 >> 8);
    block[4] = static_cast<uint8_t>(r2); block[5] = static_cast<uint8_t>(r2 >> 8);
    block[6] = static_cast<uint8_t>(r3); block[7] = static_cast<uint8_t>(r3 >> 8);
}
