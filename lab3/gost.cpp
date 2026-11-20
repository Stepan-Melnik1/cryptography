// gost.cpp - ГОСТ 28147-89 / ГОСТ Р 34.12-2015 «Магма»: вспомогательные функции,
// ключи, шифрование/расшифрование, дополнение PKCS#7
#include "crypto-lab.h"

// ---------- вспомогательные функции ----------

uint32_t ROL32(uint32_t x, unsigned n)
{
    return (x << n) | (x >> (32 - n));
}

uint32_t load32be(const uint8_t *p)
{
    return (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8)  |  static_cast<uint32_t>(p[3]);
}

void store32be(uint8_t *p, uint32_t v)
{
    p[0] = static_cast<uint8_t>(v >> 24);
    p[1] = static_cast<uint8_t>(v >> 16);
    p[2] = static_cast<uint8_t>(v >> 8);
    p[3] = static_cast<uint8_t>(v);
}

// Подстановка S-блока по 8 полубайтам: i-й полубайт идёт через строку i.
uint32_t T(uint32_t a)
{
    uint32_t r = 0;
    for (int i = 0; i < 8; i++)
        r |= static_cast<uint32_t>(GOST_SBOX[i][(a >> (4 * i)) & 0xF]) << (4 * i);
    return r;
}

// PKCS#7: добавляем pad байт, каждый равен pad (pad = 1..block).
Bytes padding(const Bytes &in, std::size_t block)
{
    std::size_t pad = block - in.size() % block;
    Bytes out = in;
    out.insert(out.end(), pad, static_cast<uint8_t>(pad));
    return out;
}

bool unpadding(Bytes &data, std::size_t block)
{
    if (data.empty() || data.size() % block != 0)
        return false;
    std::size_t pad = data.back();
    if (pad == 0 || pad > block)
        return false;
    for (std::size_t i = data.size() - pad; i < data.size(); i++)
        if (data[i] != pad)
            return false;
    data.resize(data.size() - pad);
    return true;
}

// ---------- ключи ----------

// 256-битный ключ -> 8 подключей по 32 бита (Магма: big-endian).
GostSubkeys GOST_keyexp(const GostKey &key)
{
    GostSubkeys K{};
    for (std::size_t i = 0; i < GOST_SUBKEYS; i++)
        K[i] = load32be(key.data() + 4 * i);
    return K;
}

// ---------- ядро: 32 раунда сети Фейстеля ----------

static void gost_core(const GostSubkeys &K, Block64 &data, const uint8_t order[32])
{
    uint32_t N2 = load32be(&data[0]);    // старшая половина
    uint32_t N1 = load32be(&data[4]);    // младшая половина

    for (int i = 0; i < 32; i++) {
        uint32_t cm1 = N1 + K[order[i]];          // сложение по модулю 2^32
        uint32_t cm2 = ROL32(T(cm1), 11);         // S-блок + сдвиг на 11
        uint32_t cm3 = cm2 ^ N2;
        if (i < 31) {                             // раунды 1..31: обмен половин
            N2 = N1;
            N1 = cm3;
        } else {                                  // раунд 32: без обмена, результат -> старшая половина
            N2 = cm3;
        }
    }
    store32be(&data[0], N2);
    store32be(&data[4], N1);
}

void GOST_encrypt(const GostSubkeys &K, Block64 &data)
{
    gost_core(K, data, GOST_ORDER_ENC);
}

void GOST_decrypt(const GostSubkeys &K, Block64 &data)
{
    gost_core(K, data, GOST_ORDER_DEC);
}
