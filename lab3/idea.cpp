// idea.cpp - шифр IDEA: вспомогательные функции, ключи, шифрование/расшифрование
#include "crypto-lab.h"

// ---------- вспомогательные функции ----------

// Умножение по модулю 65537. Ноль означает 2^16 = 65536.
uint16_t mul65537(uint16_t a, uint16_t b)
{
    uint64_t x = a ? a : 65536;
    uint64_t y = b ? b : 65536;
    uint64_t r = (x * y) % 65537;      // 65536*65536 не лезет в uint32_t
    return static_cast<uint16_t>(r == 65536 ? 0 : r);
}

// Мультипликативное обратное по модулю 65537 (расширенный алгоритм Евклида).
uint16_t mulinv(uint16_t a)
{
    if (a == 0)
        return 0;                      // 65536 = -1, обратный к нему он сам
    int32_t t = 0, newt = 1, r = 65537, newr = a;
    while (newr != 0) {
        int32_t q = r / newr;
        int32_t tmp;
        tmp = t - q * newt;  t = newt;  newt = tmp;
        tmp = r - q * newr;  r = newr;  newr = tmp;
    }
    if (t < 0)
        t += 65537;
    return static_cast<uint16_t>(t == 65536 ? 0 : t);
}

// Аддитивное обратное по модулю 65536.
uint16_t addinv(uint16_t a)
{
    return static_cast<uint16_t>((0u - a) & 0xFFFF);
}

static uint16_t add16(uint16_t a, uint16_t b)
{
    return static_cast<uint16_t>((a + b) & 0xFFFF);
}

// Циклический сдвиг 128-битного ключа (8 слов по 16 бит) влево на 25 бит = 16 + 9.
void keyrot25(std::array<uint16_t, 8> &w)
{
    std::array<uint16_t, 8> t{};
    for (int j = 0; j < 8; j++)
        t[j] = static_cast<uint16_t>((w[(j + 1) % 8] << 9) | (w[(j + 2) % 8] >> 7));
    w = t;
}

uint16_t load16be(const uint8_t *p)
{
    return static_cast<uint16_t>((p[0] << 8) | p[1]);
}

void store16be(uint8_t *p, uint16_t v)
{
    p[0] = static_cast<uint8_t>(v >> 8);
    p[1] = static_cast<uint8_t>(v & 0xFF);
}

// ---------- ключи ----------

// 128-битный ключ -> 52 подключа шифрования.
IdeaSubkeys IDEA_keyexp(const IdeaKey &key)
{
    std::array<uint16_t, 8> W{};
    for (int i = 0; i < 8; i++)
        W[i] = load16be(key.data() + 2 * i);

    IdeaSubkeys Z{};
    for (std::size_t i = 0; i < IDEA_SUBKEYS; i++) {
        if (i > 0 && i % 8 == 0)
            keyrot25(W);
        Z[i] = W[i % 8];
    }
    return Z;
}

// 52 подключа шифрования -> 52 подключа расшифрования.
IdeaSubkeys IDEA_invkeys(const IdeaSubkeys &EK)
{
    IdeaSubkeys DK{};

    // первый раунд расшифрования
    DK[0] = mulinv(EK[48]);
    DK[1] = addinv(EK[49]);
    DK[2] = addinv(EK[50]);
    DK[3] = mulinv(EK[51]);
    DK[4] = EK[46];
    DK[5] = EK[47];

    // раунды 2..8: средние подключа меняются местами
    for (int r = 2; r <= 8; r++) {
        int d = 6 * (r - 1);
        int s = 6 * (9 - r);
        DK[d + 0] = mulinv(EK[s + 0]);
        DK[d + 1] = addinv(EK[s + 2]);
        DK[d + 2] = addinv(EK[s + 1]);
        DK[d + 3] = mulinv(EK[s + 3]);
        DK[d + 4] = EK[s - 2];
        DK[d + 5] = EK[s - 1];
    }

    // выходное преобразование
    DK[48] = mulinv(EK[0]);
    DK[49] = addinv(EK[1]);
    DK[50] = addinv(EK[2]);
    DK[51] = mulinv(EK[3]);
    return DK;
}

// ---------- шифрование одного 8-байтного блока (на месте) ----------

void IDEA_encrypt(const IdeaSubkeys &Z, Block64 &data)
{
    uint16_t x1 = load16be(&data[0]);
    uint16_t x2 = load16be(&data[2]);
    uint16_t x3 = load16be(&data[4]);
    uint16_t x4 = load16be(&data[6]);
    int j = 0;

    for (int r = 0; r < 8; r++) {
        uint16_t y1 = mul65537(x1, Z[j++]);
        uint16_t y2 = add16(x2, Z[j++]);
        uint16_t y3 = add16(x3, Z[j++]);
        uint16_t y4 = mul65537(x4, Z[j++]);

        // MA-блок
        uint16_t t0 = y1 ^ y3;
        uint16_t t1 = y2 ^ y4;
        uint16_t t2 = mul65537(t0, Z[j++]);
        uint16_t t3 = add16(t1, t2);
        uint16_t t4 = mul65537(t3, Z[j++]);
        uint16_t t5 = add16(t2, t4);

        x1 = y1 ^ t4;
        x2 = y3 ^ t4;      // обмен средних регистров
        x3 = y2 ^ t5;
        x4 = y4 ^ t5;
    }

    // выходное преобразование (отменяет последний обмен)
    uint16_t c1 = mul65537(x1, Z[48]);
    uint16_t c2 = add16(x3, Z[49]);
    uint16_t c3 = add16(x2, Z[50]);
    uint16_t c4 = mul65537(x4, Z[51]);

    store16be(&data[0], c1);
    store16be(&data[2], c2);
    store16be(&data[4], c3);
    store16be(&data[6], c4);
}

// Расшифрование = та же сеть с подключами DK, полученными из EK.
void IDEA_decrypt(const IdeaSubkeys &EK, Block64 &data)
{
    IDEA_encrypt(IDEA_invkeys(EK), data);
}
