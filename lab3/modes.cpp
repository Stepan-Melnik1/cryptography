// modes.cpp - режимы работы: ECB, CTR (гаммирование), имитовставка (CMAC) для ГОСТ
#include "crypto-lab.h"

// ---------- ECB ----------

// Применяет f к каждому полному 8-байтному блоку буфера.
template <class F>
static void for_each_block64(Bytes &buf, F f)
{
    for (std::size_t off = 0; off + BLOCK64 <= buf.size(); off += BLOCK64) {
        Block64 b;
        std::copy_n(buf.begin() + off, BLOCK64, b.begin());
        f(b);
        std::copy(b.begin(), b.end(), buf.begin() + off);
    }
}

void IDEA_ecb_encrypt(const IdeaSubkeys &EK, Bytes &buf)
{
    for_each_block64(buf, [&](Block64 &b) { IDEA_encrypt(EK, b); });
}

void IDEA_ecb_decrypt(const IdeaSubkeys &EK, Bytes &buf)
{
    IdeaSubkeys DK = IDEA_invkeys(EK);    // считаем подключи один раз на всё сообщение
    for_each_block64(buf, [&](Block64 &b) { IDEA_encrypt(DK, b); });
}

void GOST_ecb_encrypt(const GostSubkeys &K, Bytes &buf)
{
    for_each_block64(buf, [&](Block64 &b) { GOST_encrypt(K, b); });
}

void GOST_ecb_decrypt(const GostSubkeys &K, Bytes &buf)
{
    for_each_block64(buf, [&](Block64 &b) { GOST_decrypt(K, b); });
}

// ---------- CTR ----------

// Гамма = E(nonce || счётчик), счётчик растёт на 1 с каждым блоком.
// encrypt_block - любая функция, шифрующая один 8-байтный блок.
template <class EncryptBlock>
static void ctr_crypt(EncryptBlock encrypt_block, const Nonce &nonce, Bytes &buf)
{
    uint32_t counter = 0;

    for (std::size_t off = 0; off < buf.size(); off += BLOCK64) {
        Block64 gamma{};
        std::copy(nonce.begin(), nonce.end(), gamma.begin());
        store32be(&gamma[4], counter++);
        encrypt_block(gamma);

        std::size_t n = std::min(BLOCK64, buf.size() - off);   // последний блок может быть неполным
        for (std::size_t i = 0; i < n; i++)
            buf[off + i] ^= gamma[i];
    }
}

void IDEA_ctr(const IdeaSubkeys &EK, const Nonce &nonce, Bytes &buf)
{
    ctr_crypt([&](Block64 &b) { IDEA_encrypt(EK, b); }, nonce, buf);
}

void GOST_ctr(const GostSubkeys &K, const Nonce &nonce, Bytes &buf)
{
    ctr_crypt([&](Block64 &b) { GOST_encrypt(K, b); }, nonce, buf);
}

// ---------- имитовставка ГОСТ Р 34.13-2015 (CMAC, блок 64 бита) ----------

// Умножение на x в GF(2^64): сдвиг влево на 1 бит, при выходе старшего бита xor 0x1B.
static Block64 dbl(const Block64 &in)
{
    Block64 out{};
    for (std::size_t i = 0; i + 1 < BLOCK64; i++)
        out[i] = static_cast<uint8_t>((in[i] << 1) | (in[i + 1] >> 7));
    out[BLOCK64 - 1] = static_cast<uint8_t>(in[BLOCK64 - 1] << 1);
    if (in[0] & 0x80)
        out[BLOCK64 - 1] ^= 0x1B;
    return out;
}

Block64 GOST_mac(const GostSubkeys &K, const Bytes &msg)
{
    // подключи K1, K2 из E(0)
    Block64 zero{};
    GOST_encrypt(K, zero);
    Block64 k1 = dbl(zero);
    Block64 k2 = dbl(k1);

    std::size_t len = msg.size();
    std::size_t n = (len + BLOCK64 - 1) / BLOCK64;       // число блоков
    if (n == 0)
        n = 1;
    bool complete = (len != 0 && len % BLOCK64 == 0);    // последний блок полный?

    // все блоки, кроме последнего: обычная цепочка CBC
    Block64 x{};
    for (std::size_t i = 0; i + 1 < n; i++) {
        for (std::size_t j = 0; j < BLOCK64; j++)
            x[j] ^= msg[BLOCK64 * i + j];
        GOST_encrypt(K, x);
    }

    // последний блок: полный xor K1, неполный - дополняем 0x80 00.. и xor K2
    std::size_t rest = len % BLOCK64;                    // байт в последнем блоке
    if (rest == 0 && len != 0)
        rest = BLOCK64;
    Block64 last{};
    std::copy_n(msg.begin() + BLOCK64 * (n - 1), rest, last.begin());
    if (!complete)
        last[rest] = 0x80;
    const Block64 &k = complete ? k1 : k2;
    for (std::size_t j = 0; j < BLOCK64; j++)
        x[j] ^= last[j] ^ k[j];

    GOST_encrypt(K, x);
    return x;
}
