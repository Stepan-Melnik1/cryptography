// crypto-lab.h - публичный интерфейс libcryptolab (лабораторная 03, блочные шифры), C++17
#ifndef CRYPTO_LAB_H
#define CRYPTO_LAB_H

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

using Bytes = std::vector<uint8_t>;

constexpr std::size_t IDEA_KEY_LEN = 16;
constexpr std::size_t IDEA_SUBKEYS = 52;
constexpr std::size_t GOST_KEY_LEN = 32;
constexpr std::size_t GOST_SUBKEYS = 8;
constexpr std::size_t KUZ_KEY_LEN  = 32;
constexpr std::size_t KUZ_ROUNDS   = 10;
constexpr std::size_t RC2_KEY_LEN  = 16;
constexpr std::size_t BLOCK64      = 8;
constexpr std::size_t BLOCK128     = 16;

using Block64  = std::array<uint8_t, BLOCK64>;
using Block128 = std::array<uint8_t, BLOCK128>;
using Nonce    = std::array<uint8_t, 4>;

using IdeaKey      = std::array<uint8_t, IDEA_KEY_LEN>;
using IdeaSubkeys  = std::array<uint16_t, IDEA_SUBKEYS>;
using GostKey      = std::array<uint8_t, GOST_KEY_LEN>;
using GostSubkeys  = std::array<uint32_t, GOST_SUBKEYS>;
using KuzKey       = std::array<uint8_t, KUZ_KEY_LEN>;
using KuzRoundKeys = std::array<Block128, KUZ_ROUNDS>;
using Rc2Key       = std::array<uint8_t, RC2_KEY_LEN>;
using Rc2Subkeys   = std::array<uint16_t, 64>;

// Первые N байт вектора -> std::array (размер вектора должен быть не меньше N).
template <std::size_t N>
std::array<uint8_t, N> to_array(const Bytes &v)
{
    std::array<uint8_t, N> a{};
    std::copy_n(v.begin(), N, a.begin());
    return a;
}

// ---------- vars.cpp: таблицы и константы ----------
extern const uint8_t  GOST_SBOX[8][16];    // S-блок id-tc26-gost-28147-param-Z
extern const uint32_t GOST_C1, GOST_C2;    // константы ГОСТ 28147-89 (в Магме не используются)
extern const uint8_t  GOST_ORDER_ENC[32];  // порядок подключей при шифровании
extern const uint8_t  GOST_ORDER_DEC[32];  // порядок подключей при расшифровании
extern const uint8_t  KUZ_PI[256];         // S-блок Кузнечика
extern const uint8_t  KUZ_LVEC[16];        // коэффициенты линейного преобразования L
extern const uint8_t  RC2_PITABLE[256];    // таблица RC2 (RFC 2268)

// ---------- idea.cpp ----------
uint16_t mul65537(uint16_t a, uint16_t b);
uint16_t mulinv(uint16_t a);
uint16_t addinv(uint16_t a);
void     keyrot25(std::array<uint16_t, 8> &w);
uint16_t load16be(const uint8_t *p);
void     store16be(uint8_t *p, uint16_t v);

IdeaSubkeys IDEA_keyexp(const IdeaKey &key);
IdeaSubkeys IDEA_invkeys(const IdeaSubkeys &EK);
void        IDEA_encrypt(const IdeaSubkeys &Z, Block64 &data);
void        IDEA_decrypt(const IdeaSubkeys &EK, Block64 &data);

// ---------- gost.cpp ----------
uint32_t ROL32(uint32_t x, unsigned n);
uint32_t load32be(const uint8_t *p);
void     store32be(uint8_t *p, uint32_t v);
uint32_t T(uint32_t a);

GostSubkeys GOST_keyexp(const GostKey &key);
void        GOST_encrypt(const GostSubkeys &K, Block64 &data);
void        GOST_decrypt(const GostSubkeys &K, Block64 &data);

// PKCS#7: дополняет данные до кратного block (всегда добавляет 1..block байт).
Bytes padding(const Bytes &in, std::size_t block);
// Обратная операция: убирает дополнение на месте. false, если дополнение некорректно.
bool  unpadding(Bytes &data, std::size_t block);

// ---------- modes.cpp: режимы работы ----------
// ECB: обрабатываются только полные блоки (размер buf должен быть кратен длине блока).
void IDEA_ecb_encrypt(const IdeaSubkeys &EK, Bytes &buf);
void IDEA_ecb_decrypt(const IdeaSubkeys &EK, Bytes &buf);
void GOST_ecb_encrypt(const GostSubkeys &K, Bytes &buf);
void GOST_ecb_decrypt(const GostSubkeys &K, Bytes &buf);

// CTR (гаммирование): блок счётчика = nonce (4 байта) || счётчик (4 байта, big-endian).
// Шифрование и расшифрование - одна и та же функция, длина любая.
void IDEA_ctr(const IdeaSubkeys &EK, const Nonce &nonce, Bytes &buf);
void GOST_ctr(const GostSubkeys &K, const Nonce &nonce, Bytes &buf);

// Имитовставка ГОСТ Р 34.13-2015 (CMAC, блок 64 бита). Полные 8 байт;
// по стандарту используется старшая часть (обычно 4 байта).
Block64 GOST_mac(const GostSubkeys &K, const Bytes &msg);

// ---------- kuznyechik.cpp ----------
KuzRoundKeys KUZ_keyexp(const KuzKey &key);
void         KUZ_encrypt(const KuzRoundKeys &RK, Block128 &block);
void         KUZ_decrypt(const KuzRoundKeys &RK, Block128 &block);

// ---------- rc2.cpp (для сравнения лавинного эффекта) ----------
Rc2Subkeys RC2_keyexp(const Rc2Key &key);
void       RC2_encrypt(const Rc2Subkeys &K, Block64 &block);
void       RC2_decrypt(const Rc2Subkeys &K, Block64 &block);

#endif // CRYPTO_LAB_H
