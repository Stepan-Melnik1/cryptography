// selftest.cpp - тесты (векторы + round-trip), лавинный эффект, замер скорости
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <functional>
#include <string>
#include "crypto-lab.h"
#include "selftest.h"

// ---------- мелкие помощники ----------

static uint64_t rng_state = 0x9E3779B97F4A7C15ULL;

// xorshift64*: результат повторяется от запуска к запуску
static uint64_t rng()
{
    rng_state ^= rng_state >> 12;
    rng_state ^= rng_state << 25;
    rng_state ^= rng_state >> 27;
    return rng_state * 0x2545F4914F6CDD1DULL;
}

static Bytes rand_bytes(std::size_t n)
{
    Bytes v(n);
    for (auto &b : v)
        b = static_cast<uint8_t>(rng() >> 32);
    return v;
}

static Bytes hex2bin(const std::string &s)
{
    Bytes out;
    for (std::size_t i = 0; i + 1 < s.size(); i += 2)
        out.push_back(static_cast<uint8_t>(std::stoul(s.substr(i, 2), nullptr, 16)));
    return out;
}

static int popcount8(uint8_t x)
{
    int c = 0;
    while (x) {
        c += x & 1;
        x >>= 1;
    }
    return c;
}

// Применяет функцию над Block64/Block128 к блоку, лежащему в векторе.
template <std::size_t B, class F>
static void apply_block(Bytes &b, F f)
{
    auto blk = to_array<B>(b);
    f(blk);
    b.assign(blk.begin(), blk.end());
}

// ---------- обёртки: «ключ + блок -> зашифрованный блок» ----------

static void enc_idea(const Bytes &key, Bytes &b)
{
    IdeaSubkeys Z = IDEA_keyexp(to_array<IDEA_KEY_LEN>(key));
    apply_block<BLOCK64>(b, [&](Block64 &x) { IDEA_encrypt(Z, x); });
}

static void dec_idea(const Bytes &key, Bytes &b)
{
    IdeaSubkeys Z = IDEA_keyexp(to_array<IDEA_KEY_LEN>(key));
    apply_block<BLOCK64>(b, [&](Block64 &x) { IDEA_decrypt(Z, x); });
}

static void enc_gost(const Bytes &key, Bytes &b)
{
    GostSubkeys K = GOST_keyexp(to_array<GOST_KEY_LEN>(key));
    apply_block<BLOCK64>(b, [&](Block64 &x) { GOST_encrypt(K, x); });
}

static void dec_gost(const Bytes &key, Bytes &b)
{
    GostSubkeys K = GOST_keyexp(to_array<GOST_KEY_LEN>(key));
    apply_block<BLOCK64>(b, [&](Block64 &x) { GOST_decrypt(K, x); });
}

static void enc_rc2(const Bytes &key, Bytes &b)
{
    Rc2Subkeys K = RC2_keyexp(to_array<RC2_KEY_LEN>(key));
    apply_block<BLOCK64>(b, [&](Block64 &x) { RC2_encrypt(K, x); });
}

static void dec_rc2(const Bytes &key, Bytes &b)
{
    Rc2Subkeys K = RC2_keyexp(to_array<RC2_KEY_LEN>(key));
    apply_block<BLOCK64>(b, [&](Block64 &x) { RC2_decrypt(K, x); });
}

static void enc_kuz(const Bytes &key, Bytes &b)
{
    KuzRoundKeys RK = KUZ_keyexp(to_array<KUZ_KEY_LEN>(key));
    apply_block<BLOCK128>(b, [&](Block128 &x) { KUZ_encrypt(RK, x); });
}

static void dec_kuz(const Bytes &key, Bytes &b)
{
    KuzRoundKeys RK = KUZ_keyexp(to_array<KUZ_KEY_LEN>(key));
    apply_block<BLOCK128>(b, [&](Block128 &x) { KUZ_decrypt(RK, x); });
}

struct Cipher {
    const char *name;
    std::size_t block, key_len;
    std::function<void(const Bytes &key, Bytes &block)> enc, dec;
};

static const Cipher CIPHERS[] = {
    {"IDEA",       BLOCK64,  IDEA_KEY_LEN, enc_idea, dec_idea},
    {"GOST/Magma", BLOCK64,  GOST_KEY_LEN, enc_gost, dec_gost},
    {"RC2",        BLOCK64,  RC2_KEY_LEN,  enc_rc2,  dec_rc2},
    {"Kuznyechik", BLOCK128, KUZ_KEY_LEN,  enc_kuz,  dec_kuz},
};

// ---------- тесты ----------

static int failures;

static void check(bool ok, const std::string &name)
{
    std::printf("[%s] %s\n", ok ? " OK " : "FAIL", name.c_str());
    if (!ok)
        failures++;
}

// Шифруем блок известным ключом и сравниваем с эталоном (всё в hex), потом расшифровываем обратно.
static bool vector_ok(const Cipher &c, const char *key_hex, const char *pt_hex, const char *ct_hex)
{
    Bytes key = hex2bin(key_hex);
    Bytes pt = hex2bin(pt_hex);
    Bytes ct = hex2bin(ct_hex);

    Bytes tmp = pt;
    c.enc(key, tmp);
    if (tmp != ct)
        return false;
    c.dec(key, tmp);
    return tmp == pt;
}

int run_selftest()
{
    failures = 0;

    std::puts("== Тестовые векторы ==");
    check(vector_ok(CIPHERS[0], "00010002000300040005000600070008", "0000000100020003",
                    "11fbed2b01986de5"), "IDEA: классический вектор (ключ 1..8)");
    check(vector_ok(CIPHERS[1], "ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
                    "fedcba9876543210", "4ee901e5c2d8ca3d"), "Магма: вектор ГОСТ Р 34.12-2015");
    check(vector_ok(CIPHERS[3], "8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef",
                    "1122334455667700ffeeddccbbaa9988", "7f679d90bebc24305a468d42b9d4edcd"),
          "Кузнечик: вектор ГОСТ Р 34.12-2015");
    check(vector_ok(CIPHERS[2], "000102030405060708090a0b0c0d0e0f", "0000000000000000",
                    "9c4bfe6dfe739c2b"), "RC2: ключ 0..15, 128 бит (результат openssl rc2-ecb)");

    {   // подключи IDEA: Z1..Z16 для ключа 1..8
        static const uint16_t want[16] = {0x0001, 0x0002, 0x0003, 0x0004, 0x0005, 0x0006, 0x0007, 0x0008,
                                          0x0400, 0x0600, 0x0800, 0x0a00, 0x0c00, 0x0e00, 0x1000, 0x0200};
        IdeaSubkeys Z = IDEA_keyexp(to_array<IDEA_KEY_LEN>(hex2bin("00010002000300040005000600070008")));
        check(std::equal(want, want + 16, Z.begin()), "IDEA_keyexp: подключи Z1..Z16");
    }

    std::puts("== Вспомогательные функции IDEA ==");
    {
        bool ok_inv = true, ok_add = true;
        for (uint32_t a = 0; a < 65536; a++) {
            if (mul65537(static_cast<uint16_t>(a), mulinv(static_cast<uint16_t>(a))) != 1)
                ok_inv = false;
            if (static_cast<uint16_t>(a + addinv(static_cast<uint16_t>(a))) != 0)
                ok_add = false;
        }
        check(mul65537(0, 0) == 1 && mul65537(0, 2) == 65535, "mul65537: 0 трактуется как 65536");
        check(ok_inv, "mulinv: a * a^-1 = 1 для всех 65536 значений");
        check(ok_add, "addinv: a + (-a) = 0 для всех 65536 значений");
    }

    std::puts("== Режимы ==");
    {
        GostSubkeys K = GOST_keyexp(to_array<GOST_KEY_LEN>(
            hex2bin("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")));
        Bytes m = hex2bin("92def06b3c130a59db54c704f8189d204a98fb2e67a8024c8912409b17b57e41");
        Nonce nonce = to_array<4>(hex2bin("12345678"));

        Bytes c = m;
        GOST_ctr(K, nonce, c);
        check(c == hex2bin("4e98110c97b7b93c3e250d93d6e85d69136d868807b2dbef568eb680ab52a12d"),
              "Магма CTR: вектор ГОСТ Р 34.13-2015");

        Block64 mac = GOST_mac(K, m);
        check(std::equal(mac.begin(), mac.begin() + 4, hex2bin("154e7210").begin()),
              "Магма MAC (CMAC): вектор ГОСТ Р 34.13-2015, 32 бита");
    }

    std::puts("== Round-trip: dec(enc(x)) == x ==");
    for (const Cipher &c : CIPHERS) {
        bool ok = true;
        for (int t = 0; t < 2000; t++) {
            Bytes key = rand_bytes(c.key_len);
            Bytes b = rand_bytes(c.block);
            Bytes orig = b;
            c.enc(key, b);
            c.dec(key, b);
            if (b != orig)
                ok = false;
        }
        check(ok, std::string(c.name) + ": 2000 случайных ключей/блоков");
    }

    {   // padding PKCS#7
        bool ok = true;
        for (std::size_t len = 0; len <= 40; len++)
            for (std::size_t block = 8; block <= 16; block += 8) {
                Bytes in = rand_bytes(len);
                Bytes out = padding(in, block);
                Bytes back = out;
                if (out.size() % block != 0 || out.size() <= len ||
                    !unpadding(back, block) || back != in)
                    ok = false;
            }
        Bytes bad = {1, 2, 3, 4, 5, 6, 3, 2};             // неверное дополнение
        check(ok && !unpadding(bad, 8), "padding/unpadding PKCS#7: длины 0..40, блоки 8 и 16");
    }

    {   // CTR: расшифрование = шифрование, для любой длины
        bool ok = true;
        Bytes key = rand_bytes(32);
        Nonce nonce = to_array<4>(rand_bytes(4));
        IdeaSubkeys Z = IDEA_keyexp(to_array<IDEA_KEY_LEN>(key));
        GostSubkeys K = GOST_keyexp(to_array<GOST_KEY_LEN>(key));
        for (std::size_t len = 0; len <= 50; len++) {
            Bytes orig = rand_bytes(len);
            Bytes b = orig;
            IDEA_ctr(Z, nonce, b);
            if (len > 8 && b == orig)
                ok = false;
            IDEA_ctr(Z, nonce, b);
            if (b != orig)
                ok = false;
            GOST_ctr(K, nonce, b);
            GOST_ctr(K, nonce, b);
            if (b != orig)
                ok = false;
        }
        check(ok, "CTR (IDEA и ГОСТ): round-trip для длин 0..50 (с неполным блоком)");
    }

    std::printf("\nИтого: %s (%d ошибок)\n", failures ? "ЕСТЬ ОШИБКИ" : "все проверки пройдены", failures);
    return failures;
}

// ---------- лавинный эффект ----------

struct Stat {
    double sum = 0, sumsq = 0;
    int min = 1 << 30, max = 0;

    void add(int v)
    {
        sum += v;
        sumsq += static_cast<double>(v) * v;
        min = std::min(min, v);
        max = std::max(max, v);
    }

    void print(unsigned n, std::size_t block_bits) const
    {
        double mean = sum / n;
        double var = sumsq / n - mean * mean;
        std::printf("%6.2f%%  σ=%5.2f%%  [%5.1f%% .. %5.1f%%]",
                    100.0 * mean / block_bits, 100.0 * std::sqrt(var) / block_bits,
                    100.0 * min / block_bits, 100.0 * max / block_bits);
    }
};

// Сколько бит отличается между двумя блоками.
static int diff_bits(const Bytes &a, const Bytes &b)
{
    int d = 0;
    for (std::size_t j = 0; j < a.size(); j++)
        d += popcount8(a[j] ^ b[j]);
    return d;
}

void run_avalanche(unsigned trials)
{
    std::printf("Лавинный эффект: %u испытаний на шифр, случайные ключи и блоки.\n", trials);
    std::printf("Для идеального шифра: среднее 50%%, σ = 50%%/sqrt(бит блока) (6.25%% для 64 бит, 4.42%% для 128).\n\n");
    std::printf("%-11s %5s %5s | %-44s | %s\n", "Шифр", "блок", "ключ",
                "1 бит КЛЮЧА -> доля бит шифротекста", "1 бит ОТКР. ТЕКСТА -> доля бит шифротекста");
    std::printf("---------------------------------------------------------------------------------------------------------------\n");

    for (const Cipher &c : CIPHERS) {
        std::size_t block_bits = c.block * 8, key_bits = c.key_len * 8;
        Stat sk, sp;

        for (unsigned t = 0; t < trials; t++) {
            Bytes key = rand_bytes(c.key_len);
            Bytes pt = rand_bytes(c.block);

            Bytes c1 = pt;
            c.enc(key, c1);

            // меняем один случайный бит ключа
            Bytes key2 = key;
            std::size_t kb = rng() % key_bits;
            key2[kb / 8] ^= static_cast<uint8_t>(1u << (kb % 8));
            Bytes c2 = pt;
            c.enc(key2, c2);
            sk.add(diff_bits(c1, c2));

            // меняем один случайный бит открытого текста
            Bytes pt2 = pt;
            std::size_t pb = rng() % block_bits;
            pt2[pb / 8] ^= static_cast<uint8_t>(1u << (pb % 8));
            c2 = pt2;
            c.enc(key, c2);
            sp.add(diff_bits(c1, c2));
        }
        std::printf("%-11s %5zu %5zu | ", c.name, block_bits, key_bits);
        sk.print(trials, block_bits);
        std::printf(" | ");
        sp.print(trials, block_bits);
        std::printf("\n");
    }
}

// ---------- скорость ----------

static double now()
{
    using clock = std::chrono::steady_clock;
    return std::chrono::duration<double>(clock::now().time_since_epoch()).count();
}

// Лучшее время из трёх прогонов, печатает МБ/с.
static void bench(const char *label, double mb, const std::function<void()> &work)
{
    double best = 1e30;
    for (int rep = 0; rep < 3; rep++) {
        double t0 = now();
        work();
        best = std::min(best, now() - t0);
    }
    std::printf("%-22s %8.1f МБ/с\n", label, mb / best);
}

void run_bench()
{
    constexpr std::size_t BENCH_MB = 8;
    constexpr std::size_t BENCH_KUZ_MB = 1;

    Bytes buf = rand_bytes(BENCH_MB * 1024 * 1024);
    Bytes key = rand_bytes(32);
    Nonce nonce = {1, 2, 3, 4};

    IdeaSubkeys Z = IDEA_keyexp(to_array<IDEA_KEY_LEN>(key));
    GostSubkeys K = GOST_keyexp(to_array<GOST_KEY_LEN>(key));
    KuzRoundKeys RK = KUZ_keyexp(to_array<KUZ_KEY_LEN>(key));
    double mb = static_cast<double>(BENCH_MB);

    bench("IDEA   ECB encrypt", mb, [&] { IDEA_ecb_encrypt(Z, buf); });
    bench("IDEA   ECB decrypt", mb, [&] { IDEA_ecb_decrypt(Z, buf); });
    bench("IDEA   CTR",         mb, [&] { IDEA_ctr(Z, nonce, buf); });
    bench("ГОСТ   ECB encrypt", mb, [&] { GOST_ecb_encrypt(K, buf); });
    bench("ГОСТ   ECB decrypt", mb, [&] { GOST_ecb_decrypt(K, buf); });
    bench("ГОСТ   CTR",         mb, [&] { GOST_ctr(K, nonce, buf); });
    bench("ГОСТ   MAC",         mb, [&] { volatile uint8_t sink = GOST_mac(K, buf)[0]; (void)sink; });
    bench("Кузнечик ECB encrypt", static_cast<double>(BENCH_KUZ_MB), [&] {
        for (std::size_t off = 0; off < BENCH_KUZ_MB * 1024 * 1024; off += BLOCK128) {
            Block128 b;
            std::copy_n(buf.begin() + off, BLOCK128, b.begin());
            KUZ_encrypt(RK, b);
            std::copy(b.begin(), b.end(), buf.begin() + off);
        }
    });
}
