// main.cpp - консольное приложение лабораторной 03 «Симметричные блочные шифры».
// Вся криптография лежит в libcryptolab (idea.cpp, gost.cpp, modes.cpp, kuznyechik.cpp, vars.cpp),
// здесь только разбор командной строки и вывод.
#include <cstdlib>
#include <functional>
#include <iostream>
#include <optional>
#include <string>
#include "crypto-lab.h"
#include "selftest.h"

using std::optional;
using std::string;

static const char *NONCE_DEFAULT = "12345678";

// ---------- hex ----------

static int hex_digit(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

// Строка hex -> байты. false, если строка некорректна.
static bool hex2bin(const string &s, Bytes &out)
{
    if (s.size() % 2 != 0)
        return false;
    out.clear();
    for (std::size_t i = 0; i < s.size(); i += 2) {
        int hi = hex_digit(s[i]), lo = hex_digit(s[i + 1]);
        if (hi < 0 || lo < 0)
            return false;
        out.push_back(static_cast<uint8_t>(hi * 16 + lo));
    }
    return true;
}

static string to_hex(const Bytes &v, bool upper)
{
    const char *digits = upper ? "0123456789ABCDEF" : "0123456789abcdef";
    string s;
    for (uint8_t b : v) {
        s += digits[b >> 4];
        s += digits[b & 0xF];
    }
    return s;
}

static void print_hex(const char *label, const Bytes &v, bool upper)
{
    std::cout << label << ' ' << to_hex(v, upper) << '\n';
}

// ---------- описание шифров ----------

struct Algo {
    string name;
    std::size_t block, key_len;
    string default_key;
    // ECB по всем полным блокам буфера
    std::function<void(const Bytes &key, Bytes &buf, bool decrypt)> ecb;
    // CTR; пустая функция, если режим для шифра не делали
    std::function<void(const Bytes &key, const Nonce &nonce, Bytes &buf)> ctr;
};

static void idea_ecb(const Bytes &key, Bytes &buf, bool decrypt)
{
    IdeaSubkeys Z = IDEA_keyexp(to_array<IDEA_KEY_LEN>(key));
    if (decrypt)
        IDEA_ecb_decrypt(Z, buf);
    else
        IDEA_ecb_encrypt(Z, buf);
}

static void gost_ecb(const Bytes &key, Bytes &buf, bool decrypt)
{
    GostSubkeys K = GOST_keyexp(to_array<GOST_KEY_LEN>(key));
    if (decrypt)
        GOST_ecb_decrypt(K, buf);
    else
        GOST_ecb_encrypt(K, buf);
}

static void kuz_ecb(const Bytes &key, Bytes &buf, bool decrypt)
{
    KuzRoundKeys RK = KUZ_keyexp(to_array<KUZ_KEY_LEN>(key));
    for (std::size_t off = 0; off + BLOCK128 <= buf.size(); off += BLOCK128) {
        Block128 b;
        std::copy_n(buf.begin() + off, BLOCK128, b.begin());
        if (decrypt)
            KUZ_decrypt(RK, b);
        else
            KUZ_encrypt(RK, b);
        std::copy(b.begin(), b.end(), buf.begin() + off);
    }
}

static void idea_ctr(const Bytes &key, const Nonce &nonce, Bytes &buf)
{
    IDEA_ctr(IDEA_keyexp(to_array<IDEA_KEY_LEN>(key)), nonce, buf);
}

static void gost_ctr(const Bytes &key, const Nonce &nonce, Bytes &buf)
{
    GOST_ctr(GOST_keyexp(to_array<GOST_KEY_LEN>(key)), nonce, buf);
}

static const std::vector<Algo> &algos()
{
    static const std::vector<Algo> list = {
        {"idea", BLOCK64, IDEA_KEY_LEN, "00010002000300040005000600070008", idea_ecb, idea_ctr},
        {"gost", BLOCK64, GOST_KEY_LEN,
         "ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", gost_ecb, gost_ctr},
        {"kuz", BLOCK128, KUZ_KEY_LEN,
         "8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef", kuz_ecb, nullptr},
    };
    return list;
}

static const Algo *find_algo(const string &name)
{
    for (const Algo &a : algos())
        if (a.name == name)
            return &a;
    return nullptr;
}

// Ключ из аргумента командной строки (или по умолчанию). false при ошибке.
static bool get_key(const Algo &a, const optional<string> &arg, Bytes &key)
{
    if (!hex2bin(arg ? *arg : a.default_key, key) || key.size() != a.key_len) {
        std::cerr << "ошибка: ключ " << a.name << " должен быть " << a.key_len << " байт ("
                  << a.key_len * 2 << " hex-символов)\n";
        return false;
    }
    return true;
}

static void print_text(const char *label, const Bytes &v)
{
    std::cout << label << ' ';
    std::cout.write(reinterpret_cast<const char *>(v.data()), static_cast<std::streamsize>(v.size()));
    std::cout << '\n';
}

// ---------- команды ----------

// ECB + PKCS#7:  -E<алгоритм> ТЕКСТ [ключ]   и   -D<алгоритм> HEX [ключ]
static int cmd_ecb(const Algo &a, bool decrypt, const string &arg, const optional<string> &key_arg)
{
    Bytes key;
    if (!get_key(a, key_arg, key))
        return 1;

    if (!decrypt) {
        Bytes buf = padding(Bytes(arg.begin(), arg.end()), a.block);
        a.ecb(key, buf, false);
        print_hex("key:", key, false);
        print_hex("enc:", buf, true);
        return 0;
    }

    Bytes buf;
    if (!hex2bin(arg, buf) || buf.empty() || buf.size() % a.block != 0) {
        std::cerr << "ошибка: шифротекст должен быть hex-строкой, кратной " << a.block << " байтам\n";
        return 1;
    }
    a.ecb(key, buf, true);
    if (!unpadding(buf, a.block)) {
        std::cerr << "ошибка: неверное дополнение PKCS#7 (неправильный ключ или данные)\n";
        return 1;
    }
    print_hex("key:", key, false);
    print_text("dec:", buf);
    return 0;
}

// CTR: -Ectr-<алгоритм> ТЕКСТ [ключ [nonce]]  и  -Dctr-<алгоритм> HEX [ключ [nonce]]
static int cmd_ctr(const Algo &a, bool decrypt, const string &arg,
                   const optional<string> &key_arg, const optional<string> &nonce_arg)
{
    if (!a.ctr) {
        std::cerr << "ошибка: для " << a.name << " режим CTR не реализован\n";
        return 1;
    }
    Bytes key;
    if (!get_key(a, key_arg, key))
        return 1;

    Bytes nonce_bytes;
    if (!hex2bin(nonce_arg ? *nonce_arg : NONCE_DEFAULT, nonce_bytes) || nonce_bytes.size() != 4) {
        std::cerr << "ошибка: nonce - 4 байта (8 hex-символов)\n";
        return 1;
    }
    Nonce nonce = to_array<4>(nonce_bytes);

    Bytes buf;
    if (decrypt) {
        if (!hex2bin(arg, buf)) {
            std::cerr << "ошибка: шифротекст должен быть hex-строкой\n";
            return 1;
        }
    } else {
        buf.assign(arg.begin(), arg.end());
    }

    a.ctr(key, nonce, buf);                 // одна и та же операция в обе стороны
    print_hex("key:", key, false);
    print_hex("nonce:", nonce_bytes, false);
    if (decrypt)
        print_text("dec:", buf);
    else
        print_hex("enc:", buf, true);
    return 0;
}

// Имитовставка: -Mgost ТЕКСТ [ключ]
static int cmd_mac(const string &text, const optional<string> &key_arg)
{
    const Algo &a = *find_algo("gost");
    Bytes key;
    if (!get_key(a, key_arg, key))
        return 1;

    Block64 mac = GOST_mac(GOST_keyexp(to_array<GOST_KEY_LEN>(key)), Bytes(text.begin(), text.end()));
    Bytes mac64(mac.begin(), mac.end());
    print_hex("key:", key, false);
    print_hex("mac:", Bytes(mac64.begin(), mac64.begin() + 4), true);   // старшие 32 бита - как в ГОСТ Р 34.13-2015
    print_hex("mac64:", mac64, true);
    return 0;
}

static void usage(const string &prog)
{
    std::cout <<
        "Использование:\n"
        "  " << prog << " -Eidea|gost|kuz ТЕКСТ [ключ_hex]      шифрование (ECB + PKCS#7)\n"
        "  " << prog << " -Didea|gost|kuz HEX   [ключ_hex]      расшифрование\n"
        "  " << prog << " -Ectr-idea|-Ectr-gost ТЕКСТ [ключ [nonce]]   гаммирование (CTR)\n"
        "  " << prog << " -Dctr-idea|-Dctr-gost HEX   [ключ [nonce]]\n"
        "  " << prog << " -Mgost ТЕКСТ [ключ]                   имитовставка ГОСТ (CMAC)\n"
        "  " << prog << " -T                                    тестовые векторы и round-trip\n"
        "  " << prog << " -A [число_испытаний]                  лавинный эффект (по умолчанию 20000)\n"
        "  " << prog << " -B                                    скорость шифрования\n"
        "Алгоритмы: idea, gost (Магма), kuz (Кузнечик). Ключ по умолчанию - тестовый.\n";
}

int main(int argc, char **argv)
{
    string prog = argc > 0 ? argv[0] : "crypto";
    if (argc < 2) {
        usage(prog);
        return 1;
    }
    string cmd = argv[1];
    optional<string> a2, a3, a4;
    if (argc > 2) a2 = argv[2];
    if (argc > 3) a3 = argv[3];
    if (argc > 4) a4 = argv[4];

    if (cmd == "-T")
        return run_selftest() ? 1 : 0;
    if (cmd == "-A") {
        unsigned n = a2 ? static_cast<unsigned>(std::strtoul(a2->c_str(), nullptr, 10)) : 20000;
        run_avalanche(n ? n : 20000);
        return 0;
    }
    if (cmd == "-B") {
        run_bench();
        return 0;
    }
    if (cmd == "-Mgost" && a2)
        return cmd_mac(*a2, a3);

    if (cmd.size() > 2 && cmd[0] == '-' && (cmd[1] == 'E' || cmd[1] == 'D') && a2) {
        bool decrypt = (cmd[1] == 'D');
        string name = cmd.substr(2);
        if (name.compare(0, 4, "ctr-") == 0) {
            if (const Algo *a = find_algo(name.substr(4)))
                return cmd_ctr(*a, decrypt, *a2, a3, a4);
        } else if (const Algo *a = find_algo(name)) {
            return cmd_ecb(*a, decrypt, *a2, a3);
        }
    }

    usage(prog);
    return 1;
}

