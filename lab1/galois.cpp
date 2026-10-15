#include "galois.h"
#include <iostream>

using namespace std;

// 1. Крестьянское умножение в GF(2^8) (по стандарту AES, многочлен 0x11B -> 0x1B)
unsigned char gf_mult_peasant(unsigned char a, unsigned char b) {
    unsigned char p = 0;
    for (int i = 0; i < 8; i++) {
        if (b & 1) {
            p ^= a;
        }
        unsigned char hi_bit = (a & 0x80);
        a <<= 1;
        if (hi_bit) {
            a ^= 0x1B; // Редукция по модулю неприводимого многочлена
        }
        b >>= 1;
    }
    return p;
}

// Вспомогательные функции для многочленов
int poly_degree(unsigned short poly) {
    int deg = -1;
    while (poly > 0) {
        deg++;
        poly >>= 1;
    }
    return deg;
}

unsigned short poly_mult(unsigned short a, unsigned short b) {
    unsigned short p = 0;
    while (b > 0) {
        if (b & 1) p ^= a;
        a <<= 1;
        b >>= 1;
    }
    return p;
}

unsigned short poly_mod(unsigned short a, unsigned short b) {
    int deg_b = poly_degree(b);
    if (deg_b < 0) return 0;
    int deg_a = poly_degree(a);
    while (deg_a >= deg_b) {
        a ^= (b << (deg_a - deg_b));
        deg_a = poly_degree(a);
    }
    return a;
}

// 2. Расширенный алгоритм Евклида для многочленов
unsigned short poly_ext_gcd(unsigned short a, unsigned short m) {
    unsigned short old_r = m, r = a;
    unsigned short old_s = 0, s = 1;

    while (r != 0) {
        unsigned short q = 0;
        int deg_r = poly_degree(r);
        int deg_old = poly_degree(old_r);
        while (deg_old >= deg_r && deg_r >= 0) {
            int shift = deg_old - deg_r;
            q ^= (1 << shift);
            old_r ^= (r << shift);
            deg_old = poly_degree(old_r);
        }
    }
    return s;
}

// 3. Таблицы логарифмов и антилогарифмов
const unsigned char GENERATOR = 0x03;
unsigned char log_table[256];
unsigned char antilog_table[256];

void precompute_tables() {
    unsigned char b = 1;
    for (int i = 0; i < 255; i++) {
        antilog_table[i] = b;
        log_table[b] = i;
        b = gf_mult_peasant(b, GENERATOR);
    }
    antilog_table[255] = antilog_table[0];
}

unsigned char gf_mult_table(unsigned char a, unsigned char b) {
    if (a == 0 || b == 0) return 0;
    int sum_log = (int)log_table[a] + (int)log_table[b];
    return antilog_table[sum_log % 255];
}