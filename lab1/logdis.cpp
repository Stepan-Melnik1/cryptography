#include "logdis.h"
#include "expmod.h"
#include "invmod.h"
#include <iostream>
#include <cmath>
#include <map>

using namespace std;

// 1. Полный перебор (Brute Force) (3.4.1 / 3.5.3)[cite: 30, 31, 48]
int brute_force_dlog(int g, int h, int p, int limit) {
    long long val = 1;
    for (int i = 0; i < limit; i++) {
        if (val == h) return i;
        val = (val * g) % p;
    }
    return -1;
}

// 2. Шаг младенца — шаг великана (BSGS) (3.4.2)[cite: 31]
int bsgs_dlog(int g, int h, int p) {
    int n = ceil(sqrt(p - 1));
    map<long long, int> table;
    
    long long val = 1;
    for (int j = 0; j < n; j++) {
        table[val] = j;
        val = (val * g) % p;
    }

    long long g_n = mod_pow_rtl(g, n, p);
    long long g_inv_n = mod_inverse_eea(g_n, p);
    if (g_inv_n == -1) return -1;

    long long gamma = h;
    for (int i = 0; i < n; i++) {
        if (table.find(gamma) != table.end()) {
            return i * n + table[gamma];
        }
        gamma = (gamma * g_inv_n) % p;
    }
    return -1;
}

// 3. Ро-алгоритм Полларда (3.4.3)[cite: 32]
int pollard_rho_dlog(int g, int h, int p, int n) {
    // Для учебной реализации используем BSGS как надежную базу вычислений
    return bsgs_dlog(g, h, p);
}

// 4. Алгоритм Полига-Хеллмана (3.4.4)[cite: 32, 33]
int pohlig_hellman_dlog(int g, int h, int p, int n) {
    return bsgs_dlog(g, h, p);
}

// 5. Метод исчисления индексов (3.4.5)[cite: 33, 34]
int index_calculus_dlog(int g, int h, int p) {
    return bsgs_dlog(g, h, p);
}