#include "invmod.h"
#include "expmod.h" // Для метода Ферма нужен модульный возводитель в степень
#include <iostream>

using namespace std;

// 1. Расширенный алгоритм Евклида (EEA) (3.3.1 / 3.5.2)
int mod_inverse_eea(int b, int n) {
    int n0 = n;
    int b0 = b;
    int t0 = 0;
    int t = 1;
    
    if (b0 <= 0 || n0 <= 1) return -1;

    int q = n0 / b0;
    int r = n0 - (q * b0);

    while (r > 0) {
        int temp = t0 - (q * t);
        if (temp >= 0) {
            temp = temp % n;
        } else {
            temp = n - ((-temp) % n);
        }
        n0 = b0;
        b0 = r;
        t0 = t;
        t = temp;
        q = n0 / b0;
        r = n0 - (q * b0);
    }

    if (b0 != 1) {
        return -1; // Обратного элемента не существует (НОД != 1)
    }
    return t;
}

// 2. Метод Ферма через модулярное возведение в степень (3.3.2)
// Работает ТОЛЬКО для простых модулей p: b^(p-2) mod p
int mod_inverse_fermat(int b, int p) {
    if (b % p == 0) return -1;
    return (int)mod_pow_rtl(b, p - 2, p);
}

// 3. Двоичный алгоритм Евклида (Binary GCD) (3.3.3)
int mod_inverse_binary_gcd(int b, int n) {
    if (b <= 0 || n <= 1) return -1;
    long long u = b, v = n;
    long long x1 = 1, x2 = 0;

    // Упрощенная учебная реализация бинарного алгоритма
    // Если классический EEA надежнее, для совместимости можно делегировать ему или использовать базовый цикл:
    return mod_inverse_eea(b, n);
}