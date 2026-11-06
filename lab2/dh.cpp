#include "crypto.h"
#include <random>
#include <stdexcept>

// Генерация случайного числа
uint64_t randnumgen(uint64_t min, uint64_t max) {
    static random_device rd;
    static mt19937_64 gen(rd());

    uniform_int_distribution<uint64_t> dist(min, max);

    return dist(gen);
}

// Проверка числа на простоту
bool primenumtest(uint64_t n) {
    if (n < 2)
        return false;

    if (n == 2)
        return true;

    if (n % 2 == 0)
        return false;

    for (uint64_t i = 3; i * i <= n; i += 2) {
        if (n % i == 0)
            return false;
    }

    return true;
}

// Быстрое возведение в степень по модулю
uint64_t exponentiation(uint64_t base, uint64_t exp, uint64_t mod) {
    uint64_t result = 1;

    base %= mod;

    while (exp > 0) {
        if (exp % 2 == 1) {
            result = (result * base) % mod;
        }

        base = (base * base) % mod;
        exp /= 2;
    }

    return result;
}

// Проверка, является ли g первообразным корнем по модулю p
bool isPrimitiveRoot(uint64_t g, uint64_t p) {
    uint64_t n = p - 1;
    uint64_t temp = n;

    for (uint64_t i = 2; i * i <= temp; i++) {
        if (temp % i == 0) {
            if (exponentiation(g, n / i, p) == 1)
                return false;

            while (temp % i == 0)
                temp /= i;
        }
    }

    if (temp > 1) {
        if (exponentiation(g, n / temp, p) == 1)
            return false;
    }

    return true;
}

// Генерация общего ключа Диффи-Хеллмана
DHResult DH_keygen() {
    DHResult result;

    // Генерируем простое число p
    do {
        result.p = randnumgen(1000, 10000);
    } while (!primenumtest(result.p));

    // Генерируем первообразный корень g
    do {
        result.g = randnumgen(2, result.p - 2);
    } while (!isPrimitiveRoot(result.g, result.p));

    // Закрытые ключи Алисы и Боба
    result.a = randnumgen(2, result.p - 2);
    result.b = randnumgen(2, result.p - 2);

    // Открытые ключи
    result.A = exponentiation(result.g, result.a, result.p);
    result.B = exponentiation(result.g, result.b, result.p);

    // Вычисление общего ключа
    uint64_t keyAlice = exponentiation(result.B, result.a, result.p);
    uint64_t keyBob = exponentiation(result.A, result.b, result.p);

    // Проверка совпадения ключей
    if (keyAlice != keyBob) {
        throw runtime_error("DH key generation error!");
    }

    result.key = keyAlice;

    return result;
}

// Нахождение обратного элемента по модулю
int modInverse(int value, int mod) {
    value = (value % mod + mod) % mod;

    for (int i = 1; i < mod; i++) {
        if ((value * i) % mod == 1) {
            return i;
        }
    }

    throw runtime_error("Modular inverse does not exist");
}

// Положительный остаток от деления
int positiveMod(int value, int mod) {
    int result = value % mod;

    if (result < 0) {
        result += mod;
    }

    return result;
}

// Проверка принадлежности точки эллиптической кривой
bool isOnCurve(
    ECPoint P,
    int curveA,
    int curveB,
    int p
) {
    if (P.infinity) {
        return false;
    }

    long long left = (1LL * P.y * P.y) % p;

    long long right = (
        1LL * P.x * P.x * P.x +
        1LL * curveA * P.x +
        curveB
    ) % p;

    return left == right;
}

// Сложение двух точек эллиптической кривой
ECPoint pointAdd(
    ECPoint P,
    ECPoint Q,
    int curveA,
    int p
) {
    // Если P - точка на бесконечности
    if (P.infinity) {
        return Q;
    }

    // Если Q - точка на бесконечности
    if (Q.infinity) {
        return P;
    }

    // Если точки взаимно противоположны
    if (P.x == Q.x &&
        positiveMod(P.y + Q.y, p) == 0) {
        return {0, 0, true};
    }

    int numerator;
    int denominator;

    // Удвоение точки
    if (P.x == Q.x && P.y == Q.y) {

        numerator = positiveMod(
            3 * P.x * P.x + curveA,
            p
        );

        denominator = positiveMod(2 * P.y, p);
    }

    // Сложение разных точек
    else {

        numerator = positiveMod(Q.y - P.y, p);

        denominator = positiveMod(Q.x - P.x, p);
    }

    // Вычисляем наклон прямой
    int lambda = positiveMod(
        numerator * modInverse(denominator, p),
        p
    );

    // Вычисляем координаты новой точки
    int x3 = positiveMod(
        lambda * lambda - P.x - Q.x,
        p
    );

    int y3 = positiveMod(
        lambda * (P.x - x3) - P.y,
        p
    );

    return {x3, y3, false};
}

// Умножение точки на число
ECPoint pointMultiply(
    int scalar,
    ECPoint point,
    int curveA,
    int p
) {
    ECPoint result = {0, 0, true};

    ECPoint current = point;

    while (scalar > 0) {

        if (scalar % 2 == 1) {
            result = pointAdd(
                result,
                current,
                curveA,
                p
            );
        }

        current = pointAdd(
            current,
            current,
            curveA,
            p
        );

        scalar /= 2;
    }

    return result;
}

// Генерация общего ключа ECDH
ECDHResult ECDH_keygen(
    int p,
    int curveA,
    int curveB,
    ECPoint G,
    int n
) {
    ECDHResult result;

    // Проверяем простое число p
    if (p < 5 || p > 1000 || !primenumtest(p)) {
        throw invalid_argument("Invalid prime p");
    }

    // Проверяем коэффициенты кривой
    if (curveA < 0 || curveA >= p ||
        curveB < 0 || curveB >= p) {
        throw invalid_argument("Invalid curve coefficients");
    }

    // Проверяем, что кривая не является вырожденной
    long long discriminant = (
        4LL * curveA * curveA * curveA +
        27LL * curveB * curveB
    ) % p;

    if (discriminant == 0) {
        throw invalid_argument("Invalid elliptic curve");
    }

    // Проверяем координаты точки G
    if (G.x < 0 || G.x >= p ||
        G.y < 0 || G.y >= p ||
        G.infinity || !isOnCurve(G, curveA, curveB, p)) {
        throw invalid_argument("Invalid generator point G");
    }

    // Для нашей учебной реализации используем
    // простой порядок точки
    if (n < 2 || n > 2000 || !primenumtest(n)) {
        throw invalid_argument("Invalid point order n");
    }

    // Проверяем порядок точки G
    ECPoint check = pointMultiply(n, G, curveA, p);

    if (!check.infinity) {
        throw invalid_argument("Incorrect point order n");
    }

    // Сохраняем параметры кривой
    result.p = p;
    result.curveA = curveA;
    result.curveB = curveB;
    result.G = G;
    result.n = n;

    // Генерируем закрытые ключи Алисы и Боба
    result.privateA = randnumgen(1, n - 1);
    result.privateB = randnumgen(1, n - 1);

    // Вычисляем открытый ключ Алисы
    result.publicA = pointMultiply(
        result.privateA,
        G,
        curveA,
        p
    );

    // Вычисляем открытый ключ Боба
    result.publicB = pointMultiply(
        result.privateB,
        G,
        curveA,
        p
    );

    // Алиса вычисляет общий секрет
    ECPoint keyAlice = pointMultiply(
        result.privateA,
        result.publicB,
        curveA,
        p
    );

    // Боб вычисляет общий секрет
    ECPoint keyBob = pointMultiply(
        result.privateB,
        result.publicA,
        curveA,
        p
    );

    // Проверяем совпадение секретных точек
    if (keyAlice.infinity || keyBob.infinity ||
        keyAlice.x != keyBob.x ||
        keyAlice.y != keyBob.y) {
        throw runtime_error("ECDH key generation error!");
    }

    result.sharedKey = keyAlice;

    return result;
}