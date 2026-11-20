// selftest.h - проверки, лавинный эффект и замер скорости (часть приложения, не библиотеки)
#ifndef SELFTEST_H
#define SELFTEST_H

// Тестовые векторы + round-trip dec(enc(x)) == x. Возвращает число ошибок.
int  run_selftest();

// Лавинный эффект: меняем 1 бит ключа (и отдельно 1 бит открытого текста),
// считаем долю изменившихся бит шифротекста. IDEA, ГОСТ, RC2, Кузнечик.
void run_avalanche(unsigned trials);

// Скорость шифрования в МБ/с.
void run_bench();

#endif
