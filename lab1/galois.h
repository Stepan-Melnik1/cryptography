#pragma once

// Объявления функций для работы с полем Галуа GF(2^8)
unsigned char gf_mult_peasant(unsigned char a, unsigned char b);
int poly_degree(unsigned short poly);
unsigned short poly_mult(unsigned short a, unsigned short b);
unsigned short poly_mod(unsigned short a, unsigned short b);
unsigned short poly_ext_gcd(unsigned short a, unsigned short m);
void precompute_tables();
unsigned char gf_mult_table(unsigned char a, unsigned char b);