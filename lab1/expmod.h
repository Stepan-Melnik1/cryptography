#pragma once

long long mod_pow_rtl(long long b, long long e, long long m);
long long mod_pow_ltr(long long b, long long e, long long m);
long long montgomery_ladder(long long b, long long e, long long m);
long long sliding_window_pow(long long b, long long e, long long m, int k);