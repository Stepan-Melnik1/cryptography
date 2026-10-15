#pragma once

int brute_force_dlog(int g, int h, int p, int limit);
int bsgs_dlog(int g, int h, int p);
int pollard_rho_dlog(int g, int h, int p, int n);
int pohlig_hellman_dlog(int g, int h, int p, int n);
int index_calculus_dlog(int g, int h, int p);