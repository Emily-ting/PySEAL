#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
HE (BFV) Private Aggregation Demo with PySEAL (legacy-friendly)
- Multi-user sum
- Mean (divide on client side after decryption)
- Histogram (no BatchEncoder: one ciphertext per bin)
Tested against older PySEAL wrappers (SEAL 2.3 PoC).
"""

import time, math
import seal
from seal import (EncryptionParameters, SEALContext,
                  KeyGenerator, Encryptor, Decryptor, Evaluator,
                  Plaintext, Ciphertext)

# ---------- small helpers ----------
def try_decode_int(encoder, plain):
    """Best-effort decode for older wrappers."""
    for name in ("decode", "decode_int64", "decode_uint64"):
        fn = getattr(encoder, name, None)
        if fn:
            try:
                return int(fn(plain))
            except Exception:
                pass
    s = None
    if hasattr(plain, "to_string"):
        try: s = plain.to_string()
        except Exception: s = None
    if s is None: s = str(plain)
    try: return int(s.strip())
    except Exception: return None

def setup_bfv(poly_degree=8192, plain_mod=(1<<16), coeff_modulus_bits=2048):
    """Legacy-friendly BFV setup."""
    try:
        parms = EncryptionParameters()
    except TypeError:
        parms = EncryptionParameters(0)

    # poly modulus (two variants across versions)
    ok = False
    for setter in ("set_poly_modulus", "set_poly_modulus_degree"):
        if hasattr(parms, setter):
            try:
                if setter == "set_poly_modulus":
                    getattr(parms, setter)(f"1x^{poly_degree} + 1")
                else:
                    getattr(parms, setter)(poly_degree)
                ok = True
                break
            except Exception:
                pass
    if not ok:
        raise RuntimeError("Could not set polynomial modulus.")

    # coeff modulus helper for old SEAL
    cm_helper = None
    for name in ("coeff_modulus_128", "CoeffModulus_128", "coeff_modulus"):
        if hasattr(seal, name):
            cm_helper = getattr(seal, name); break
    if cm_helper is None:
        raise RuntimeError("Coefficient modulus helper not found.")
    parms.set_coeff_modulus(cm_helper(int(coeff_modulus_bits)))

    # plain modulus (choose > n*max_value to avoid wrap for sums)
    parms.set_plain_modulus(int(plain_mod))

    context = SEALContext(parms)
    keygen   = KeyGenerator(context)
    public_k = keygen.public_key()
    secret_k = keygen.secret_key()
    encryptor = Encryptor(context, public_k)
    decryptor = Decryptor(context, secret_k)
    evaluator = Evaluator(context)

    IntegerEncoder = getattr(seal, "IntegerEncoder")
    try:
        encoder = IntegerEncoder(context.plain_modulus())
    except Exception:
        encoder = IntegerEncoder(context)

    return dict(context=context, keygen=keygen,
                public_key=public_k, secret_key=secret_k,
                encryptor=encryptor, decryptor=decryptor,
                evaluator=evaluator, encoder=encoder)

# ---------- HE building blocks ----------
def he_encrypt_int(enc, encryptor, v:int):
    pt = enc.encode(int(v))
    ct = Ciphertext()
    encryptor.encrypt(pt, ct)
    return ct

def he_sum_ciphertexts(evaluator, cts):
    """Aggregate on the server: repeated adds."""
    if not cts: raise ValueError("no ciphertexts")
    acc = cts[0]
    for ct in cts[1:]:
        out = Ciphertext()
        evaluator.add(acc, ct, out)
        acc = out
    return acc

def he_decrypt_int(enc, decryptor, ct:Ciphertext):
    pt = Plaintext()
    decryptor.decrypt(ct, pt)
    return try_decode_int(enc, pt)

def he_histogram_no_batch(enc, encryptor, evaluator, decryptor, user_bins, K:int):
    """
    Each user uploads K ciphertexts: one-hot (1 at their bin, else 0).
    Server sums per-bin; client decrypts per-bin counts.
    """
    # encrypt one-hot row for one user
    def enc_one_hot(idx:int, K:int):
        row=[]
        for b in range(K):
            pt = enc.encode(1 if b==idx else 0)
            c  = Ciphertext()
            encryptor.encrypt(pt, c)
            row.append(c)
        return row

    # users -> list of rows (each row has K ciphertexts)
    rows = [enc_one_hot(i, K) for i in user_bins]

    # aggregate per bin on server
    agg = [rows[0][b] for b in range(K)]
    for r in rows[1:]:
        for b in range(K):
            out = Ciphertext()
            evaluator.add(agg[b], r[b], out)
            agg[b] = out

    # decrypt
    counts = []
    for b in range(K):
        pt = Plaintext(); decryptor.decrypt(agg[b], pt)
        counts.append(try_decode_int(enc, pt))
    return counts

# ---------- demo ----------
def main():
    # ===== parameters =====
    POLY_DEG = 8192
    # Choose plain_mod so that plain_mod > n * max_value to avoid sum wrap.
    # e.g., if <= 1000 users and each value <= 50, 65536 is fine.
    PLAIN_MOD = 1<<16
    COEFF_BITS = 2048

    print("[HE] setting up BFV...")
    t0 = time.perf_counter()
    env = setup_bfv(POLY_DEG, PLAIN_MOD, COEFF_BITS)
    print("  setup time: %.3f s" % (time.perf_counter()-t0))

    enc, encor, dec, evalr = env["encoder"], env["encryptor"], env["decryptor"], env["evaluator"]

    # ===== Example dataset (replace with your real data) =====
    X = [7, 5, 12, 3, 9]     # multi-user numeric values
    n = len(X)

    # ----- Sum -----
    print("\n[HE] SUM aggregation")
    t1=time.perf_counter()
    cts = [he_encrypt_int(enc, encor, v) for v in X]  # clients encrypt
    Csum = he_sum_ciphertexts(evalr, cts)             # server adds
    he_sum = he_decrypt_int(enc, dec, Csum)           # client decrypts
    t_sum=time.perf_counter()-t1
    print("  true sum =", sum(X), " | HE sum =", he_sum, " | time: %.4f s" % t_sum)

    # ----- Mean (divide on client side) -----
    print("\n[HE] MEAN (divide after decrypt)")
    he_mean = he_sum / n
    print("  true mean =", sum(X)/n, " | HE mean =", he_mean)

    # ----- Histogram (no BatchEncoder) -----
    print("\n[HE] HISTOGRAM (no BatchEncoder)")
    # Example labels for users (0..K-1). Change to your real categorical data.
    K = 4
    user_bins = [0, 1, 3, 1, 1]
    t2=time.perf_counter()
    hist = he_histogram_no_batch(enc, encor, evalr, dec, user_bins, K)
    t_hist=time.perf_counter()-t2
    print("  true hist =", [user_bins.count(b) for b in range(K)])
    print("  HE   hist =", hist, " | time: %.4f s" % t_hist)

    # Notes:
    # - Sum/mean only use additions → 不需要 relinearization。
    # - 若要支援很大的值或很多用戶，請把 PLAIN_MOD 調大，避免取模回繞。
    # - 負數：IntegerEncoder 會以模 t 的平衡表示法編碼負數（-x ↦ t-x）。

if __name__ == "__main__":
    main()
