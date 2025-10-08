#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PySEAL benchmark script (legacy wrapper friendly)
- Works without `scheme_type`
- Handles legacy `generate_evaluation_keys` signatures
- Handles legacy IntegerEncoder without `.decode` (tries multiple decoders or skips correctness)
- BFV always; CKKS only if encoder exists
"""

import argparse, math, random, statistics, time
from typing import List, Optional

try:
    import seal
    from seal import (EncryptionParameters, SEALContext,
                      KeyGenerator, Encryptor, Decryptor, Evaluator,
                      Plaintext, Ciphertext)
except Exception as e:
    raise SystemExit("[ERROR] Could not import PySEAL 'seal' module: %r" % (e,))

def bench(fn, repeat=30, warmup=5):
    for _ in range(max(0, warmup)):
        fn()
    xs = []
    for _ in range(repeat):
        t0 = time.perf_counter()
        fn()
        xs.append(time.perf_counter() - t0)
    xs.sort()
    return {
        "median_s": (xs[len(xs)//2] if xs else float('nan')),
        "mean_s": (sum(xs)/len(xs) if xs else float('nan')),
        "p90_s": (xs[int(0.9*(len(xs)-1))] if xs else float('nan'))
    }

def fmt(x): return f"{x:.6f}"

# ---------- helpers ----------
def try_decode_int(encoder, plain) -> Optional[int]:
    """Try various legacy decoder names; return None if not decodable."""
    for name in ("decode", "decode_int64", "decode_uint64"):
        fn = getattr(encoder, name, None)
        if fn:
            try:
                return int(fn(plain))
            except Exception:
                pass
    # String fallback (best-effort)
    s = None
    if hasattr(plain, "to_string"):
        try:
            s = plain.to_string()
        except Exception:
            s = None
    if s is None:
        s = str(plain)
    try:
        return int(s.strip())
    except Exception:
        return None

# ---------- DP baseline ----------
def laplace_noise(scale: float) -> float:
    u = random.random() - 0.5
    return -scale * (1 if u >= 0 else -1) * math.log(1 - 2*abs(u) + 1e-12)

def dp_release_sum(vals: List[float], epsilon: float) -> float:
    sens = 1.0
    return sum(vals) + laplace_noise(sens/epsilon)

# ---------- BFV (legacy-friendly) ----------
def setup_bfv_legacy(poly_degree=8192, plain_modulus=(1<<16), coeff_modulus_bits=2048):
    # Construct parms WITHOUT scheme_type
    try:
        parms = EncryptionParameters()
    except TypeError:
        parms = EncryptionParameters(0)

    # Poly modulus
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
        raise RuntimeError("Could not set poly modulus on EncryptionParameters (legacy wrapper mismatch).")

    # Coeff modulus helper
    cm_helper = None
    for name in ("coeff_modulus_128", "CoeffModulus_128", "coeff_modulus"):
        if hasattr(seal, name):
            cm_helper = getattr(seal, name)
            break
    if cm_helper is None:
        raise RuntimeError("Could not find coeff_modulus helper (e.g., seal.coeff_modulus_128).")

    parms.set_coeff_modulus(cm_helper(int(coeff_modulus_bits)))
    parms.set_plain_modulus(int(plain_modulus))

    context = SEALContext(parms)
    keygen = KeyGenerator(context)
    public_key = keygen.public_key()
    secret_key = keygen.secret_key()

    encryptor = Encryptor(context, public_key)
    decryptor = Decryptor(context, secret_key)
    evaluator = Evaluator(context)

    # Integer encoder
    IntegerEncoder = getattr(seal, "IntegerEncoder", None)
    if IntegerEncoder is None:
        raise RuntimeError("IntegerEncoder not found in this PySEAL build.")
    try:
        encoder = IntegerEncoder(context.plain_modulus())
    except Exception:
        encoder = IntegerEncoder(context)

    # Try to obtain relinearization keys
    relin_keys = None
    if hasattr(keygen, "relin_keys"):
        rk = keygen.relin_keys
        relin_keys = rk() if callable(rk) else rk
    elif hasattr(seal, "EvaluationKeys") and hasattr(keygen, "generate_evaluation_keys"):
        evk = seal.EvaluationKeys()
        ok = False
        for args in [(16, 1, evk), (32, 1, evk), (16, evk), (32, evk)]:
            try:
                keygen.generate_evaluation_keys(*args)
                relin_keys = evk
                ok = True
                break
            except Exception:
                continue
        if not ok:
            relin_keys = None

    return context, keygen, encryptor, decryptor, evaluator, encoder, relin_keys

def bfv_microbench(context, encryptor, decryptor, evaluator, encoder, relin_keys,
                   repeat=30, pair=(7,5)):
    x, y = pair
    # encode
    px = encoder.encode(x); py = encoder.encode(y)
    # encrypt
    cx = Ciphertext(); cy = Ciphertext()
    encryptor.encrypt(px, cx); encryptor.encrypt(py, cy)

    results = {}
    # timings
    results["bfv_encrypt"] = bench(lambda: (lambda tmp=Ciphertext(): encryptor.encrypt(px, tmp))(), repeat=repeat)
    results["bfv_add"] = bench(lambda: (lambda out=Ciphertext(): evaluator.add(cx, cy, out))(), repeat=repeat)

    def mul_once():
        out = Ciphertext()
        evaluator.multiply(cx, cy, out)
        if relin_keys is not None:
            if hasattr(evaluator, "relinearize"):
                evaluator.relinearize(out, relin_keys, out)
            elif hasattr(evaluator, "relinearise"):
                evaluator.relinearise(out, relin_keys, out)
    results["bfv_multiply_relin"] = bench(mul_once, repeat=repeat)

    # correctness (best-effort if decode available)
    try:
        c_add = Ciphertext(); evaluator.add(cx, cy, c_add)
        c_mul = Ciphertext(); evaluator.multiply(cx, cy, c_mul)
        if relin_keys is not None:
            if hasattr(evaluator, "relinearize"):
                evaluator.relinearize(c_mul, relin_keys, c_mul)
            elif hasattr(evaluator, "relinearise"):
                evaluator.relinearise(c_mul, relin_keys, c_mul)

        px2 = Plaintext(); decryptor.decrypt(cx, px2)
        py2 = Plaintext(); decryptor.decrypt(cy, py2)
        padd = Plaintext(); decryptor.decrypt(c_add, padd)
        pmul = Plaintext(); decryptor.decrypt(c_mul, pmul)

        rx = try_decode_int(encoder, px2)
        ry = try_decode_int(encoder, py2)
        r_add = try_decode_int(encoder, padd)
        r_mul = try_decode_int(encoder, pmul)

        results["bfv_correct_x"] = rx
        results["bfv_correct_y"] = ry
        results["bfv_correct_add"] = r_add
        results["bfv_correct_mul"] = r_mul
    except Exception as e:
        results["bfv_correct_x"] = results["bfv_correct_y"] = None
        results["bfv_correct_add"] = results["bfv_correct_mul"] = None

    return results

# ---------- CKKS (only if present) ----------
def ckks_available():
    for name in ("CKKSEncoder", "CkkSEncoder", "CkksEncoder"):
        if hasattr(seal, name):
            return name
    return None

def setup_ckks_legacy(poly_degree=8192, coeff_modulus_bits=2048, scale_bits=40):
    try:
        parms = EncryptionParameters()
    except TypeError:
        parms = EncryptionParameters(0)

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
        raise RuntimeError("Could not set poly modulus (CKKS).")

    cm_helper = None
    for name in ("coeff_modulus_128", "CoeffModulus_128", "coeff_modulus"):
        if hasattr(seal, name):
            cm_helper = getattr(seal, name)
            break
    if cm_helper is None:
        raise RuntimeError("Could not find coeff_modulus helper for CKKS.")
    parms.set_coeff_modulus(cm_helper(int(coeff_modulus_bits)))

    context = SEALContext(parms)
    keygen = KeyGenerator(context)
    public_key = keygen.public_key()
    secret_key = keygen.secret_key()
    encryptor = Encryptor(context, public_key)
    decryptor = Decryptor(context, secret_key)
    evaluator = Evaluator(context)

    enc_name = ckks_available()
    CKKSEncoder = getattr(seal, enc_name)
    encoder = CKKSEncoder(context)

    relin_keys = None
    if hasattr(keygen, "relin_keys"):
        rk = keygen.relin_keys
        relin_keys = rk() if callable(rk) else rk
    elif hasattr(seal, "EvaluationKeys") and hasattr(keygen, "generate_evaluation_keys"):
        evk = seal.EvaluationKeys()
        ok = False
        for args in [(16, 1, evk), (32, 1, evk), (16, evk), (32, evk)]:
            try:
                keygen.generate_evaluation_keys(*args)
                relin_keys = evk
                ok = True
                break
            except Exception:
                continue
        if not ok:
            relin_keys = None

    scale = float(2 ** scale_bits)
    return context, keygen, encryptor, decryptor, evaluator, encoder, relin_keys, scale

def ckks_microbench(context, encryptor, decryptor, evaluator, encoder, relin_keys,
                    scale, repeat=30, data=None):
    if data is None:
        data = [3.5, -2.2, 0.75, math.pi, 1.2345, -0.3333, 10.0, 0.0]

    plain = Plaintext(); encoder.encode(data, scale, plain)
    c = Ciphertext(); encryptor.encrypt(plain, c)
    p1 = Plaintext(); encoder.encode([1.0]*len(data), scale, p1)

    results = {}
    results["ckks_encrypt"] = bench(lambda: (lambda tmp=Ciphertext(): encryptor.encrypt(plain, tmp))(), repeat=repeat)
    results["ckks_add_plain"] = bench(lambda: (lambda out=Ciphertext(): evaluator.add_plain(c, p1, out))(), repeat=repeat)

    def mul_sq():
        out = Ciphertext()
        evaluator.multiply(c, c, out)
        if relin_keys is not None:
            if hasattr(evaluator, "relinearize"):
                evaluator.relinearize(out, relin_keys, out)
            elif hasattr(evaluator, "relinearise"):
                evaluator.relinearise(out, relin_keys, out)
        for name in ("rescale_to_next", "rescaleToNext", "rescale"):
            if hasattr(evaluator, name):
                getattr(evaluator, name)(out, out)
                break
    results["ckks_multiply_relin_rescale"] = bench(mul_sq, repeat=repeat)

    c_add = Ciphertext(); evaluator.add_plain(c, p1, c_add)
    c_sq = Ciphertext(); evaluator.multiply(c, c, c_sq)
    if relin_keys is not None:
        if hasattr(evaluator, "relinearize"):
            evaluator.relinearize(c_sq, relin_keys, c_sq)
        elif hasattr(evaluator, "relinearise"):
            evaluator.relinearise(c_sq, relin_keys, c_sq)
    for name in ("rescale_to_next", "rescaleToNext", "rescale"):
        if hasattr(evaluator, name):
            getattr(evaluator, name)(c_sq, c_sq)
            break

    p_add = Plaintext(); decryptor.decrypt(c_add, p_add)
    out_add = []; encoder.decode(p_add, out_add)

    p_sq = Plaintext(); decryptor.decrypt(c_sq, p_sq)
    out_sq = []; encoder.decode(p_sq, out_sq)

    truth_add = [v + 1.0 for v in data]
    truth_sq = [v * v for v in data]

    def mae(a, b): return sum(abs(x-y) for x,y in zip(a,b))/len(a)
    def rmse(a, b): return math.sqrt(sum((x-y)**2 for x,y in zip(a,b))/len(a))

    results["ckks_add_mae"] = mae(out_add, truth_add)
    results["ckks_add_rmse"] = rmse(out_add, truth_add)
    results["ckks_mul_mae"] = mae(out_sq, truth_sq)
    results["ckks_mul_rmse"] = rmse(out_sq, truth_sq)
    results["ckks_sample_add"] = out_add[:4]
    results["ckks_sample_mul"] = out_sq[:4]
    return results

def ckks_encoder_name():
    for n in ("CKKSEncoder", "CkkSEncoder", "CkksEncoder"):
        if hasattr(seal, n): return n

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scheme", choices=["bfv","ckks","all"], default="all")
    ap.add_argument("--repeat", type=int, default=30)
    ap.add_argument("--poly-degree", type=int, default=8192)
    ap.add_argument("--coeff-bits", type=int, default=2048)
    ap.add_argument("--plain-mod", type=int, default=(1<<16))
    ap.add_argument("--scale-bits", type=int, default=40)
    ap.add_argument("--dp-epsilon", type=float, default=1.0)
    args = ap.parse_args()

    # BFV
    if args.scheme in ("bfv","all"):
        print("\n[ BFV ] setting up (legacy-friendly)...")
        try:
            ctx, kg, enc, dec, ev, encdr, rlk = setup_bfv_legacy(
                poly_degree=args.poly_degree,
                plain_modulus=args.plain_mod,
                coeff_modulus_bits=args.coeff_bits
            )
            print("[ BFV ] running...")
            res = bfv_microbench(ctx, enc, dec, ev, encdr, rlk, repeat=args.repeat)
            print("  encrypt  median/mean/p90 (s):", fmt(res['bfv_encrypt']['median_s']), fmt(res['bfv_encrypt']['mean_s']), fmt(res['bfv_encrypt']['p90_s']))
            print("  add      median/mean/p90 (s):", fmt(res['bfv_add']['median_s']), fmt(res['bfv_add']['mean_s']), fmt(res['bfv_add']['p90_s']))
            print("  mul+relin median/mean/p90(s):", fmt(res['bfv_multiply_relin']['median_s']), fmt(res['bfv_multiply_relin']['mean_s']), fmt(res['bfv_multiply_relin']['p90_s']))
            if res.get('bfv_correct_add') is not None:
                print("  correctness (x,y,add,mul):", res['bfv_correct_x'], res['bfv_correct_y'], res['bfv_correct_add'], res['bfv_correct_mul'])
            else:
                print("  correctness check skipped (encoder has no decode method).")
        except Exception as e:
            print("[ BFV ] ERROR:", e)

    # CKKS (attempt only if encoder exists)
    if ckks_available() and args.scheme in ("ckks","all"):
        print("\n[ CKKS ] setting up (legacy-friendly)...")
        try:
            ctx, kg, enc, dec, ev, encdr, rlk, scale = setup_ckks_legacy(
                poly_degree=args.poly_degree,
                coeff_modulus_bits=args.coeff_bits,
                scale_bits=args.scale_bits
            )
            print("[ CKKS ] running...")
            res = ckks_microbench(ctx, enc, dec, ev, encdr, rlk, scale, repeat=args.repeat)
            print("  encrypt       median/mean/p90 (s):", fmt(res['ckks_encrypt']['median_s']), fmt(res['ckks_encrypt']['mean_s']), fmt(res['ckks_encrypt']['p90_s']))
            print("  add_plain     median/mean/p90 (s):", fmt(res['ckks_add_plain']['median_s']), fmt(res['ckks_add_plain']['mean_s']), fmt(res['ckks_add_plain']['p90_s']))
            print("  mul+relin+res median/mean/p90 (s):", fmt(res['ckks_multiply_relin_rescale']['median_s']), fmt(res['ckks_multiply_relin_rescale']['mean_s']), fmt(res['ckks_multiply_relin_rescale']['p90_s']))
            print("  accuracy (MAE/RMSE): add=%.3e/%.3e, mul=%.3e/%.3e" % (
                res['ckks_add_mae'], res['ckks_add_rmse'], res['ckks_mul_mae'], res['ckks_mul_rmse']
            ))
            print("  sample add outputs:", res['ckks_sample_add'])
            print("  sample mul outputs:", res['ckks_sample_mul'])
        except Exception as e:
            print("[ CKKS ] ERROR (skipping):", e)
    elif args.scheme in ("ckks","all"):
        print("\n[ CKKS ] Encoder not found in this PySEAL build. Skipping CKKS.")

    # DP baseline
    if args.scheme in ("all",):
        print("\n[ DP ] baseline...")
        values = [random.uniform(-5, 5) for _ in range(1000)]
        true_sum = sum(values)
        errs = [abs(dp_release_sum(values, args.dp_epsilon) - true_sum) for _ in range(max(100, args.repeat))]
        mae = sum(errs)/len(errs)
        rmse = math.sqrt(sum(e*e for e in errs)/len(errs))
        t = bench(lambda: dp_release_sum(values, args.dp_epsilon), repeat=args.repeat)
        print("  epsilon =", args.dp_epsilon, " MAE=%.3e RMSE=%.3e" % (mae, rmse))
        print("  timing  median/mean/p90 (s):", fmt(t['median_s']), fmt(t['mean_s']), fmt(t['p90_s']))

if __name__ == "__main__":
    main()
