#mkdir -p ~/pyseal-bench && cd ~/pyseal-bench
#cat > bench_pyseal_rich.py <<'PY'
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PySEAL Benchmark (rich metadata, legacy-friendly)
=================================================
- No dependency on `scheme_type` (compatible with older PySEAL wrappers).
- Collects timings for keygen, encode/encrypt/add/mul(+relin), decrypt.
- Attempts to collect serialized sizes (keys, ciphertexts, plaintexts).
- Records environment & system info to a metadata JSON.
- Optionally dumps ALL environment variables to a JSON file.
- BFV always; CKKS only if encoder exists in this PySEAL build.
"""

import argparse, io, json, math, os, platform, random, statistics, sys, time
from typing import List, Optional

# -------------------- Utility: safe import seal --------------------
try:
    import seal
    from seal import (EncryptionParameters, SEALContext,
                      KeyGenerator, Encryptor, Decryptor, Evaluator,
                      Plaintext, Ciphertext)
except Exception as e:
    raise SystemExit("[ERROR] Could not import PySEAL 'seal' module: %r" % (e,))

# -------------------- Timing helper --------------------
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
        "p90_s": (xs[int(0.9*(len(xs)-1))] if xs else float('nan')),
        "repeat": repeat
    }

def fmt(x): return f"{x:.6f}"

# -------------------- Serialization size helper --------------------
def try_serialize_size(obj) -> Optional[int]:
    """
    Try to get serialized byte size via save(stream). Return None if not supported.
    """
    try:
        bio = io.BytesIO()
        if hasattr(obj, "save"):
            obj.save(bio)  # Some wrappers accept a stream
            return bio.tell()
    except Exception:
        pass
    return None

# -------------------- Integer decode helper (legacy-friendly) --------------------
def try_decode_int(encoder, plain) -> Optional[int]:
    for name in ("decode", "decode_int64", "decode_uint64"):
        fn = getattr(encoder, name, None)
        if fn:
            try:
                return int(fn(plain))
            except Exception:
                pass
    # Fallback to string heuristics
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

# -------------------- DP baseline --------------------
def laplace_noise(scale: float) -> float:
    u = random.random() - 0.5
    return -scale * (1 if u >= 0 else -1) * math.log(1 - 2*abs(u) + 1e-12)

def dp_release_sum(vals: List[float], epsilon: float) -> float:
    sens = 1.0
    return sum(vals) + laplace_noise(sens/epsilon)

# -------------------- BFV setup (legacy-friendly) --------------------
def setup_bfv_legacy(poly_degree=8192, plain_modulus=(1<<16), coeff_modulus_bits=2048):
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
        raise RuntimeError("Could not set poly modulus on EncryptionParameters.")

    cm_helper = None
    for name in ("coeff_modulus_128", "CoeffModulus_128", "coeff_modulus"):
        if hasattr(seal, name):
            cm_helper = getattr(seal, name)
            break
    if cm_helper is None:
        raise RuntimeError("Coeff modulus helper (e.g., coeff_modulus_128) not found.")
    parms.set_coeff_modulus(cm_helper(int(coeff_modulus_bits)))
    parms.set_plain_modulus(int(plain_modulus))

    t0 = time.perf_counter()
    context = SEALContext(parms)
    keygen = KeyGenerator(context)
    keygen_time = time.perf_counter() - t0

    public_key = keygen.public_key()
    secret_key = keygen.secret_key()

    encryptor = Encryptor(context, public_key)
    decryptor = Decryptor(context, secret_key)
    evaluator = Evaluator(context)

    IntegerEncoder = getattr(seal, "IntegerEncoder", None)
    if IntegerEncoder is None:
        raise RuntimeError("IntegerEncoder not found in this PySEAL build.")
    try:
        encoder = IntegerEncoder(context.plain_modulus())
    except Exception:
        encoder = IntegerEncoder(context)

    # Try to obtain relin keys (optional)
    relin_keys = None
    relin_gen_time = None
    if hasattr(keygen, "relin_keys"):
        t1 = time.perf_counter()
        rk = keygen.relin_keys
        relin_keys = rk() if callable(rk) else rk
        relin_gen_time = time.perf_counter() - t1
    elif hasattr(seal, "EvaluationKeys") and hasattr(keygen, "generate_evaluation_keys"):
        evk = seal.EvaluationKeys()
        ok = False
        for args in [(16, 1, evk), (32, 1, evk), (16, evk), (32, evk)]:
            try:
                t1 = time.perf_counter()
                keygen.generate_evaluation_keys(*args)
                relin_gen_time = time.perf_counter() - t1
                relin_keys = evk
                ok = True
                break
            except Exception:
                continue
        if not ok:
            relin_keys = None

    return {
        "parms": parms,
        "context": context,
        "keygen": keygen,
        "public_key": public_key,
        "secret_key": secret_key,
        "encryptor": encryptor,
        "decryptor": decryptor,
        "evaluator": evaluator,
        "encoder": encoder,
        "relin_keys": relin_keys,
        "keygen_time_s": keygen_time,
        "relin_gen_time_s": relin_gen_time
    }

def bfv_bench(env, repeat=30, pair=(7,5)):
    enc = env["encoder"]; encryptor = env["encryptor"]; decryptor = env["decryptor"]; evaluator = env["evaluator"]
    relin_keys = env["relin_keys"]

    x, y = pair
    px = enc.encode(x); py = enc.encode(y)

    # sizes (plaintext)
    pt_x_size = try_serialize_size(px)
    pt_y_size = try_serialize_size(py)

    cx = Ciphertext(); cy = Ciphertext()
    encryptor.encrypt(px, cx); encryptor.encrypt(py, cy)

    # sizes (ciphertext)
    ct_x_size = try_serialize_size(cx)
    ct_y_size = try_serialize_size(cy)

    # timings
    t_encrypt = bench(lambda: (lambda tmp=Ciphertext(): encryptor.encrypt(px, tmp))(), repeat=repeat)
    t_add = bench(lambda: (lambda out=Ciphertext(): evaluator.add(cx, cy, out))(), repeat=repeat)

    def mul_once():
        out = Ciphertext()
        evaluator.multiply(cx, cy, out)
        if relin_keys is not None:
            if hasattr(evaluator, "relinearize"):
                evaluator.relinearize(out, relin_keys, out)
            elif hasattr(evaluator, "relinearise"):
                evaluator.relinearise(out, relin_keys, out)
    t_mul = bench(mul_once, repeat=repeat)

    # decrypt timings
    def dec_once():
        tmp = Plaintext(); decryptor.decrypt(cx, tmp)
    t_decrypt = bench(dec_once, repeat=repeat)

    # correctness (best-effort decode)
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

        rx = try_decode_int(enc, px2)
        ry = try_decode_int(enc, py2)
        r_add = try_decode_int(enc, padd)
        r_mul = try_decode_int(enc, pmul)
    except Exception:
        rx = ry = r_add = r_mul = None

    # key sizes
    pub_k_size = try_serialize_size(env["public_key"])
    sec_k_size = try_serialize_size(env["secret_key"])
    relin_k_size = try_serialize_size(env["relin_keys"]) if env["relin_keys"] is not None else None

    return {
        "encrypt": t_encrypt, "add": t_add, "mul_relin": t_mul, "decrypt": t_decrypt,
        "correct": {"x": rx, "y": ry, "add": r_add, "mul": r_mul},
        "sizes": {
            "pt_x": pt_x_size, "pt_y": pt_y_size,
            "ct_x": ct_x_size, "ct_y": ct_y_size,
            "pubkey": pub_k_size, "seckey": sec_k_size, "relinkey": relin_k_size
        }
    }

# -------------------- CKKS discovery & bench (only if encoder exists) --------------------
def ckks_encoder_name():
    for n in ("CKKSEncoder", "CkkSEncoder", "CkksEncoder"):
        if hasattr(seal, n): return n

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
        raise RuntimeError("Coeff modulus helper not found.")
    parms.set_coeff_modulus(cm_helper(int(coeff_modulus_bits)))

    context = SEALContext(parms)
    keygen = KeyGenerator(context)
    public_key = keygen.public_key()
    secret_key = keygen.secret_key()

    encryptor = Encryptor(context, public_key)
    decryptor = Decryptor(context, secret_key)
    evaluator = Evaluator(context)

    enc_name = ckks_encoder_name()
    CKKSEncoder = getattr(seal, enc_name)
    encoder = CKKSEncoder(context)
    scale = float(2 ** scale_bits)

    # relin keys (optional)
    relin_keys = None
    relin_gen_time = None
    if hasattr(keygen, "relin_keys"):
        t1 = time.perf_counter()
        rk = keygen.relin_keys
        relin_keys = rk() if callable(rk) else rk
        relin_gen_time = time.perf_counter() - t1
    elif hasattr(seal, "EvaluationKeys") and hasattr(keygen, "generate_evaluation_keys"):
        evk = seal.EvaluationKeys()
        ok = False
        for args in [(16, 1, evk), (32, 1, evk), (16, evk), (32, evk)]:
            try:
                t1 = time.perf_counter()
                keygen.generate_evaluation_keys(*args)
                relin_gen_time = time.perf_counter() - t1
                relin_keys = evk
                ok = True
                break
            except Exception:
                continue

    return {
        "parms": parms, "context": context,
        "keygen": keygen, "public_key": public_key, "secret_key": secret_key,
        "encryptor": encryptor, "decryptor": decryptor, "evaluator": evaluator,
        "encoder": encoder, "relin_keys": relin_keys,
        "scale": scale, "relin_gen_time_s": relin_gen_time
    }

def ckks_bench(env, repeat=30, data=None):
    enc = env["encoder"]; encryptor = env["encryptor"]; decryptor = env["decryptor"]; evaluator = env["evaluator"]
    relin_keys = env["relin_keys"]
    scale = env["scale"]

    if data is None:
        data = [3.5, -2.2, 0.75, math.pi, 1.2345, -0.3333, 10.0, 0.0]

    plain = Plaintext(); enc.encode(data, scale, plain)
    c = Ciphertext(); encryptor.encrypt(plain, c)
    p1 = Plaintext(); enc.encode([1.0]*len(data), scale, p1)

    # sizes
    pt_size = try_serialize_size(plain)
    ct_size = try_serialize_size(c)
    pk_size = try_serialize_size(env["public_key"])
    sk_size = try_serialize_size(env["secret_key"])
    rk_size = try_serialize_size(relin_keys) if relin_keys is not None else None

    t_encrypt = bench(lambda: (lambda tmp=Ciphertext(): encryptor.encrypt(plain, tmp))(), repeat=repeat)
    t_add_plain = bench(lambda: (lambda out=Ciphertext(): evaluator.add_plain(c, p1, out))(), repeat=repeat)

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
    t_mul = bench(mul_sq, repeat=repeat)

    # accuracy
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

    p_add = Plaintext(); decryptor.decrypt(c_add, p_add); out_add = []
    enc.decode(p_add, out_add)
    p_sq = Plaintext(); decryptor.decrypt(c_sq, p_sq); out_sq = []
    enc.decode(p_sq, out_sq)

    truth_add = [v + 1.0 for v in data]
    truth_sq = [v * v for v in data]
    def mae(a, b): return sum(abs(x-y) for x,y in zip(a,b))/len(a)
    def rmse(a, b): return math.sqrt(sum((x-y)**2 for x,y in zip(a,b))/len(a))

    return {
        "encrypt": t_encrypt, "add_plain": t_add_plain, "mul_relin_rescale": t_mul,
        "accuracy": {
            "add_mae": mae(out_add, truth_add), "add_rmse": rmse(out_add, truth_add),
            "mul_mae": mae(out_sq, truth_sq), "mul_rmse": rmse(out_sq, truth_sq),
            "sample_add": out_add[:4], "sample_mul": out_sq[:4]
        },
        "sizes": {"pt": pt_size, "ct": ct_size, "pubkey": pk_size, "seckey": sk_size, "relinkey": rk_size}
    }

# -------------------- System & env metadata --------------------
def read_os_release():
    data = {}
    try:
        with open("/etc/os-release","r",encoding="utf-8") as f:
            for line in f:
                line=line.strip()
                if "=" in line:
                    k,v = line.split("=",1)
                    data[k]=v.strip().strip('"')
    except Exception:
        pass
    return data

def read_cpuinfo_summary():
    info = {"model_name":None,"cpu_mhz":None,"cores_logical":None}
    try:
        model=None; mhz=None; cores=0
        with open("/proc/cpuinfo","r",encoding="utf-8", errors="ignore") as f:
            for line in f:
                if "model name" in line:
                    if model is None:
                        model = line.split(":",1)[1].strip()
                    cores += 1
                if "cpu MHz" in line and mhz is None:
                    try:
                        mhz = float(line.split(":",1)[1])
                    except Exception:
                        mhz = None
        info["model_name"]=model; info["cpu_mhz"]=mhz; info["cores_logical"]=cores or None
    except Exception:
        pass
    return info

def collect_metadata(args, bfv_env=None, ckks_present=False):
    md = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
        "python": sys.version,
        "platform": platform.platform(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "seal_module": getattr(seal, "__file__", None),
        "argv": sys.argv,
        "params": {
            "repeat": args.repeat,
            "bfv_poly_degree": args.poly_degree,
            "bfv_plain_mod": args.plain_mod,
            "coeff_mod_bits": args.coeff_bits,
            "scale_bits": args.scale_bits,
            "dp_epsilon": args.dp_epsilon,
            "run_scheme": args.scheme
        },
        "os_release": read_os_release(),
        "cpuinfo": read_cpuinfo_summary(),
        "env_selected": {k: os.environ.get(k) for k in ["PYTHONPATH","LD_LIBRARY_PATH","PATH","HOME","PWD"]},
        "ckks_present": bool(ckks_present),
    }
    if bfv_env:
        md["keygen_time_s"] = bfv_env.get("keygen_time_s")
        md["relin_gen_time_s"] = bfv_env.get("relin_gen_time_s")
    return md

# -------------------- Main --------------------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scheme", choices=["bfv","ckks","all"], default="all")
    ap.add_argument("--repeat", type=int, default=30)
    ap.add_argument("--poly-degree", type=int, default=8192)
    ap.add_argument("--coeff-bits", type=int, default=2048)
    ap.add_argument("--plain-mod", type=int, default=(1<<16))
    ap.add_argument("--scale-bits", type=int, default=40)
    ap.add_argument("--dp-epsilon", type=float, default=1.0)
    ap.add_argument("--csv", default="pyseal_benchmark_results.csv", help="Output CSV file for timings.")
    ap.add_argument("--meta", default="run_metadata.json", help="Output JSON file for run metadata.")
    ap.add_argument("--dump-env", default=None, help="If set, write ALL environment variables to this JSON path.")
    args = ap.parse_args()

    rows = []
    ckks_present = ckks_encoder_name() is not None

    # BFV
    bfv_env = None
    if args.scheme in ("bfv","all"):
        print("\n[ BFV ] setup...")
        try:
            bfv_env = setup_bfv_legacy(poly_degree=args.poly_degree, plain_modulus=args.plain_mod, coeff_modulus_bits=args.coeff_bits)
            print("  keygen_time_s:", fmt(bfv_env.get("keygen_time_s", float('nan'))))
            if bfv_env.get("relin_gen_time_s") is not None:
                print("  relin_gen_time_s:", fmt(bfv_env["relin_gen_time_s"]))
            print("[ BFV ] running...")
            res = bfv_bench(bfv_env, repeat=args.repeat)
            print("  encrypt  median/mean/p90 (s):", fmt(res["encrypt"]["median_s"]), fmt(res["encrypt"]["mean_s"]), fmt(res["encrypt"]["p90_s"]))
            print("  add      median/mean/p90 (s):", fmt(res["add"]["median_s"]), fmt(res["add"]["mean_s"]), fmt(res["add"]["p90_s"]))
            print("  mul+relin median/mean/p90(s):", fmt(res["mul_relin"]["median_s"]), fmt(res["mul_relin"]["mean_s"]), fmt(res["mul_relin"]["p90_s"]))
            print("  decrypt  median/mean/p90 (s):", fmt(res["decrypt"]["median_s"]), fmt(res["decrypt"]["mean_s"]), fmt(res["decrypt"]["p90_s"]))
            if res["correct"]["add"] is not None:
                print("  correctness (x,y,add,mul):", res["correct"]["x"], res["correct"]["y"], res["correct"]["add"], res["correct"]["mul"])
            else:
                print("  correctness: skipped (no decode available)")
            print("  sizes (bytes):", res["sizes"])

            # Save rows
            def add_row(op, tdict):
                rows.append({"scheme":"BFV","op":op, **{k:tdict[k] for k in ("median_s","mean_s","p90_s","repeat")}})
            add_row("encrypt", res["encrypt"]); add_row("add", res["add"]); add_row("mul+relin", res["mul_relin"]); add_row("decrypt", res["decrypt"])
            # Add a synthetic row for sizes
            size_row = {"scheme":"BFV","op":"sizes","median_s":"","mean_s":"","p90_s":"","repeat":""}
            size_row.update({f"size_{k}": (v if v is not None else "") for k,v in res["sizes"].items()})
            rows.append(size_row)


        except Exception as e:
            print("[ BFV ] ERROR:", e)

    # CKKS (optional)
    if ckks_present and args.scheme in ("ckks","all"):
        print("\n[ CKKS ] setup...")
        try:
            ck_env = setup_ckks_legacy(poly_degree=args.poly_degree, coeff_modulus_bits=args.coeff_bits, scale_bits=args.scale_bits)
            if ck_env.get("relin_gen_time_s") is not None:
                print("  relin_gen_time_s:", fmt(ck_env["relin_gen_time_s"]))
            print("[ CKKS ] running...")
            res = ckks_bench(ck_env, repeat=args.repeat)
            print("  encrypt       median/mean/p90 (s):", fmt(res["encrypt"]["median_s"]), fmt(res["encrypt"]["mean_s"]), fmt(res["encrypt"]["p90_s"]))
            print("  add_plain     median/mean/p90 (s):", fmt(res["add_plain"]["median_s"]), fmt(res["add_plain"]["mean_s"]), fmt(res["add_plain"]["p90_s"]))
            print("  mul+relin+res median/mean/p90 (s):", fmt(res["mul_relin_rescale"]["median_s"]), fmt(res["mul_relin_rescale"]["mean_s"]), fmt(res["mul_relin_rescale"]["p90_s"]))
            print("  accuracy:", res["accuracy"])
            print("  sizes (bytes):", res["sizes"])

            def add_row(op, tdict):
                rows.append({"scheme":"CKKS","op":op, **{k:tdict[k] for k in ("median_s","mean_s","p90_s","repeat")}})
            add_row("encrypt", res["encrypt"]); add_row("add_plain", res["add_plain"]); add_row("mul+relin+rescale", res["mul_relin_rescale"])
            size_row = {"scheme":"CKKS","op":"sizes","median_s":"","mean_s":"","p90_s":"","repeat":""}
            size_row.update({f"size_{k}": (v if v is not None else "") for k,v in res["sizes"].items()})
            rows.append(size_row)

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
        rmse = math.sqrt(sum(e*e for e in errs) / len(errs))
        t = bench(lambda: dp_release_sum(values, args.dp_epsilon), repeat=args.repeat)
        print("  epsilon =", args.dp_epsilon, " MAE=%.3e RMSE=%.3e" % (mae, rmse))
        print("  timing  median/mean/p90 (s):", fmt(t['median_s']), fmt(t['mean_s']), fmt(t['p90_s']))
        rows.append({"scheme":"DP","op":"release_sum","median_s":t["median_s"],"mean_s":t["mean_s"],"p90_s":t["p90_s"],"repeat":t["repeat"],"epsilon":args.dp_epsilon})

    # Write CSV
    if rows:
        import csv
        with open(args.csv, "w", newline="") as f:
            fieldnames = sorted(set().union(*[r.keys() for r in rows]))
            w = csv.DictWriter(f, fieldnames=fieldnames)
            w.writeheader()
            for r in rows:
                w.writerow(r)
        print("[OUT] wrote timings CSV:", args.csv)

    # Metadata
    md = collect_metadata(args, bfv_env=bfv_env, ckks_present=ckks_present)
    with open(args.meta, "w", encoding="utf-8") as f:
        json.dump(md, f, indent=2, ensure_ascii=False)
    print("[OUT] wrote metadata JSON:", args.meta)

    # Dump ALL env vars (optional)
    if args.dump_env:
        with open(args.dump_env, "w", encoding="utf-8") as f:
            json.dump(dict(os.environ), f, indent=2, ensure_ascii=False)
        print("[OUT] wrote ALL environment variables to:", args.dump_env)

if __name__ == "__main__":
    main()
#PY
#chmod +x bench_pyseal_rich.py
