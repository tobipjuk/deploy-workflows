"""Test-only RSA/JWT helpers (stdlib): key generation, RS256 signing, JWKS. Never used in CI runs."""
import base64
import hashlib
import json
import secrets

SHA256_DIGEST_INFO = bytes.fromhex("3031300d060960864801650304020105000420")
_SMALL_PRIMES = [p for p in range(3, 2000, 2) if all(p % d for d in range(3, int(p ** 0.5) + 1, 2))]


def _probable_prime(n, rounds=40):
    if n < 2:
        return False
    for p in _SMALL_PRIMES:
        if n % p == 0:
            return n == p
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _prime(bits):
    while True:
        c = secrets.randbits(bits) | (1 << (bits - 1)) | (1 << (bits - 2)) | 1
        if _probable_prime(c):
            return c


def generate_key(bits=2048, e=65537):
    while True:
        p, q = _prime(bits // 2), _prime(bits // 2)
        phi = (p - 1) * (q - 1)
        if p != q and phi % e and (p * q).bit_length() == bits:
            return {"n": p * q, "e": e, "d": pow(e, -1, phi)}


def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def int_b64u(i):
    return b64u(i.to_bytes((i.bit_length() + 7) // 8, "big"))


def jwks(key, kid):
    return {"keys": [{"kty": "RSA", "alg": "RS256", "use": "sig", "kid": kid,
                      "n": int_b64u(key["n"]), "e": int_b64u(key["e"])}]}


def sign(key, message):
    k = (key["n"].bit_length() + 7) // 8
    t = SHA256_DIGEST_INFO + hashlib.sha256(message).digest()
    em = b"\x00\x01" + b"\xff" * (k - len(t) - 3) + b"\x00" + t
    return pow(int.from_bytes(em, "big"), key["d"], key["n"]).to_bytes(k, "big")


def make_token(key, kid, claims, alg="RS256"):
    h = b64u(json.dumps({"alg": alg, "kid": kid, "typ": "JWT"}, separators=(",", ":")).encode())
    p = b64u(json.dumps(claims, separators=(",", ":")).encode())
    return f"{h}.{p}.{b64u(sign(key, f'{h}.{p}'.encode()))}"
