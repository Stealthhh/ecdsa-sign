import hashlib
import secrets

p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
a = 0
b = 7

Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
G = (Gx, Gy)

n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

def mod_inv(x, m):
    return pow(x, -1, m)


def is_on_curve(P):
    if P is None:
        return True
    x, y = P
    return (y * y - (x * x * x + a * x + b)) % p == 0


def point_add(P, Q):
    if P is None:
        return Q
    if Q is None:
        return P

    x1, y1 = P
    x2, y2 = Q

    if x1 == x2 and (y1 + y2) % p == 0:
        return None

    if P != Q:
        lam = ((y2 - y1) * mod_inv((x2 - x1) % p, p)) % p
    else:
        lam = ((3 * x1 * x1 + a) * mod_inv((2 * y1) % p, p)) % p

    x3 = (lam * lam - x1 - x2) % p
    y3 = (lam * (x1 - x3) - y1) % p
    return (x3, y3)


def scalar_mult(k, P):
    if k % n == 0 or P is None:
        return None
    if k < 0:
        raise ValueError("k must be non-negative")

    result = None
    addend = P

    while k:
        if k & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        k >>= 1

    return result


def hash_message(message: bytes) -> int:
    h = hashlib.sha256(message).digest()
    return int.from_bytes(h, "big")


def generate_keypair():
    d = secrets.randbelow(n - 1) + 1
    Q = scalar_mult(d, G)
    assert is_on_curve(Q)
    return d, Q


def sign_message(message: bytes, d: int):
    z = hash_message(message)

    while True:
        k = secrets.randbelow(n - 1) + 1
        x1, _ = scalar_mult(k, G)
        r = x1 % n
        if r == 0:
            continue

        k_inv = mod_inv(k, n)
        s = (k_inv * (z + r * d)) % n
        if s == 0:
            continue

        return (r, s)


def verify_signature(message: bytes, signature, Q):
    if not is_on_curve(Q):
        return False

    r, s = signature
    if not (1 <= r < n and 1 <= s < n):
        return False

    z = hash_message(message)
    w = mod_inv(s, n)
    u1 = (z * w) % n
    u2 = (r * w) % n

    P1 = scalar_mult(u1, G)
    P2 = scalar_mult(u2, Q)
    X = point_add(P1, P2)

    if X is None:
        return False

    x, _ = X
    return (x % n) == r


if __name__ == "__main__":
    private_key, public_key = generate_keypair()

    message = ""
    msg_bytes = message.encode("utf-8")

    signature = sign_message(msg_bytes, private_key)
    r, s = signature

    valid = verify_signature(msg_bytes, signature, public_key)

    print(f"Private key d: {hex(private_key)}")
    print(f"Public key Qx: {hex(public_key[0])}")
    print(f"Public key Qy: {hex(public_key[1])}")
    print(f"\nSignature:")
    print(f"r = {hex(r)}")
    print(f"s = {hex(s)}")