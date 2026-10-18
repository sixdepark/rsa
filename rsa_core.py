from math import gcd, isqrt


def is_prime(number):
    """判断是否为质数，适用于当前的小数值教学实验。"""
    if number < 2:
        return False

    for divisor in range(2, isqrt(number) + 1):
        if number % divisor == 0:
            return False

    return True


def generate_keypair(p, q, e=65537):
    """根据两个不同的质数和公钥指数生成 RSA 密钥参数。"""
    if not is_prime(p) or not is_prime(q):
        raise ValueError("p and q must be prime")

    if p == q:
        raise ValueError("p and q must be different")

    n = p * q
    phi = (p - 1) * (q - 1)

    if not 1 < e < phi or gcd(e, phi) != 1:
        raise ValueError("e must satisfy 1 < e < phi and gcd(e, phi) = 1")

    d = pow(e, -1, phi)

    return {
        "p": p,
        "q": q,
        "n": n,
        "phi": phi,
        "e": e,
        "d": d,
    }


def encrypt(message, e, n):
    """使用公钥加密整数消息。"""
    if not 0 <= message < n:
        raise ValueError("message must satisfy 0 <= message < n")

    return pow(message, e, n)


def decrypt(ciphertext, d, n):
    """使用私钥解密整数密文。"""
    if not 0 <= ciphertext < n:
        raise ValueError("ciphertext must satisfy 0 <= ciphertext < n")

    return pow(ciphertext, d, n)