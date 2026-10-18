from math import isqrt
from time import perf_counter

from rsa_core import generate_keypair, encrypt, decrypt


def fermat_factor(n, max_checks=100000):
    """只根据 n 分解因子，最多检查 max_checks 次。"""
    if n <= 1 or n % 2 == 0:
        raise ValueError("n must be an odd integer greater than 1")

    if max_checks < 1:
        raise ValueError("max_checks must be positive")

    # 从不小于 sqrt(n) 的最小整数开始
    a = isqrt(n)
    if a * a < n:
        a += 1

    for checks in range(1, max_checks + 1):
        b_squared = a * a - n
        b = isqrt(b_squared)

        # 判断 a² - n 是否为完全平方数
        if b * b == b_squared:
            p = a - b
            q = a + b

            if p > 1 and q > 1:
                return p, q, checks

            # 已到达 1 × n，未找到非平凡因子
            return None

        a += 1

    return None


def main():
    # 实验准备：故意选择两个很接近的质数
    key = generate_keypair(p=1009, q=1013, e=65537)
    message = 42
    ciphertext = encrypt(message, key["e"], key["n"])

    # 攻击阶段：只把公开的 n 传给分解函数
    start = perf_counter()
    result = fermat_factor(key["n"])
    elapsed = perf_counter() - start

    print("=== Fermat Attack Demo ===")
    print(f"Public key: e={key['e']}, n={key['n']}")
    print(f"Ciphertext: {ciphertext}")

    if result is None:
        print("No factors recovered within the check limit.")
        return

    recovered_p, recovered_q, checks = result

    # 使用找回的因子计算私钥
    recovered_phi = (recovered_p - 1) * (recovered_q - 1)
    recovered_d = pow(key["e"], -1, recovered_phi)

    recovered_message = decrypt(
        ciphertext, recovered_d, key["n"]
    )

    print(f"Recovered p: {recovered_p}")
    print(f"Recovered q: {recovered_q}")
    print(f"Recovered d: {recovered_d}")
    print(f"Checks: {checks}")
    print(f"Factorization time: {elapsed:.8f} seconds")
    print(f"Decrypted message: {recovered_message}")

    # 攻击结束后，才使用原始参数核对
    assert recovered_p * recovered_q == key["n"]
    assert recovered_d == key["d"]
    assert recovered_message == message

    print("\nPASS: Private key recovered and message decrypted.")


if __name__ == "__main__":
    main()