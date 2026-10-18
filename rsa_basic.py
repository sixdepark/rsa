from math import gcd


def main():
    # 1. 选择两个不同的质数
    p = 61
    q = 53

    # 2. 计算模数 n 和欧拉函数 phi
    n = p * q
    phi = (p - 1) * (q - 1)

    # 3. 选择公钥指数 e，要求 e 与 phi 互质
    e = 17
    if gcd(e, phi) != 1:
        raise ValueError("e must be coprime to phi")

    # 4. 计算私钥指数 d，使 e * d ≡ 1 (mod phi)
    d = pow(e, -1, phi)

    # 5. 原始消息必须满足 0 <= message < n
    message = 42

    # 6. 使用公钥加密：c = m^e mod n
    ciphertext = pow(message, e, n)

    # 7. 使用私钥解密：m = c^d mod n
    recovered = pow(ciphertext, d, n)

    print("=== RSA Basic Demo ===")
    print(f"p = {p}, q = {q}")
    print(f"n = {n}")
    print(f"phi = {phi}")
    print(f"Public key (e, n): ({e}, {n})")
    print(f"Private key (d, n): ({d}, {n})")
    print()
    print(f"Original message:  {message}")
    print(f"Encrypted message: {ciphertext}")
    print(f"Decrypted message: {recovered}")

    assert recovered == message, "Decryption failed!"
    print("\nPASS: Decrypted message matches the original.")


if __name__ == "__main__":
    main()
