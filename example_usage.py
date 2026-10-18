from rsa_core import generate_keypair, encrypt, decrypt


def main():
    # 调用共用模块生成密钥
    key = generate_keypair(p=61, q=53, e=17)

    message = 42

    # 加密只需要公钥 e、n
    ciphertext = encrypt(message, key["e"], key["n"])

    # 解密需要私钥指数 d 和模数 n
    recovered = decrypt(ciphertext, key["d"], key["n"])

    print("=== RSA Module Example ===")
    print(f"Public key:  e={key['e']}, n={key['n']}")
    print(f"Private key: d={key['d']}")
    print(f"Original message:  {message}")
    print(f"Encrypted message: {ciphertext}")
    print(f"Decrypted message: {recovered}")

    assert recovered == message, "Decryption failed!"
    print("\nPASS: RSA module works correctly.")


if __name__ == "__main__":
    main()