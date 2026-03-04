import base64
import sys
import os
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend

def decrypt_rsa(private_key_path, ciphertext_str):
    """
    智能 RSA 解密：自动尝试不同的填充模式和编码。
    """
    # 1. 加载私钥 (支持 PKCS#1 和 PKCS#8)
    try:
        with open(private_key_path, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )
    except Exception as e:
        print(f"[!] 无法加载私钥文件: {e}")
        return None

    # 2. 预处理密文 (处理 Base64、Hex、或文件内容)
    ciphertext_str = ciphertext_str.strip()
    if os.path.exists(ciphertext_str):
        with open(ciphertext_str, "rb") as f:
            ciphertext = f.read()
    else:
        # 尝试 Base64 解码
        try:
            ciphertext = base64.b64decode(ciphertext_str)
        except:
            # 尝试 Hex 解码
            try:
                ciphertext = bytes.fromhex(ciphertext_str)
            except:
                # 原始字符串编码为 bytes
                ciphertext = ciphertext_str.encode('utf-8')

    # 3. 填充模式组合尝试
    # 最常见的 RSA 失败原因是 Padding 不一致
    paddings = [
        ("PKCS1v1.5", padding.PKCS1v15()),
        ("OAEP SHA-1 / MGF1-SHA1", padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA1()), algorithm=hashes.SHA1(), label=None)),
        ("OAEP SHA-256 / MGF1-SHA1", padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA1()), algorithm=hashes.SHA256(), label=None)),
        ("OAEP SHA-256 / MGF1-SHA256", padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)),
    ]

    print(f"[*] 密文长度: {len(ciphertext)} 字节")
    print("[*] 开始尝试解密模式...")

    for name, pad in paddings:
        try:
            plaintext = private_key.decrypt(ciphertext, pad)
            print(f"[+] 匹配成功! 模式: {name}")
            try:
                return plaintext.decode('utf-8')
            except UnicodeDecodeError:
                return f"[!] 解密成功，但内容似乎不是 UTF-8 文本 (Hex: {plaintext.hex()})"
        except Exception as e:
            # 这里的异常通常是 'Decryption failed'，表示填充不匹配
            continue
    
    return None

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("用法: python rsa_tool.py <私钥路径> <密文内容或密文文件路径>")
        print("示例: python rsa_tool.py private.key "base64_ciphertext"")
        sys.exit(1)

    key_p = sys.argv[1]
    cipher_p = sys.argv[2]

    result = decrypt_rsa(key_p, cipher_p)
    if result:
        print("
" + "="*40)
        print("解密内容如下:")
        print("-" * 20)
        print(result)
        print("-" * 20)
        print("="*40)
    else:
        print("
[!] 解密失败：已尝试所有填充模式 (PKCS1v1.5, OAEP SHA1/SHA256)。")
        print("[*] 检查点：")
        print("    1. 私钥是否与加密时的公钥匹配？")
        print("    2. 密文内容是否完整且没有多余空格？")
        print("    3. 如果密文是 URL 编码的，请先进行 URL Decode。")
