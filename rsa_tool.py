import base64
import sys
import os
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend

def is_printable(data):
    """简单判断解密结果是否为可读文本"""
    try:
        decoded = data.decode('utf-8')
        return all(c.isprintable() or c in '\n\r\t' for c in decoded), decoded
    except UnicodeDecodeError:
        return False, None

def decrypt_rsa(private_key_path, ciphertext_str):
    """
    智能 RSA 解密：自动尝试不同的填充模式和编码。
    """
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

    ciphertext_str = ciphertext_str.strip()
    if os.path.exists(ciphertext_str):
        with open(ciphertext_str, "rb") as f:
            ciphertext = f.read()
    else:
        try:
            clean_cipher = "".join(ciphertext_str.split())
            ciphertext = base64.b64decode(clean_cipher)
        except:
            try:
                ciphertext = bytes.fromhex(ciphertext_str)
            except:
                ciphertext = ciphertext_str.encode('utf-8')

    # 填充模式列表 - 将 OAEP 放在前面，因为它有校验位，不容易发生假匹配
    paddings = [
        ("OAEP SHA-256 / MGF1-SHA256", padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)),
        ("OAEP SHA-256 / MGF1-SHA1", padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA1()), algorithm=hashes.SHA256(), label=None)),
        ("OAEP SHA-1 / MGF1-SHA1", padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA1()), algorithm=hashes.SHA1(), label=None)),
        ("PKCS1v1.5", padding.PKCS1v15()),
    ]

    print(f"[*] 密文长度: {len(ciphertext)} 字节")
    
    results = []
    for name, pad in paddings:
        try:
            plaintext = private_key.decrypt(ciphertext, pad)
            ok, text = is_printable(plaintext)
            if ok:
                print(f"[+] 发现有效匹配! 模式: {name}")
                return text
            else:
                results.append((name, plaintext))
        except Exception:
            continue
    
    # 如果没有找到完美的文本匹配，但有模式能解密出东西（比如二进制数据）
    if results:
        best_name, best_data = results[0]
        print(f"[!] 警告：找到能解密的模式 {best_name}，但内容包含不可见字符。")
        return best_data.hex()
    
    return None

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("用法: python rsa_tool.py <私钥路径> <密文内容或密文文件路径>")
        sys.exit(1)

    key_p = sys.argv[1]
    cipher_p = sys.argv[2]

    result = decrypt_rsa(key_p, cipher_p)
    if result:
        print("\n" + "="*40)
        print("解密内容如下:")
        print("-" * 20)
        print(result)
        print("-" * 20)
        print("="*40)
    else:
        print("\n[!] 解密失败：已尝试所有填充模式。")
