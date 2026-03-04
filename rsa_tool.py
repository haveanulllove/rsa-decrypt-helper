import base64
import sys
import os
import time
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
        if not os.path.exists(private_key_path):
            print(f"[!] 错误：找不到私钥文件 '{private_key_path}'")
            return None
            
        with open(private_key_path, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )
    except Exception as e:
        print(f"[!] 无法加载私钥文件 (格式可能不对): {e}")
        return None

    ciphertext_str = ciphertext_str.strip()
    # 如果输入是一个存在的文件路径，则读取文件内容
    if os.path.exists(ciphertext_str):
        with open(ciphertext_str, "rb") as f:
            ciphertext = f.read()
    else:
        # 尝试解码 Base64/Hex/Raw
        try:
            clean_cipher = "".join(ciphertext_str.split())
            ciphertext = base64.b64decode(clean_cipher)
        except:
            try:
                ciphertext = bytes.fromhex(ciphertext_str)
            except:
                ciphertext = ciphertext_str.encode('utf-8')

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
    
    if results:
        best_name, best_data = results[0]
        print(f"[!] 警告：找到能解密的模式 {best_name}，但内容包含不可见字符。")
        return f"(HEX数据): {best_data.hex()}"
    
    return None

def main():
    print("="*50)
    print("        RSA 智能解密辅助工具 (Windows v2.0)")
    print("="*50)

    # 逻辑：如果有命令行参数则使用参数，否则进入交互模式
    if len(sys.argv) >= 3:
        key_p = sys.argv[1]
        cipher_p = sys.argv[2]
    else:
        print("\n[交互模式] 请输入以下信息：")
        key_p = input("1. 请输入私钥文件路径 (例如 private.key): ").strip('"').strip()
        cipher_p = input("2. 请输入密文内容 (Base64) 或 密文文件路径: ").strip('"').strip()

    if not key_p or not cipher_p:
        print("\n[!] 错误：私钥路径和密文内容不能为空。")
    else:
        result = decrypt_rsa(key_p, cipher_p)
        if result:
            print("\n" + "="*40)
            print("解密结果如下:")
            print("-" * 20)
            print(result)
            print("-" * 20)
            print("="*40)
        else:
            print("\n[!] 解密失败：已尝试所有常见 RSA 填充模式。")
            print("    请确认私钥是否正确，以及密文是否完整。")

    print("\n" + "-"*50)
    input("任务结束。请按 [回车键] 退出程序...")

if __name__ == "__main__":
    main()
