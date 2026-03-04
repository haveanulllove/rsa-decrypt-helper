import base64
import sys
import os
import time
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend

def is_printable(data):
    """判断解密结果是否为可读文本"""
    try:
        decoded = data.decode('utf-8')
        return all(c.isprintable() or c in '\n\r\t' for c in decoded), decoded
    except UnicodeDecodeError:
        return False, None

def load_private_key_robustly(key_path):
    """
    鲁棒地加载私钥：支持 PEM, DER 以及缺失头尾标记的 Base64 格式。
    """
    if not os.path.exists(key_path):
        print(f"[!] 错误：找不到文件 '{key_path}'")
        return None

    with open(key_path, "rb") as f:
        key_data = f.read()

    # 1. 尝试直接作为 PEM 加载
    try:
        return serialization.load_pem_private_key(key_data, password=None, backend=default_backend())
    except Exception:
        pass

    # 2. 尝试作为二进制 DER 加载
    try:
        return serialization.load_der_private_key(key_data, password=None, backend=default_backend())
    except Exception:
        pass

    # 3. 尝试如果它是纯 Base64 (没有头尾标记)，手动补全再试
    try:
        # 清理多余空格、换行
        clean_key = "".join(key_data.decode('utf-8', errors='ignore').split())
        # 尝试补全 PKCS8 标记
        pem_formatted = f"-----BEGIN PRIVATE KEY-----\n{clean_key}\n-----END PRIVATE KEY-----"
        return serialization.load_pem_private_key(pem_formatted.encode(), password=None, backend=default_backend())
    except Exception:
        pass

    # 4. 尝试补全 PKCS1 标记
    try:
        clean_key = "".join(key_data.decode('utf-8', errors='ignore').split())
        pem_formatted = f"-----BEGIN RSA PRIVATE KEY-----\n{clean_key}\n-----END RSA PRIVATE KEY-----"
        return serialization.load_pem_private_key(pem_formatted.encode(), password=None, backend=default_backend())
    except Exception:
        pass

    return None

def decrypt_rsa(private_key_path, ciphertext_str):
    """智能 RSA 解密工具（支持分段解密）"""
    private_key = load_private_key_robustly(private_key_path)
    if not private_key:
        print(f"[!] 无法解析私钥。")
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

    # 文档中提到密钥大小是 2048 位，解密块大小是 256 字节
    key_size_bytes = 256 
    
    paddings = [
        ("PKCS1v1.5", padding.PKCS1v15()),
        ("OAEP SHA-256", padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)),
    ]

    print(f"[*] 密文总长度: {len(ciphertext)} 字节")
    
    for name, pad in paddings:
        try:
            full_plaintext = b""
            # 分段解密逻辑
            for i in range(0, len(ciphertext), key_size_bytes):
                chunk = ciphertext[i:i+key_size_bytes]
                decrypted_chunk = private_key.decrypt(chunk, pad)
                full_plaintext += decrypted_chunk
            
            ok, text = is_printable(full_plaintext)
            if ok:
                print(f"[+] 解密成功! 模式: {name} (已自动进行分段处理)")
                return text
        except Exception as e:
            continue
    
    return None

def main():
    print("="*50)
    print("        RSA 智能解密辅助工具 (Windows v2.1-Robust)")
    print("="*50)

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
            print("\n[!] 解密失败：已尝试所有常见格式和填充模式。")
            print("    提示：请确保私钥是 RSA 算法生成的，且密文与其匹配。")

    print("\n" + "-"*50)
    input("任务结束。请按 [回车键] 退出程序...")

if __name__ == "__main__":
    main()
