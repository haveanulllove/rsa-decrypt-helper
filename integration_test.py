from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import base64
import subprocess
import os

def run_test():
    print("[*] 开始自动化集成测试...")
    
    # 1. 生成 RSA 密钥对
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    # 保存私钥到文件
    with open("test_private.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    test_message = b"Hello, RSA Security Test!"
    
    # 2. 测试场景 A: PKCS1v15 加密
    cipher_pkcs1 = public_key.encrypt(test_message, padding.PKCS1v15())
    b64_cipher_pkcs1 = base64.b64encode(cipher_pkcs1).decode()
    
    # 3. 测试场景 B: OAEP SHA-256 加密
    cipher_oaep = public_key.encrypt(
        test_message, 
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    b64_cipher_oaep = base64.b64encode(cipher_oaep).decode()

    print(f"[*] 场景 A (PKCS1v1.5) 密文已生成")
    print(f"[*] 场景 B (OAEP SHA-256) 密文已生成")

    # 4. 调用 rsa_tool.py 进行验证
    def check_decrypt(cipher_text, scenario_name):
        print(f"\n[>] 测试 {scenario_name}...")
        process = subprocess.Popen(
            ['python3', 'rsa_tool.py', 'test_private.pem', cipher_text],
            stdin=subprocess.PIPE, # 允许输入
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE, 
            text=True
        )
        # 模拟按下回车键以跳过最后的 input()
        stdout, stderr = process.communicate(input="\n")
        
        if "Hello, RSA Security Test!" in stdout:
            print(f"[OK] {scenario_name} 解密成功！")
            return True
        else:
            print(f"[FAIL] {scenario_name} 解密失败！")
            print("Output:", stdout)
            print("Error:", stderr)
            return False

    success_a = check_decrypt(b64_cipher_pkcs1, "PKCS1v1.5")
    success_b = check_decrypt(b64_cipher_oaep, "OAEP SHA-256")

    # 清理
    if os.path.exists("test_private.pem"):
        os.remove("test_private.pem")

    if success_a and success_b:
        print("\n[SUCCESS] 所有测试用例均已通过！工具逻辑严密。")
    else:
        print("\n[ERROR] 测试未完全通过，请检查代码。")

if __name__ == "__main__":
    run_test()
