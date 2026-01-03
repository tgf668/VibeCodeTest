#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
算法模块
实现 MD5、SHA1、RSA 加密解密算法
"""

import hashlib
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64


# ============= MD5 算法 =============

def CalculateMD5(input_data):
    """
    传入值: input_data (str) - 需要计算MD5的字符串
    返回值: str - MD5哈希值（十六进制字符串）
    
    功能: 计算字符串的MD5哈希值
    """
    if isinstance(input_data, str):
        input_data = input_data.encode('utf-8')
    
    md5_hash = hashlib.md5()
    md5_hash.update(input_data)
    
    return md5_hash.hexdigest()


def VerifyMD5(input_data, expected_hash):
    """
    传入值: input_data (str) - 待验证的字符串, expected_hash (str) - 预期的MD5值
    返回值: bool - 验证结果
    
    功能: 验证字符串的MD5哈希值是否匹配
    """
    calculated_hash = CalculateMD5(input_data)
    return calculated_hash.lower() == expected_hash.lower()


# ============= SHA1 算法 =============

def CalculateSHA1(input_data):
    """
    传入值: input_data (str) - 需要计算SHA1的字符串
    返回值: str - SHA1哈希值（十六进制字符串）
    
    功能: 计算字符串的SHA1哈希值
    """
    if isinstance(input_data, str):
        input_data = input_data.encode('utf-8')
    
    sha1_hash = hashlib.sha1()
    sha1_hash.update(input_data)
    
    return sha1_hash.hexdigest()


def VerifySHA1(input_data, expected_hash):
    """
    传入值: input_data (str) - 待验证的字符串, expected_hash (str) - 预期的SHA1值
    返回值: bool - 验证结果
    
    功能: 验证字符串的SHA1哈希值是否匹配
    """
    calculated_hash = CalculateSHA1(input_data)
    return calculated_hash.lower() == expected_hash.lower()


# ============= RSA 加密解密算法 =============

def GenerateRSAKeyPair(key_size=2048):
    """
    传入值: key_size (int) - RSA密钥长度，默认2048位
    返回值: tuple - (private_key, public_key) RSA密钥对
    
    功能: 生成RSA公钥和私钥对
    """
    key = RSA.generate(key_size)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    
    return private_key, public_key


def SaveRSAKeyToFile(private_key, filename='key.txt'):
    """
    传入值: private_key (bytes) - RSA私钥, filename (str) - 保存文件名
    返回值: NULL
    
    功能: 将RSA私钥保存到文件
    """
    try:
        with open(filename, 'wb') as f:
            f.write(private_key)
        print(f"私钥已保存到 {filename}")
    except Exception as e:
        print(f"保存私钥时发生错误: {e}")


def LoadRSAKeyFromFile(filename='key.txt'):
    """
    传入值: filename (str) - 密钥文件名
    返回值: RSA密钥对象
    
    功能: 从文件加载RSA密钥
    """
    try:
        with open(filename, 'rb') as f:
            key_data = f.read()
        return RSA.import_key(key_data)
    except Exception as e:
        print(f"加载密钥时发生错误: {e}")
        return None


def RSAEncrypt(plaintext, public_key):
    """
    传入值: plaintext (str) - 明文数据, public_key (bytes) - RSA公钥
    返回值: str - Base64编码的密文
    
    功能: 使用RSA公钥加密数据，使用PKCS#7填充模式和ECB分组模式
    """
    try:
        # 导入公钥
        if isinstance(public_key, bytes):
            rsa_key = RSA.import_key(public_key)
        else:
            rsa_key = public_key
        
        # 使用PKCS1_OAEP加密（包含PKCS#7填充）
        cipher = PKCS1_OAEP.new(rsa_key)
        
        # 将字符串转换为字节
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
        
        # RSA加密（ECB模式是RSA的默认模式）
        ciphertext = cipher.encrypt(plaintext)
        
        # Base64编码以便传输
        encrypted_data = base64.b64encode(ciphertext).decode('utf-8')
        
        return encrypted_data
    
    except Exception as e:
        print(f"RSA加密时发生错误: {e}")
        return None


def RSADecrypt(ciphertext, private_key):
    """
    传入值: ciphertext (str) - Base64编码的密文, private_key (bytes) - RSA私钥
    返回值: str - 解密后的明文
    
    功能: 使用RSA私钥解密数据，使用PKCS#7填充模式和ECB分组模式
    """
    try:
        # 导入私钥
        if isinstance(private_key, bytes):
            rsa_key = RSA.import_key(private_key)
        else:
            rsa_key = private_key
        
        # 使用PKCS1_OAEP解密（包含PKCS#7填充）
        cipher = PKCS1_OAEP.new(rsa_key)
        
        # Base64解码
        ciphertext_bytes = base64.b64decode(ciphertext)
        
        # RSA解密（ECB模式是RSA的默认模式）
        plaintext = cipher.decrypt(ciphertext_bytes)
        
        # 转换为字符串
        decrypted_data = plaintext.decode('utf-8')
        
        return decrypted_data
    
    except Exception as e:
        print(f"RSA解密时发生错误: {e}")
        return None


def EncryptPasswordWithRSA(password, public_key_file='key.txt'):
    """
    传入值: password (str) - 密码明文, public_key_file (str) - 公钥文件路径
    返回值: str - 加密后的密码（Base64编码）
    
    功能: 使用RSA公钥加密密码
    """
    try:
        # 加载公钥
        key = LoadRSAKeyFromFile(public_key_file)
        if key is None:
            return None
        
        public_key = key.publickey()
        
        # 加密密码
        encrypted_password = RSAEncrypt(password, public_key)
        
        return encrypted_password
    
    except Exception as e:
        print(f"加密密码时发生错误: {e}")
        return None


def DecryptPasswordWithRSA(encrypted_password, private_key_file='key.txt'):
    """
    传入值: encrypted_password (str) - 加密的密码, private_key_file (str) - 私钥文件路径
    返回值: str - 解密后的密码明文
    
    功能: 使用RSA私钥解密密码
    """
    try:
        # 加载私钥
        private_key = LoadRSAKeyFromFile(private_key_file)
        if private_key is None:
            return None
        
        # 解密密码
        decrypted_password = RSADecrypt(encrypted_password, private_key)
        
        return decrypted_password
    
    except Exception as e:
        print(f"解密密码时发生错误: {e}")
        return None


# ============= 测试函数 =============

def TestFromConsole():
    """
    传入值: 无 (从控制台接收)
    返回值: NULL
    
    功能: 从控制台接收数据，分别测试MD5、SHA1、RSA算法
    """
    print("\n" + "="*60)
    print("算法测试系统 - 控制台模式")
    print("="*60 + "\n")
    
    # 从控制台接收测试数据
    print("请输入要测试的数据:")
    test_data = input("> ")
    
    if not test_data:
        print("错误：未输入数据")
        return
    
    print("\n" + "-"*60)
    print("开始测试...")
    print("-"*60 + "\n")
    
    # 测试结果列表
    results = []
    
    # 测试 MD5 算法
    try:
        md5_hash = CalculateMD5(test_data)
        if md5_hash and len(md5_hash) == 32:
            # 验证 MD5 是否能正确验证
            if VerifyMD5(test_data, md5_hash):
                results.append(("MD5算法", "OK", md5_hash))
            else:
                results.append(("MD5算法", "ERROR", "验证失败"))
        else:
            results.append(("MD5算法", "ERROR", "哈希值生成失败"))
    except Exception as e:
        results.append(("MD5算法", "ERROR", str(e)))
    
    # 测试 SHA1 算法
    try:
        sha1_hash = CalculateSHA1(test_data)
        if sha1_hash and len(sha1_hash) == 40:
            # 验证 SHA1 是否能正确验证
            if VerifySHA1(test_data, sha1_hash):
                results.append(("SHA1算法", "OK", sha1_hash))
            else:
                results.append(("SHA1算法", "ERROR", "验证失败"))
        else:
            results.append(("SHA1算法", "ERROR", "哈希值生成失败"))
    except Exception as e:
        results.append(("SHA1算法", "ERROR", str(e)))
    
    # 测试 RSA 算法
    try:
        # 生成测试用的RSA密钥对
        print("正在生成RSA密钥对...")
    import sys
    
    # 检查命令行参数
    if len(sys.argv) > 1:
        if sys.argv[1] == 'test':
            # 运行完整测试
            RunAlgorithmTests()
        elif sys.argv[1] == 'console':
            # 控制台输入测试
            TestFromConsole()
        elif sys.argv[1] == 'sample':
            # 样本数据测试
            TestWithSampleData()
        else:
            print(f"未知参数: {sys.argv[1]}")
            print("可用参数: test, console, sample")
    else:
        # 默认启动交互式菜单
        InteractiveTestMenupublic_key = GenerateRSAKeyPair(2048)
        
        # 加密
        encrypted_data = RSAEncrypt(test_data, public_key)
        if encrypted_data:
            # 解密
            decrypted_data = RSADecrypt(encrypted_data, private_key)
            
            # 验证解密后的数据是否与原数据一致
            if decrypted_data == test_data:
                results.append(("RSA算法", "OK", f"加密长度: {len(encrypted_data)}"))
            else:
                results.append(("RSA算法", "ERROR", "解密数据不匹配"))
        else:
            results.append(("RSA算法", "ERROR", "加密失败"))
    except Exception as e:
        results.append(("RSA算法", "ERROR", str(e)))
    
    # 打印测试结果
    print("\n" + "="*60)
    print("测试结果")
    print("="*60 + "\n")
    
    for algo_name, status, detail in results:
        print(f"{algo_name}，结果为{status}")
        if status == "OK":
            print(f"  详情: {detail}")
        else:
            print(f"  错误信息: {detail}")
        print()
    
    # 统计
    ok_count = sum(1 for _, status, _ in results if status == "OK")
    error_count = sum(1 for _, status, _ in results if status == "ERROR")
    
    print("-"*60)
    print(f"总计: {len(results)} 个测试")
    print(f"成功: {ok_count} 个 | 失败: {error_count} 个")
    print("-"*60 + "\n")


def TestWithSampleData():
    """
    传入值: 无
    返回值: NULL
    
    功能: 使用预定义的样本数据测试所有算法
    """
    print("\n" + "="*60)
    print("算法测试系统 - 样本数据模式")
    print("="*60 + "\n")
    
    # 测试样本数据
    sample_data_list = [
        "Hello123",
        "Test@2026",
        "MyPassword",
        "123456789",
        "短文本"
    ]
    
    for idx, test_data in enumerate(sample_data_list, 1):
        print(f"\n【测试 {idx}】测试数据: {test_data}")
        print("-"*60)
        
        # 测试 MD5
        try:
            md5_hash = CalculateMD5(test_data)
            if VerifyMD5(test_data, md5_hash):
                print(f"MD5算法，结果为OK")
            else:
                print(f"MD5算法，结果为ERROR")
        except Exception as e:
            print(f"MD5算法，结果为ERROR (异常: {e})")
        
        # 测试 SHA1
        try:
            sha1_hash = CalculateSHA1(test_data)
            if VerifySHA1(test_data, sha1_hash):
                print(f"SHA1算法，结果为OK")
            else:
                print(f"SHA1算法，结果为ERROR")
        except Exception as e:
            print(f"SHA1算法，结果为ERROR (异常: {e})")
        
        # 测试 RSA
        try:
            private_key, public_key = GenerateRSAKeyPair(2048)
            encrypted = RSAEncrypt(test_data, public_key)
            decrypted = RSADecrypt(encrypted, private_key)
            
            if decrypted == test_data:
                print(f"RSA算法，结果为OK")
            else:
                print(f"RSA算法，结果为ERROR")
        except Exception as e:
            print(f"RSA算法，结果为ERROR (异常: {e})")
    
    print("\n" + "="*60)
    print("所有样本数据测试完成")
    print("="*60 + "\n")


def InteractiveTestMenu():
    """
    传入值: 无
    返回值: NULL
    
    功能: 交互式测试菜单，允许用户选择测试模式
    """
    while True:
        print("\n" + "="*60)
        print("算法测试系统 - 主菜单")
        print("="*60)
        print("\n请选择测试模式:")
        print("  1. 从控制台输入数据测试")
        print("  2. 使用样本数据批量测试")
        print("  3. 运行完整算法测试")
        print("  0. 退出")
        print()
        
        choice = input("请输入选项 (0-3): ").strip()
        
        if choice == "1":
            TestFromConsole()
        elif choice == "2":
            TestWithSampleData()
        elif choice == "3":
            RunAlgorithmTests()
        elif choice == "0":
            print("\n退出测试系统。")
            break
        else:
            print("\n错误：无效的选项，请重新选择。")
        
        # 询问是否继续
        if choice in ["1", "2", "3"]:
            continue_test = input("\n是否继续测试? (y/n): ").strip().lower()
            if continue_test != 'y' and continue_test != 'yes':
                print("\n退出测试系统。")
                break

def RunAlgorithmTests():
    """
    传入值: 无
    返回值: NULL
    
    功能: 执行算法模块的测试
    """
    print("\n" + "="*50)
    print("算法模块测试")
    print("="*50 + "\n")
    
    # 测试MD5
    print("【MD5算法测试】")
    test_string = "Hello, World!"
    md5_result = CalculateMD5(test_string)
    print(f"输入: {test_string}")
    print(f"MD5: {md5_result}")
    print(f"验证: {VerifyMD5(test_string, md5_result)}")
    print()
    
    # 测试SHA1
    print("【SHA1算法测试】")
    sha1_result = CalculateSHA1(test_string)
    print(f"输入: {test_string}")
    print(f"SHA1: {sha1_result}")
    print(f"验证: {VerifySHA1(test_string, sha1_result)}")
    print()
    
    # 测试RSA
    print("【RSA算法测试】")
    print("生成RSA密钥对...")
    private_key, public_key = GenerateRSAKeyPair(2048)
    print("✓ 密钥生成成功")
    
    # 保存私钥
    SaveRSAKeyToFile(private_key)
    
    # 测试加密解密
    test_password = "MyP@ssw0rd"
    print(f"\n原始密码: {test_password}")
    
    encrypted = RSAEncrypt(test_password, public_key)
    print(f"加密后: {encrypted[:50]}..." if len(encrypted) > 50 else f"加密后: {encrypted}")
    
    decrypted = RSADecrypt(encrypted, private_key)
    print(f"解密后: {decrypted}")
    
    if test_password == decrypted:
        print("✓ RSA加密解密测试通过")
    else:
        print("✗ RSA加密解密测试失败")
    
    print("\n" + "="*50)
    print("测试完成")
    print("="*50 + "\n")


if __name__ == '__main__':
    RunAlgorithmTests()
