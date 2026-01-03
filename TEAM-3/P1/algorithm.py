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
