"""
算法模块 - 实现MD5、SHA1和RSA加密解密算法
"""

import hashlib
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
import base64
import os

# 常量定义
BLOCK_SIZE = 16  # AES块大小
PADDING_MODE = 'pkcs7'  # PKCS#7填充模式
CIPHER_MODE = 'ECB'  # ECB分组模式
RSA_KEY_SIZE = 2048  # RSA密钥大小
MD5_DIGEST_SIZE = 32  # MD5摘要长度（十六进制）
SHA1_DIGEST_SIZE = 40  # SHA1摘要长度（十六进制）


def CalculateMD5(input_data):
    """
    计算输入数据的MD5哈希值
    传入值: 
        input_data (str or bytes) - 需要计算哈希的数据
    返回值: str - MD5哈希值（十六进制字符串）
    """
    # 确保输入是字节类型
    if isinstance(input_data, str):
        input_data = input_data.encode('utf-8')
    
    # 创建MD5哈希对象
    md5_hash = hashlib.md5()
    md5_hash.update(input_data)
    
    # 返回十六进制表示的哈希值
    hash_result = md5_hash.hexdigest()
    return hash_result


def CalculateSHA1(input_data):
    """
    计算输入数据的SHA1哈希值
    传入值: 
        input_data (str or bytes) - 需要计算哈希的数据
    返回值: str - SHA1哈希值（十六进制字符串）
    """
    # 确保输入是字节类型
    if isinstance(input_data, str):
        input_data = input_data.encode('utf-8')
    
    # 创建SHA1哈希对象
    sha1_hash = hashlib.sha1()
    sha1_hash.update(input_data)
    
    # 返回十六进制表示的哈希值
    hash_result = sha1_hash.hexdigest()
    return hash_result


def GenerateRSAKeyPair(key_size=RSA_KEY_SIZE):
    """
    生成RSA密钥对
    传入值: 
        key_size (int) - RSA密钥大小，默认2048位
    返回值: tuple - (私钥对象, 公钥对象)
    """
    # 生成RSA密钥对
    rsa_key = RSA.generate(key_size)
    
    # 获取私钥和公钥
    private_key = rsa_key
    public_key = rsa_key.publickey()
    
    return private_key, public_key


def ExportRSAPrivateKey(private_key, file_path='key.txt'):
    """
    导出RSA私钥到文件
    传入值: 
        private_key - RSA私钥对象
        file_path (str) - 保存私钥的文件路径
    返回值: str - PEM格式的私钥字符串
    """
    # 导出为PEM格式
    private_key_pem = private_key.export_key()
    
    # 写入文件
    with open(file_path, 'wb') as f:
        f.write(private_key_pem)
    
    return private_key_pem.decode('utf-8')


def ExportRSAPublicKey(public_key):
    """
    导出RSA公钥
    传入值: 
        public_key - RSA公钥对象
    返回值: str - PEM格式的公钥字符串
    """
    # 导出为PEM格式
    public_key_pem = public_key.export_key()
    return public_key_pem.decode('utf-8')


def LoadRSAPrivateKey(file_path='key.txt'):
    """
    从文件加载RSA私钥
    传入值: 
        file_path (str) - 私钥文件路径
    返回值: RSA私钥对象
    """
    with open(file_path, 'rb') as f:
        private_key_data = f.read()
    
    private_key = RSA.import_key(private_key_data)
    return private_key


def LoadRSAPublicKey(public_key_pem):
    """
    从PEM字符串加载RSA公钥
    传入值: 
        public_key_pem (str or bytes) - PEM格式的公钥
    返回值: RSA公钥对象
    """
    if isinstance(public_key_pem, str):
        public_key_pem = public_key_pem.encode('utf-8')
    
    public_key = RSA.import_key(public_key_pem)
    return public_key


def EncryptWithRSA(plain_text, public_key):
    """
    使用RSA公钥加密数据（PKCS#1 OAEP填充）
    传入值: 
        plain_text (str or bytes) - 需要加密的明文
        public_key - RSA公钥对象
    返回值: str - Base64编码的密文
    """
    # 确保输入是字节类型
    if isinstance(plain_text, str):
        plain_text = plain_text.encode('utf-8')
    
    # 创建RSA加密器（使用OAEP填充）
    cipher_rsa = PKCS1_OAEP.new(public_key)
    
    # 加密数据
    encrypted_data = cipher_rsa.encrypt(plain_text)
    
    # 返回Base64编码的结果
    encrypted_base64 = base64.b64encode(encrypted_data).decode('utf-8')
    return encrypted_base64


def DecryptWithRSA(encrypted_text, private_key):
    """
    使用RSA私钥解密数据（PKCS#1 OAEP填充）
    传入值: 
        encrypted_text (str) - Base64编码的密文
        private_key - RSA私钥对象
    返回值: str - 解密后的明文
    """
    # Base64解码
    encrypted_data = base64.b64decode(encrypted_text)
    
    # 创建RSA解密器（使用OAEP填充）
    cipher_rsa = PKCS1_OAEP.new(private_key)
    
    # 解密数据
    decrypted_data = cipher_rsa.decrypt(encrypted_data)
    
    # 返回解密后的字符串
    return decrypted_data.decode('utf-8')


def EncryptWithRSAECB(plain_text, public_key):
    """
    使用RSA公钥加密较长数据（模拟ECB模式分块加密）
    传入值: 
        plain_text (str or bytes) - 需要加密的明文
        public_key - RSA公钥对象
    返回值: str - Base64编码的密文（多个块拼接）
    """
    # 确保输入是字节类型
    if isinstance(plain_text, str):
        plain_text = plain_text.encode('utf-8')
    
    # 计算每块的最大大小（RSA密钥长度 - OAEP填充开销）
    key_size_bytes = public_key.size_in_bytes()
    max_chunk_size = key_size_bytes - 42  # OAEP填充需要42字节
    
    # 分块加密
    encrypted_chunks = []
    cipher_rsa = PKCS1_OAEP.new(public_key)
    
    for i in range(0, len(plain_text), max_chunk_size):
        chunk = plain_text[i:i + max_chunk_size]
        encrypted_chunk = cipher_rsa.encrypt(chunk)
        encrypted_chunks.append(encrypted_chunk)
    
    # 拼接所有加密块并Base64编码
    encrypted_data = b''.join(encrypted_chunks)
    encrypted_base64 = base64.b64encode(encrypted_data).decode('utf-8')
    return encrypted_base64


def DecryptWithRSAECB(encrypted_text, private_key):
    """
    使用RSA私钥解密较长数据（模拟ECB模式分块解密）
    传入值: 
        encrypted_text (str) - Base64编码的密文
        private_key - RSA私钥对象
    返回值: str - 解密后的明文
    """
    # Base64解码
    encrypted_data = base64.b64decode(encrypted_text)
    
    # 计算每块的大小
    key_size_bytes = private_key.size_in_bytes()
    
    # 分块解密
    decrypted_chunks = []
    cipher_rsa = PKCS1_OAEP.new(private_key)
    
    for i in range(0, len(encrypted_data), key_size_bytes):
        chunk = encrypted_data[i:i + key_size_bytes]
        decrypted_chunk = cipher_rsa.decrypt(chunk)
        decrypted_chunks.append(decrypted_chunk)
    
    # 拼接所有解密块
    decrypted_data = b''.join(decrypted_chunks)
    return decrypted_data.decode('utf-8')


def ApplyPKCS7Padding(data, block_size=BLOCK_SIZE):
    """
    应用PKCS#7填充
    传入值: 
        data (bytes) - 需要填充的数据
        block_size (int) - 块大小，默认16字节
    返回值: bytes - 填充后的数据
    """
    return pad(data, block_size, style='pkcs7')


def RemovePKCS7Padding(padded_data, block_size=BLOCK_SIZE):
    """
    移除PKCS#7填充
    传入值: 
        padded_data (bytes) - 填充后的数据
        block_size (int) - 块大小，默认16字节
    返回值: bytes - 移除填充后的原始数据
    """
    return unpad(padded_data, block_size, style='pkcs7')


def HashPassword(password):
    """
    对密码进行哈希处理（使用SHA1+MD5双重哈希）
    传入值: 
        password (str) - 原始密码
    返回值: str - 哈希后的密码
    """
    # 先使用SHA1
    sha1_result = CalculateSHA1(password)
    # 再使用MD5
    md5_result = CalculateMD5(sha1_result)
    return md5_result


def VerifyPassword(input_password, stored_hash):
    """
    验证密码是否匹配
    传入值: 
        input_password (str) - 用户输入的密码
        stored_hash (str) - 存储的哈希值
    返回值: bool - 是否匹配
    """
    # 对输入密码进行哈希
    input_hash = HashPassword(input_password)
    
    # 比较哈希值
    return input_hash == stored_hash


# 测试函数
def TestAlgorithms():
    """
    测试所有算法功能
    传入值: 无
    返回值: NULL
    """
    print("="*60)
    print("算法模块测试")
    print("="*60)
    
    # 测试数据
    test_data = "Hello, World! 这是测试数据。"
    
    # 1. 测试MD5
    print("\n1. MD5算法测试:")
    md5_result = CalculateMD5(test_data)
    print(f"   输入: {test_data}")
    print(f"   MD5: {md5_result}")
    
    # 2. 测试SHA1
    print("\n2. SHA1算法测试:")
    sha1_result = CalculateSHA1(test_data)
    print(f"   输入: {test_data}")
    print(f"   SHA1: {sha1_result}")
    
    # 3. 测试RSA加密解密
    print("\n3. RSA算法测试:")
    print("   生成RSA密钥对...")
    private_key, public_key = GenerateRSAKeyPair(2048)
    print("   密钥对生成成功！")
    
    # 导出密钥
    ExportRSAPrivateKey(private_key, 'key.txt')
    print("   私钥已保存到 key.txt")
    
    # 短文本加密测试
    short_text = "Test Message"
    print(f"\n   加密短文本: {short_text}")
    encrypted = EncryptWithRSA(short_text, public_key)
    print(f"   密文(Base64): {encrypted[:50]}...")
    
    decrypted = DecryptWithRSA(encrypted, private_key)
    print(f"   解密结果: {decrypted}")
    print(f"   解密成功: {decrypted == short_text}")
    
    # 长文本加密测试（ECB模式）
    long_text = "This is a longer message that needs to be encrypted in multiple blocks using ECB mode simulation." * 3
    print(f"\n   加密长文本 ({len(long_text)} 字节)")
    encrypted_long = EncryptWithRSAECB(long_text, public_key)
    print(f"   密文长度: {len(encrypted_long)} 字符")
    
    decrypted_long = DecryptWithRSAECB(encrypted_long, private_key)
    print(f"   解密成功: {decrypted_long == long_text}")
    
    # 4. 测试密码哈希
    print("\n4. 密码哈希测试:")
    password = "MySecurePassword123"
    hashed_pwd = HashPassword(password)
    print(f"   原始密码: {password}")
    print(f"   哈希结果: {hashed_pwd}")
    print(f"   验证正确密码: {VerifyPassword(password, hashed_pwd)}")
    print(f"   验证错误密码: {VerifyPassword('WrongPassword', hashed_pwd)}")
    
    # 5. 测试PKCS#7填充
    print("\n5. PKCS#7填充测试:")
    test_bytes = b"Test data for padding"
    padded = ApplyPKCS7Padding(test_bytes)
    print(f"   原始数据长度: {len(test_bytes)} 字节")
    print(f"   填充后长度: {len(padded)} 字节")
    unpadded = RemovePKCS7Padding(padded)
    print(f"   移除填充后: {len(unpadded)} 字节")
    print(f"   数据一致性: {unpadded == test_bytes}")
    
    print("\n" + "="*60)
    print("所有测试完成！")
    print("="*60)


if __name__ == '__main__':
    # 运行测试
    TestAlgorithms()
