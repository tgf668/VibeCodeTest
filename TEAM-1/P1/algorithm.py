"""
加密算法模块
实现MD5、SHA1、RSA等加密算法
"""

import hashlib
import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
from Crypto import Random

# 常量定义
DEFAULT_RSA_KEY_SIZE = 2048
DEFAULT_PADDING_MODE = 'PKCS7'
DEFAULT_BLOCK_MODE = 'ECB'


def CalculateMd5(data):
    """
    计算MD5哈希值
    传入值: data (str/bytes) - 待加密的数据
    返回值: str - MD5哈希值（十六进制字符串）
    """
    try:
        # 如果是字符串，转换为字节
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        # 创建MD5对象并计算哈希
        md5_hash = hashlib.md5()
        md5_hash.update(data)
        
        return md5_hash.hexdigest()
    
    except Exception as e:
        print(f"MD5计算错误: {e}")
        return None


def CalculateSha1(data):
    """
    计算SHA1哈希值
    传入值: data (str/bytes) - 待加密的数据
    返回值: str - SHA1哈希值（十六进制字符串）
    """
    try:
        # 如果是字符串，转换为字节
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        # 创建SHA1对象并计算哈希
        sha1_hash = hashlib.sha1()
        sha1_hash.update(data)
        
        return sha1_hash.hexdigest()
    
    except Exception as e:
        print(f"SHA1计算错误: {e}")
        return None


def Pkcs7Padding(data, block_size=16):
    """
    PKCS#7填充
    传入值: data (bytes) - 待填充的数据
            block_size (int) - 块大小，默认16字节
    返回值: bytes - 填充后的数据
    """
    try:
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        # 计算需要填充的字节数
        padding_length = block_size - (len(data) % block_size)
        
        # PKCS#7填充：填充字节的值等于填充的字节数
        padding = bytes([padding_length] * padding_length)
        
        return data + padding
    
    except Exception as e:
        print(f"PKCS#7填充错误: {e}")
        return None


def Pkcs7Unpadding(data):
    """
    PKCS#7去填充
    传入值: data (bytes) - 待去填充的数据
    返回值: bytes - 去填充后的数据
    """
    try:
        # 获取填充长度（最后一个字节的值）
        padding_length = data[-1]
        
        # 验证填充是否正确
        if padding_length > len(data):
            raise ValueError("填充数据不正确")
        
        # 移除填充
        return data[:-padding_length]
    
    except Exception as e:
        print(f"PKCS#7去填充错误: {e}")
        return None


def GenerateRsaKeyPair(key_size=DEFAULT_RSA_KEY_SIZE):
    """
    生成RSA密钥对
    传入值: key_size (int) - 密钥长度，默认2048位
    返回值: tuple - (public_key, private_key) 公钥和私钥对象
    """
    try:
        # 生成RSA密钥对
        key = RSA.generate(key_size)
        
        # 导出公钥和私钥
        public_key = key.publickey()
        private_key = key
        
        return public_key, private_key
    
    except Exception as e:
        print(f"RSA密钥生成错误: {e}")
        return None, None


def ExportRsaKey(key, format_type='PEM'):
    """
    导出RSA密钥为字符串格式
    传入值: key (RSA key object) - RSA密钥对象
            format_type (str) - 导出格式，默认PEM
    返回值: str - 导出的密钥字符串
    """
    try:
        key_str = key.export_key(format=format_type)
        return key_str.decode('utf-8')
    
    except Exception as e:
        print(f"RSA密钥导出错误: {e}")
        return None


def ImportRsaKey(key_str):
    """
    从字符串导入RSA密钥
    传入值: key_str (str/bytes) - 密钥字符串
    返回值: RSA key object - RSA密钥对象
    """
    try:
        if isinstance(key_str, str):
            key_str = key_str.encode('utf-8')
        
        key = RSA.import_key(key_str)
        return key
    
    except Exception as e:
        print(f"RSA密钥导入错误: {e}")
        return None


def RsaEncrypt(data, public_key):
    """
    RSA加密（使用OAEP填充模式）
    传入值: data (str/bytes) - 待加密的数据
            public_key (RSA key object) - RSA公钥对象
    返回值: str - Base64编码的加密数据
    """
    try:
        # 如果是字符串，转换为字节
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        # 创建加密器（使用OAEP填充）
        cipher = PKCS1_OAEP.new(public_key)
        
        # 加密数据
        encrypted_data = cipher.encrypt(data)
        
        # 返回Base64编码的结果
        return base64.b64encode(encrypted_data).decode('utf-8')
    
    except Exception as e:
        print(f"RSA加密错误: {e}")
        return None


def RsaDecrypt(encrypted_data, private_key):
    """
    RSA解密（使用OAEP填充模式）
    传入值: encrypted_data (str) - Base64编码的加密数据
            private_key (RSA key object) - RSA私钥对象
    返回值: str - 解密后的原始数据
    """
    try:
        # Base64解码
        encrypted_bytes = base64.b64decode(encrypted_data)
        
        # 创建解密器（使用OAEP填充）
        cipher = PKCS1_OAEP.new(private_key)
        
        # 解密数据
        decrypted_data = cipher.decrypt(encrypted_bytes)
        
        # 返回字符串
        return decrypted_data.decode('utf-8')
    
    except Exception as e:
        print(f"RSA解密错误: {e}")
        return None


def RsaEncryptLongData(data, public_key):
    """
    RSA加密长数据（分块加密）
    传入值: data (str/bytes) - 待加密的数据
            public_key (RSA key object) - RSA公钥对象
    返回值: str - Base64编码的加密数据
    """
    try:
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        # RSA加密块大小（密钥长度/8 - 42，使用OAEP填充）
        key_size = public_key.size_in_bytes()
        chunk_size = key_size - 42
        
        encrypted_chunks = []
        
        # 分块加密
        for i in range(0, len(data), chunk_size):
            chunk = data[i:i + chunk_size]
            cipher = PKCS1_OAEP.new(public_key)
            encrypted_chunk = cipher.encrypt(chunk)
            encrypted_chunks.append(encrypted_chunk)
        
        # 合并加密块并Base64编码
        encrypted_data = b''.join(encrypted_chunks)
        return base64.b64encode(encrypted_data).decode('utf-8')
    
    except Exception as e:
        print(f"RSA长数据加密错误: {e}")
        return None


def RsaDecryptLongData(encrypted_data, private_key):
    """
    RSA解密长数据（分块解密）
    传入值: encrypted_data (str) - Base64编码的加密数据
            private_key (RSA key object) - RSA私钥对象
    返回值: str - 解密后的原始数据
    """
    try:
        # Base64解码
        encrypted_bytes = base64.b64decode(encrypted_data)
        
        # RSA解密块大小等于密钥长度
        key_size = private_key.size_in_bytes()
        
        decrypted_chunks = []
        
        # 分块解密
        for i in range(0, len(encrypted_bytes), key_size):
            chunk = encrypted_bytes[i:i + key_size]
            cipher = PKCS1_OAEP.new(private_key)
            decrypted_chunk = cipher.decrypt(chunk)
            decrypted_chunks.append(decrypted_chunk)
        
        # 合并解密块
        decrypted_data = b''.join(decrypted_chunks)
        return decrypted_data.decode('utf-8')
    
    except Exception as e:
        print(f"RSA长数据解密错误: {e}")
        return None


def SaveKeyToFile(key, file_path):
    """
    将密钥保存到文件
    传入值: key (RSA key object) - RSA密钥对象
            file_path (str) - 文件路径
    返回值: bool - 保存成功返回True，失败返回False
    """
    try:
        key_str = ExportRsaKey(key)
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(key_str)
        return True
    
    except Exception as e:
        print(f"密钥保存错误: {e}")
        return False


def LoadKeyFromFile(file_path):
    """
    从文件加载密钥
    传入值: file_path (str) - 文件路径
    返回值: RSA key object - RSA密钥对象
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            key_str = f.read()
        return ImportRsaKey(key_str)
    
    except Exception as e:
        print(f"密钥加载错误: {e}")
        return None


def RunAlgorithmTests():
    """
    运行算法测试单元
    传入值: 无
    返回值: NULL
    """
    print("\n" + "="*60)
    print("算法模块测试单元")
    print("="*60 + "\n")
    
    # 测试MD5
    print("【测试1】MD5哈希算法")
    test_data = "Hello World"
    md5_result = CalculateMd5(test_data)
    print(f"  原始数据: {test_data}")
    print(f"  MD5结果: {md5_result}")
    print(f"  预期值: b10a8db164e0754105b7a99be72e3fe5")
    print(f"  结果: {'✅ 通过' if md5_result == 'b10a8db164e0754105b7a99be72e3fe5' else '❌ 失败'}\n")
    
    # 测试SHA1
    print("【测试2】SHA1哈希算法")
    sha1_result = CalculateSha1(test_data)
    print(f"  原始数据: {test_data}")
    print(f"  SHA1结果: {sha1_result}")
    print(f"  预期值: 0a4d55a8d778e5022fab701977c5d840bbc486d0")
    print(f"  结果: {'✅ 通过' if sha1_result == '0a4d55a8d778e5022fab701977c5d840bbc486d0' else '❌ 失败'}\n")
    
    # 测试PKCS#7填充
    print("【测试3】PKCS#7填充算法")
    padded_data = Pkcs7Padding("test", block_size=16)
    unpadded_data = Pkcs7Unpadding(padded_data)
    print(f"  原始数据: 'test' (4字节)")
    print(f"  填充后长度: {len(padded_data)}字节")
    print(f"  去填充后: {unpadded_data.decode('utf-8')}")
    print(f"  结果: {'✅ 通过' if unpadded_data.decode('utf-8') == 'test' else '❌ 失败'}\n")
    
    # 测试RSA加密解密
    print("【测试4】RSA加密/解密算法")
    print("  正在生成RSA密钥对（2048位）...")
    public_key, private_key = GenerateRsaKeyPair()
    
    if public_key and private_key:
        print("  ✅ 密钥生成成功")
        
        # 测试短数据加密
        original_text = "Secret Message"
        encrypted = RsaEncrypt(original_text, public_key)
        decrypted = RsaDecrypt(encrypted, private_key)
        
        print(f"  原始数据: {original_text}")
        print(f"  加密后(Base64): {encrypted[:50]}...")
        print(f"  解密后: {decrypted}")
        print(f"  结果: {'✅ 通过' if decrypted == original_text else '❌ 失败'}\n")
        
        # 测试长数据加密
        print("【测试5】RSA长数据加密/解密")
        long_text = "这是一段较长的测试数据，用于验证RSA分块加密功能是否正常工作。" * 5
        encrypted_long = RsaEncryptLongData(long_text, public_key)
        decrypted_long = RsaDecryptLongData(encrypted_long, private_key)
        
        print(f"  原始数据长度: {len(long_text)}字节")
        print(f"  加密后长度: {len(encrypted_long)}字节")
        print(f"  解密后长度: {len(decrypted_long)}字节")
        print(f"  数据一致性: {'✅ 通过' if decrypted_long == long_text else '❌ 失败'}\n")
        
        # 测试密钥导出/导入
        print("【测试6】RSA密钥导出/导入")
        exported_key = ExportRsaKey(private_key)
        imported_key = ImportRsaKey(exported_key)
        
        # 使用导入的密钥解密之前加密的数据
        test_decrypt = RsaDecrypt(encrypted, imported_key)
        print(f"  密钥导出长度: {len(exported_key)}字节")
        print(f"  密钥导入: {'✅ 成功' if imported_key else '❌ 失败'}")
        print(f"  解密测试: {'✅ 通过' if test_decrypt == original_text else '❌ 失败'}\n")
        
        # 测试密钥文件操作
        print("【测试7】密钥文件读写")
        test_key_path = 'test_key.pem'
        save_result = SaveKeyToFile(private_key, test_key_path)
        loaded_key = LoadKeyFromFile(test_key_path)
        
        if loaded_key:
            test_decrypt_file = RsaDecrypt(encrypted, loaded_key)
            print(f"  密钥保存: {'✅ 成功' if save_result else '❌ 失败'}")
            print(f"  密钥加载: {'✅ 成功' if loaded_key else '❌ 失败'}")
            print(f"  解密测试: {'✅ 通过' if test_decrypt_file == original_text else '❌ 失败'}\n")
        
    else:
        print("  ❌ 密钥生成失败\n")
    
    print("="*60)
    print("算法测试完成")
    print("="*60 + "\n")


if __name__ == '__main__':
    # 运行测试
    RunAlgorithmTests()
