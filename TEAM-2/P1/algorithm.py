"""
algorithm.py - 算法模块
实现MD5、SHA1、RSA加密解密算法
"""

import hashlib
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad
import base64
import os

# ==================== 常量定义 ====================

DEFAULT_PADDING_MODE = "PKCS7"
DEFAULT_BLOCK_MODE = "ECB"
RSA_KEY_SIZE = 2048
AES_BLOCK_SIZE = 16


# ==================== MD5 算法 ====================

def CalculateMd5(pre_data):
    """
    传入值: pre_data - 待计算的数据 (str 或 bytes)
    返回值: str - MD5哈希值（32位十六进制字符串）
    """
    if isinstance(pre_data, str):
        pre_data = pre_data.encode('utf-8')
    
    md5_hash = hashlib.md5()
    md5_hash.update(pre_data)
    ret_hash = md5_hash.hexdigest()
    
    return ret_hash


def CalculateMd5File(pre_file_path):
    """
    传入值: pre_file_path - 文件路径 (str)
    返回值: str - 文件的MD5哈希值，若文件不存在返回 None
    """
    if not os.path.exists(pre_file_path):
        return None
    
    md5_hash = hashlib.md5()
    
    with open(pre_file_path, 'rb') as file:
        for chunk in iter(lambda: file.read(4096), b''):
            md5_hash.update(chunk)
    
    ret_hash = md5_hash.hexdigest()
    return ret_hash


# ==================== SHA1 算法 ====================

def CalculateSha1(pre_data):
    """
    传入值: pre_data - 待计算的数据 (str 或 bytes)
    返回值: str - SHA1哈希值（40位十六进制字符串）
    """
    if isinstance(pre_data, str):
        pre_data = pre_data.encode('utf-8')
    
    sha1_hash = hashlib.sha1()
    sha1_hash.update(pre_data)
    ret_hash = sha1_hash.hexdigest()
    
    return ret_hash


def CalculateSha1File(pre_file_path):
    """
    传入值: pre_file_path - 文件路径 (str)
    返回值: str - 文件的SHA1哈希值，若文件不存在返回 None
    """
    if not os.path.exists(pre_file_path):
        return None
    
    sha1_hash = hashlib.sha1()
    
    with open(pre_file_path, 'rb') as file:
        for chunk in iter(lambda: file.read(4096), b''):
            sha1_hash.update(chunk)
    
    ret_hash = sha1_hash.hexdigest()
    return ret_hash


# ==================== RSA 算法 ====================

def GenerateRsaKeyPair(pre_key_size=RSA_KEY_SIZE):
    """
    传入值: pre_key_size - 密钥长度 (int)，默认2048位
    返回值: tuple - (私钥PEM, 公钥PEM)
    """
    rsa_key = RSA.generate(pre_key_size)
    
    ret_private_key = rsa_key.export_key().decode('utf-8')
    ret_public_key = rsa_key.publickey().export_key().decode('utf-8')
    
    return (ret_private_key, ret_public_key)


def RsaEncrypt(pre_data, pre_public_key):
    """
    传入值: pre_data - 待加密的数据 (str 或 bytes)
            pre_public_key - RSA公钥 (str，PEM格式)
    返回值: str - Base64编码的加密数据，失败返回 None
    """
    try:
        if isinstance(pre_data, str):
            pre_data = pre_data.encode('utf-8')
        
        public_key = RSA.import_key(pre_public_key)
        cipher = PKCS1_OAEP.new(public_key)
        
        encrypted_data = cipher.encrypt(pre_data)
        ret_encrypted = base64.b64encode(encrypted_data).decode('utf-8')
        
        return ret_encrypted
    
    except Exception as e:
        print(f"RSA加密失败: {e}")
        return None


def RsaDecrypt(pre_encrypted_data, pre_private_key):
    """
    传入值: pre_encrypted_data - Base64编码的加密数据 (str)
            pre_private_key - RSA私钥 (str，PEM格式)
    返回值: str - 解密后的原始数据，失败返回 None
    """
    try:
        encrypted_bytes = base64.b64decode(pre_encrypted_data)
        
        private_key = RSA.import_key(pre_private_key)
        cipher = PKCS1_OAEP.new(private_key)
        
        decrypted_data = cipher.decrypt(encrypted_bytes)
        ret_decrypted = decrypted_data.decode('utf-8')
        
        return ret_decrypted
    
    except Exception as e:
        print(f"RSA解密失败: {e}")
        return None


def SaveRsaPrivateKey(pre_private_key, pre_file_path):
    """
    传入值: pre_private_key - RSA私钥 (str，PEM格式)
            pre_file_path - 保存路径 (str)
    返回值: bool - 保存成功返回 True，失败返回 False
    """
    try:
        with open(pre_file_path, 'w') as file:
            file.write(pre_private_key)
        return True
    except Exception as e:
        print(f"保存私钥失败: {e}")
        return False


def LoadRsaPrivateKey(pre_file_path):
    """
    传入值: pre_file_path - 私钥文件路径 (str)
    返回值: str - RSA私钥，若文件不存在或读取失败返回 None
    """
    try:
        if not os.path.exists(pre_file_path):
            return None
        
        with open(pre_file_path, 'r') as file:
            ret_private_key = file.read()
        
        return ret_private_key
    
    except Exception as e:
        print(f"读取私钥失败: {e}")
        return None


# ==================== AES 算法 (ECB模式，PKCS7填充) ====================

def AesEncryptEcb(pre_data, pre_key):
    """
    传入值: pre_data - 待加密的数据 (str 或 bytes)
            pre_key - AES密钥 (str 或 bytes)，长度必须为16/24/32字节
    返回值: str - Base64编码的加密数据，失败返回 None
    说明: 使用ECB分组模式和PKCS7填充
    """
    try:
        if isinstance(pre_data, str):
            pre_data = pre_data.encode('utf-8')
        
        if isinstance(pre_key, str):
            pre_key = pre_key.encode('utf-8')
        
        # PKCS7填充
        padded_data = pad(pre_data, AES_BLOCK_SIZE, style='pkcs7')
        
        # ECB模式加密
        cipher = AES.new(pre_key, AES.MODE_ECB)
        encrypted_data = cipher.encrypt(padded_data)
        
        ret_encrypted = base64.b64encode(encrypted_data).decode('utf-8')
        return ret_encrypted
    
    except Exception as e:
        print(f"AES加密失败: {e}")
        return None


def AesDecryptEcb(pre_encrypted_data, pre_key):
    """
    传入值: pre_encrypted_data - Base64编码的加密数据 (str)
            pre_key - AES密钥 (str 或 bytes)，长度必须为16/24/32字节
    返回值: str - 解密后的原始数据，失败返回 None
    说明: 使用ECB分组模式和PKCS7填充
    """
    try:
        encrypted_bytes = base64.b64decode(pre_encrypted_data)
        
        if isinstance(pre_key, str):
            pre_key = pre_key.encode('utf-8')
        
        # ECB模式解密
        cipher = AES.new(pre_key, AES.MODE_ECB)
        decrypted_padded = cipher.decrypt(encrypted_bytes)
        
        # 移除PKCS7填充
        ret_decrypted = unpad(decrypted_padded, AES_BLOCK_SIZE, style='pkcs7').decode('utf-8')
        return ret_decrypted
    
    except Exception as e:
        print(f"AES解密失败: {e}")
        return None


def GenerateAesKey(pre_key_size=16):
    """
    传入值: pre_key_size - 密钥长度 (int)，可选16/24/32字节
    返回值: bytes - 随机生成的AES密钥
    """
    ret_key = os.urandom(pre_key_size)
    return ret_key


# ==================== RSA签名与验证 ====================

def RsaSign(pre_data, pre_private_key):
    """
    传入值: pre_data - 待签名的数据 (str 或 bytes)
            pre_private_key - RSA私钥 (str，PEM格式)
    返回值: str - Base64编码的签名，失败返回 None
    """
    try:
        if isinstance(pre_data, str):
            pre_data = pre_data.encode('utf-8')
        
        private_key = RSA.import_key(pre_private_key)
        data_hash = SHA256.new(pre_data)
        signature = pkcs1_15.new(private_key).sign(data_hash)
        
        ret_signature = base64.b64encode(signature).decode('utf-8')
        return ret_signature
    
    except Exception as e:
        print(f"RSA签名失败: {e}")
        return None


def RsaVerify(pre_data, pre_signature, pre_public_key):
    """
    传入值: pre_data - 原始数据 (str 或 bytes)
            pre_signature - Base64编码的签名 (str)
            pre_public_key - RSA公钥 (str，PEM格式)
    返回值: bool - 验证通过返回 True，失败返回 False
    """
    try:
        if isinstance(pre_data, str):
            pre_data = pre_data.encode('utf-8')
        
        signature_bytes = base64.b64decode(pre_signature)
        public_key = RSA.import_key(pre_public_key)
        data_hash = SHA256.new(pre_data)
        
        pkcs1_15.new(public_key).verify(data_hash, signature_bytes)
        return True
    
    except Exception as e:
        print(f"RSA验证失败: {e}")
        return False
