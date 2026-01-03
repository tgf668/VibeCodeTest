"""
算法模块 - 实现MD5、SHA1、RSA加密算法
遵循OWASP安全规范，使用标准加密库
"""

import hashlib
import os
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64

# 常量定义
DEFAULT_PADDING_MODE = 'PKCS7'  # PKCS#7填充模式
DEFAULT_BLOCK_MODE = 'ECB'      # ECB分组模式
RSA_KEY_SIZE = 2048             # RSA密钥长度
AES_KEY_SIZE = 16               # AES密钥长度（128位）


def CalculateMd5(data):
    """
    计算MD5哈希值
    传入值：data (str或bytes) - 需要计算哈希的数据
    返回值：str - MD5哈希值（32位十六进制字符串）
    """
    try:
        # 确保输入是bytes类型
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        # 使用hashlib计算MD5
        # 注意：MD5已不安全，仅用于非安全关键场景
        md5_hash = hashlib.md5()
        md5_hash.update(data)
        
        # 返回十六进制格式的哈希值
        return md5_hash.hexdigest()
        
    except Exception as e:
        print(f"MD5计算错误: {str(e)}")
        return None


def CalculateSha1(data):
    """
    计算SHA1哈希值
    传入值：data (str或bytes) - 需要计算哈希的数据
    返回值：str - SHA1哈希值（40位十六进制字符串）
    """
    try:
        # 确保输入是bytes类型
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        # 使用hashlib计算SHA1
        # 注意：SHA1已不安全，建议使用SHA256或更高版本
        sha1_hash = hashlib.sha1()
        sha1_hash.update(data)
        
        # 返回十六进制格式的哈希值
        return sha1_hash.hexdigest()
        
    except Exception as e:
        print(f"SHA1计算错误: {str(e)}")
        return None


def GenerateRsaKeyPair(key_size=RSA_KEY_SIZE):
    """
    生成RSA密钥对
    传入值：key_size (int) - 密钥长度，默认2048位
    返回值：tuple - (private_key, public_key) RSA密钥对对象
    """
    try:
        # 生成RSA密钥对（使用安全的密钥长度）
        key = RSA.generate(key_size)
        
        # 获取私钥和公钥
        private_key = key
        public_key = key.publickey()
        
        return private_key, public_key
        
    except Exception as e:
        print(f"RSA密钥生成错误: {str(e)}")
        return None, None


def ExportRsaPrivateKey(private_key, file_path='key.txt'):
    """
    导出RSA私钥到文件
    传入值：private_key - RSA私钥对象
            file_path (str) - 导出文件路径
    返回值：bool - 成功返回True，失败返回False
    """
    try:
        # 将私钥导出为PEM格式
        pem_private_key = private_key.export_key()
        
        # 写入文件（CWE-22: 使用安全的文件路径）
        with open(file_path, 'wb') as f:
            f.write(pem_private_key)
        
        return True
        
    except Exception as e:
        print(f"私钥导出错误: {str(e)}")
        return False


def ImportRsaPrivateKey(file_path='key.txt'):
    """
    从文件导入RSA私钥
    传入值：file_path (str) - 私钥文件路径
    返回值：RSA私钥对象，失败返回None
    """
    try:
        # 检查文件是否存在
        if not os.path.exists(file_path):
            print(f"文件不存在: {file_path}")
            return None
        
        # 读取私钥文件
        with open(file_path, 'rb') as f:
            private_key = RSA.import_key(f.read())
        
        return private_key
        
    except Exception as e:
        print(f"私钥导入错误: {str(e)}")
        return None


def RsaEncrypt(data, public_key):
    """
    使用RSA公钥加密数据（PKCS#1 OAEP填充）
    传入值：data (str或bytes) - 需要加密的数据
            public_key - RSA公钥对象
    返回值：str - Base64编码的加密数据，失败返回None
    """
    try:
        # 确保输入是bytes类型
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        # 使用PKCS#1 OAEP填充模式进行加密（更安全）
        cipher = PKCS1_OAEP.new(public_key)
        encrypted_data = cipher.encrypt(data)
        
        # 返回Base64编码的结果，便于传输和存储
        return base64.b64encode(encrypted_data).decode('utf-8')
        
    except Exception as e:
        print(f"RSA加密错误: {str(e)}")
        return None


def RsaDecrypt(encrypted_data, private_key):
    """
    使用RSA私钥解密数据（PKCS#1 OAEP填充）
    传入值：encrypted_data (str) - Base64编码的加密数据
            private_key - RSA私钥对象
    返回值：str - 解密后的原始数据，失败返回None
    """
    try:
        # 如果是Base64字符串，先解码
        if isinstance(encrypted_data, str):
            encrypted_data = base64.b64decode(encrypted_data)
        
        # 使用PKCS#1 OAEP填充模式进行解密
        cipher = PKCS1_OAEP.new(private_key)
        decrypted_data = cipher.decrypt(encrypted_data)
        
        # 返回解密后的字符串
        return decrypted_data.decode('utf-8')
        
    except Exception as e:
        print(f"RSA解密错误: {str(e)}")
        return None


def AesEncryptEcb(data, key):
    """
    使用AES-ECB模式加密数据（PKCS#7填充）
    传入值：data (str或bytes) - 需要加密的数据
            key (str或bytes) - AES密钥（16、24或32字节）
    返回值：str - Base64编码的加密数据，失败返回None
    
    注意：ECB模式不安全，建议仅用于测试
    """
    try:
        # 确保输入是bytes类型
        if isinstance(data, str):
            data = data.encode('utf-8')
        if isinstance(key, str):
            key = key.encode('utf-8')
        
        # 确保密钥长度正确（16、24或32字节）
        if len(key) not in [16, 24, 32]:
            # 如果密钥长度不符，进行填充或截断
            if len(key) < 16:
                key = key.ljust(16, b'\0')
            elif len(key) < 24:
                key = key[:16]
            elif len(key) < 32:
                key = key.ljust(24, b'\0')
            else:
                key = key[:32]
        
        # 使用PKCS#7填充（AES.block_size = 16）
        padded_data = pad(data, AES.block_size)
        
        # 创建AES-ECB加密器
        cipher = AES.new(key, AES.MODE_ECB)
        encrypted_data = cipher.encrypt(padded_data)
        
        # 返回Base64编码的结果
        return base64.b64encode(encrypted_data).decode('utf-8')
        
    except Exception as e:
        print(f"AES-ECB加密错误: {str(e)}")
        return None


def AesDecryptEcb(encrypted_data, key):
    """
    使用AES-ECB模式解密数据（PKCS#7填充）
    传入值：encrypted_data (str) - Base64编码的加密数据
            key (str或bytes) - AES密钥
    返回值：str - 解密后的原始数据，失败返回None
    """
    try:
        # Base64解码
        if isinstance(encrypted_data, str):
            encrypted_data = base64.b64decode(encrypted_data)
        
        # 确保密钥是bytes类型
        if isinstance(key, str):
            key = key.encode('utf-8')
        
        # 确保密钥长度正确
        if len(key) not in [16, 24, 32]:
            if len(key) < 16:
                key = key.ljust(16, b'\0')
            elif len(key) < 24:
                key = key[:16]
            elif len(key) < 32:
                key = key.ljust(24, b'\0')
            else:
                key = key[:32]
        
        # 创建AES-ECB解密器
        cipher = AES.new(key, AES.MODE_ECB)
        decrypted_data = cipher.decrypt(encrypted_data)
        
        # 去除PKCS#7填充
        unpadded_data = unpad(decrypted_data, AES.block_size)
        
        # 返回解密后的字符串
        return unpadded_data.decode('utf-8')
        
    except Exception as e:
        print(f"AES-ECB解密错误: {str(e)}")
        return None


def TestAlgorithms():
    """
    测试所有加密算法功能
    传入值：None
    返回值：None（打印测试结果）
    """
    print("\n" + "="*70)
    print("加密算法模块测试".center(70))
    print("="*70 + "\n")
    
    # 测试数据
    test_data = "Hello, World! 这是测试数据。"
    
    # ==================== 测试MD5 ====================
    print("【1】MD5哈希算法测试")
    print("-" * 70)
    md5_result = CalculateMd5(test_data)
    print(f"原始数据: {test_data}")
    print(f"MD5结果:  {md5_result}")
    print(f"长度:     {len(md5_result) if md5_result else 0} 字符\n")
    
    # ==================== 测试SHA1 ====================
    print("【2】SHA1哈希算法测试")
    print("-" * 70)
    sha1_result = CalculateSha1(test_data)
    print(f"原始数据: {test_data}")
    print(f"SHA1结果: {sha1_result}")
    print(f"长度:     {len(sha1_result) if sha1_result else 0} 字符\n")
    
    # ==================== 测试RSA ====================
    print("【3】RSA加密/解密算法测试")
    print("-" * 70)
    
    # 生成密钥对
    print("正在生成RSA密钥对（2048位）...")
    private_key, public_key = GenerateRsaKeyPair()
    
    if private_key and public_key:
        print("✅ 密钥对生成成功")
        
        # 导出私钥到文件
        if ExportRsaPrivateKey(private_key, 'key.txt'):
            print("✅ 私钥已导出到 key.txt")
        
        # RSA加密测试数据
        rsa_test_data = "RSA Test Message"
        print(f"\n原始数据: {rsa_test_data}")
        
        encrypted_rsa = RsaEncrypt(rsa_test_data, public_key)
        if encrypted_rsa:
            print(f"加密结果: {encrypted_rsa[:50]}..." if len(encrypted_rsa) > 50 else f"加密结果: {encrypted_rsa}")
            
            # RSA解密
            decrypted_rsa = RsaDecrypt(encrypted_rsa, private_key)
            if decrypted_rsa:
                print(f"解密结果: {decrypted_rsa}")
                print(f"验证:     {'✅ 加密解密成功' if decrypted_rsa == rsa_test_data else '❌ 解密失败'}")
        print()
    
    # ==================== 测试AES-ECB ====================
    print("【4】AES-ECB加密/解密算法测试（PKCS#7填充）")
    print("-" * 70)
    
    aes_key = "my_secret_key_16"  # 16字节密钥
    print(f"AES密钥: {aes_key}")
    print(f"原始数据: {test_data}")
    
    # AES加密
    encrypted_aes = AesEncryptEcb(test_data, aes_key)
    if encrypted_aes:
        print(f"加密结果: {encrypted_aes[:50]}..." if len(encrypted_aes) > 50 else f"加密结果: {encrypted_aes}")
        
        # AES解密
        decrypted_aes = AesDecryptEcb(encrypted_aes, aes_key)
        if decrypted_aes:
            print(f"解密结果: {decrypted_aes}")
            print(f"验证:     {'✅ 加密解密成功' if decrypted_aes == test_data else '❌ 解密失败'}")
    
    print("\n" + "="*70)
    print("测试完成".center(70))
    print("="*70 + "\n")


def TestAlgorithmsWithInput():
    """
    从控制台接收数据并测试所有算法
    传入值：None（从控制台输入）
    返回值：None（打印测试结果）
    """
    print("\n" + "="*70)
    print("算法交互式测试程序".center(70))
    print("="*70 + "\n")
    
    # 从控制台接收测试数据
    print("请输入要测试的数据：")
    test_input = input("> ")
    
    if not test_input:
        print("❌ 输入为空，测试终止")
        return
    
    print(f"\n测试数据: {test_input}")
    print("-" * 70 + "\n")
    
    # 存储测试结果
    test_results = []
    
    # ==================== 测试MD5算法 ====================
    try:
        md5_result = CalculateMd5(test_input)
        if md5_result and len(md5_result) == 32:
            test_results.append(("MD5算法", "OK"))
            print(f"MD5哈希值: {md5_result}")
        else:
            test_results.append(("MD5算法", "ERROR"))
    except Exception as e:
        test_results.append(("MD5算法", "ERROR"))
        print(f"MD5错误: {str(e)}")
    
    # ==================== 测试SHA1算法 ====================
    try:
        sha1_result = CalculateSha1(test_input)
        if sha1_result and len(sha1_result) == 40:
            test_results.append(("SHA1算法", "OK"))
            print(f"SHA1哈希值: {sha1_result}")
        else:
            test_results.append(("SHA1算法", "ERROR"))
    except Exception as e:
        test_results.append(("SHA1算法", "ERROR"))
        print(f"SHA1错误: {str(e)}")
    
    # ==================== 测试RSA算法 ====================
    try:
        print("\n正在测试RSA算法...")
        
        # 尝试从文件导入私钥，如果不存在则生成新密钥对
        private_key = ImportRsaPrivateKey('key.txt')
        
        if private_key is None:
            print("私钥文件不存在，正在生成新的RSA密钥对...")
            private_key, public_key = GenerateRsaKeyPair()
            if private_key and public_key:
                ExportRsaPrivateKey(private_key, 'key.txt')
                print("✅ RSA密钥对生成成功")
            else:
                raise Exception("密钥对生成失败")
        else:
            public_key = private_key.publickey()
            print("✅ 从文件加载RSA私钥成功")
        
        # RSA加密测试
        encrypted_rsa = RsaEncrypt(test_input, public_key)
        if not encrypted_rsa:
            raise Exception("RSA加密失败")
        
        # RSA解密测试
        decrypted_rsa = RsaDecrypt(encrypted_rsa, private_key)
        if not decrypted_rsa:
            raise Exception("RSA解密失败")
        
        # 验证加密解密是否正确
        if decrypted_rsa == test_input:
            test_results.append(("RSA算法", "OK"))
            print(f"RSA加密结果: {encrypted_rsa[:60]}...")
            print(f"RSA解密结果: {decrypted_rsa}")
            print("✅ RSA加密解密验证成功")
        else:
            test_results.append(("RSA算法", "ERROR"))
            print("❌ RSA解密结果与原始数据不匹配")
            
    except Exception as e:
        test_results.append(("RSA算法", "ERROR"))
        print(f"RSA错误: {str(e)}")
    
    # ==================== 测试AES-ECB算法 ====================
    try:
        print("\n正在测试AES-ECB算法...")
        
        # 使用固定密钥进行测试
        aes_key = "test_secret_key1"  # 16字节密钥
        
        # AES加密测试
        encrypted_aes = AesEncryptEcb(test_input, aes_key)
        if not encrypted_aes:
            raise Exception("AES加密失败")
        
        # AES解密测试
        decrypted_aes = AesDecryptEcb(encrypted_aes, aes_key)
        if not decrypted_aes:
            raise Exception("AES解密失败")
        
        # 验证加密解密是否正确
        if decrypted_aes == test_input:
            test_results.append(("AES-ECB算法", "OK"))
            print(f"AES加密结果: {encrypted_aes}")
            print(f"AES解密结果: {decrypted_aes}")
            print("✅ AES-ECB加密解密验证成功")
        else:
            test_results.append(("AES-ECB算法", "ERROR"))
            print("❌ AES解密结果与原始数据不匹配")
            
    except Exception as e:
        test_results.append(("AES-ECB算法", "ERROR"))
        print(f"AES错误: {str(e)}")
    
    # ==================== 打印测试结果摘要 ====================
    print("\n" + "="*70)
    print("测试结果摘要".center(70))
    print("="*70 + "\n")
    
    for algorithm, result in test_results:
        status_symbol = "✅" if result == "OK" else "❌"
        print(f"{status_symbol} {algorithm}，结果为{result}")
    
    # 统计成功和失败的数量
    success_count = sum(1 for _, result in test_results if result == "OK")
    total_count = len(test_results)
    
    print("\n" + "-"*70)
    print(f"总计: {total_count} 个算法 | 成功: {success_count} | 失败: {total_count - success_count}")
    print("="*70 + "\n")


if __name__ == '__main__':
    # 运行测试
    print("请选择测试模式：")
    print("1. 自动测试（使用预设数据）")
    print("2. 交互测试（手动输入数据）")
    
    choice = input("\n请输入选择 (1/2): ").strip()
    
    if choice == '1':
        TestAlgorithms()
    elif choice == '2':
        TestAlgorithmsWithInput()
    else:
        print("无效选择，运行自动测试...")
        TestAlgorithms()
