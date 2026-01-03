import hashlib
from Crypto.PublicKey import RSA
from Crypto.Util.number import bytes_to_long, long_to_bytes
import os
import sys
import pandas as pd
from datetime import datetime

def Md5Hash(pre_data):
    """
    功能: 计算MD5哈希
    传入值: pre_data (bytes or str)
    返回值: hex string
    """
    if isinstance(pre_data, str):
        pre_data = pre_data.encode('utf-8')
    return hashlib.md5(pre_data).hexdigest()

def Sha1Hash(pre_data):
    """
    功能: 计算SHA1哈希
    传入值: pre_data (bytes or str)
    返回值: hex string
    """
    if isinstance(pre_data, str):
        pre_data = pre_data.encode('utf-8')
    return hashlib.sha1(pre_data).hexdigest()

def Pkcs7Padding(data, block_size):
    """
    功能: PKCS#7 填充
    传入值: data (bytes), block_size (int)
    返回值: padded bytes
    """
    padding_len = block_size - (len(data) % block_size)
    padding = bytes([padding_len] * padding_len)
    return data + padding

def Pkcs7Unpadding(data):
    """
    功能: PKCS#7 去填充
    传入值: data (bytes)
    返回值: unpadded bytes
    """
    if not data:
        return b""
    padding_len = data[-1]
    if padding_len > len(data):
        raise ValueError("Invalid padding")
    return data[:-padding_len]

def RsaEncrypt(pre_data, key_path="key.txt"):
    """
    功能: RSA加密 (ECB模式, PKCS#7填充)
    传入值: pre_data (bytes or str), key_path (str)
    返回值: encrypted bytes
    """
    if isinstance(pre_data, str):
        pre_data = pre_data.encode('utf-8')

    try:
        with open(key_path, 'rb') as f:
            key_data = f.read()
            key = RSA.import_key(key_data)
    except Exception as e:
        print(f"Error loading key: {e}")
        return None

    key_size = key.size_in_bytes()
    input_block_size = key_size - 1
    padded_data = Pkcs7Padding(pre_data, input_block_size)
    encrypted_blocks = []
    
    for i in range(0, len(padded_data), input_block_size):
        block = padded_data[i : i + input_block_size]
        m = bytes_to_long(block)
        pub_key = key.publickey()
        c = pow(m, pub_key.e, pub_key.n)
        c_bytes = long_to_bytes(c, key_size)
        encrypted_blocks.append(c_bytes)
        
    return b"".join(encrypted_blocks)

def RsaDecrypt(pre_data, key_path="key.txt"):
    """
    功能: RSA解密 (ECB模式, PKCS#7去填充)
    传入值: pre_data (bytes), key_path (str)
    返回值: decrypted bytes
    """
    try:
        with open(key_path, 'rb') as f:
            key_data = f.read()
            key = RSA.import_key(key_data)
    except Exception as e:
        print(f"Error loading key: {e}")
        return None

    key_size = key.size_in_bytes()
    if len(pre_data) % key_size != 0:
        print("Error: Ciphertext length is not a multiple of key size")
        return None
        
    decrypted_blocks = []
    for i in range(0, len(pre_data), key_size):
        block = pre_data[i : i + key_size]
        c = bytes_to_long(block)
        m = pow(c, key.d, key.n)
        m_bytes = long_to_bytes(m)
        input_block_size = key_size - 1
        if len(m_bytes) < input_block_size:
            m_bytes = b'\x00' * (input_block_size - len(m_bytes)) + m_bytes
        decrypted_blocks.append(m_bytes)
        
    full_padded_data = b"".join(decrypted_blocks)
    try:
        return Pkcs7Unpadding(full_padded_data)
    except Exception as e:
        print(f"Unpadding error: {e}")
        return None

def VerifyAndLogUser(pre_user_name, pre_user_psw_md5, pre_user_ip):
    """
    功能: 验证用户并记录登录信息
    传入值: pre_user_name, pre_user_psw_md5, pre_user_ip
    返回值: "OK" or "FAIL: reason"
    """
    try:
        file_path = 'DATA.xlsx'
        if not os.path.exists(file_path):
             return "FAIL: DATA.xlsx not found"

        df = pd.read_excel(file_path)
        
        # 查找用户
        user_row = df[df['NAME'] == pre_user_name]
        
        if user_row.empty:
            return "FAIL: User not found"
            
        # 验证密码 (Excel中存储的应该是MD5)
        stored_md5 = user_row.iloc[0]['PASSWORD(MD5)']
        
        # 简单的比较，注意类型
        if str(stored_md5).lower() != str(pre_user_psw_md5).lower():
            return "FAIL: Password incorrect"
            
        # 更新登录时间和IP
        idx = user_row.index[0]
        df.at[idx, 'LAST_LOGIN_TIME'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        df.at[idx, 'LAST_LOGIN_IP'] = pre_user_ip
        
        # 保存回文件
        df.to_excel(file_path, index=False)
        
        return "OK"
    except Exception as e:
        return f"FAIL: {str(e)}"

def TestAlgorithm():
    """
    功能: 测试算法模块
    """
    print("请输入测试数据:")
    try:
        if sys.stdin.isatty():
            raw_data = input()
        else:
            raw_data = "test_data"
            print(f"(自动输入): {raw_data}")
    except EOFError:
        raw_data = "test_data"

    if not raw_data:
        raw_data = "test_data"
    
    # MD5 Test
    try:
        md5_res = Md5Hash(raw_data)
        if md5_res:
            print("MD5算法，结果为OK")
        else:
            print("MD5算法，结果为ERROR")
    except Exception:
        print("MD5算法，结果为ERROR")

    # SHA1 Test
    try:
        sha1_res = Sha1Hash(raw_data)
        if sha1_res:
            print("SHA1算法，结果为OK")
        else:
            print("SHA1算法，结果为ERROR")
    except Exception:
        print("SHA1算法，结果为ERROR")

    # RSA Test
    try:
        enc_res = RsaEncrypt(raw_data)
        if enc_res:
            dec_res = RsaDecrypt(enc_res)
            if dec_res and dec_res.decode('utf-8') == raw_data:
                print("RSA加密以及解密算法，结果为OK")
            else:
                print("RSA加密以及解密算法，结果为ERROR")
        else:
            print("RSA加密以及解密算法，结果为ERROR")
    except Exception as e:
        print(f"RSA加密以及解密算法，结果为ERROR")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        command = sys.argv[1]
        if command == "md5":
            if len(sys.argv) > 2:
                print(Md5Hash(sys.argv[2]))
            else:
                print("ERROR: Missing argument for md5")
        elif command == "verify_user":
            if len(sys.argv) > 4:
                # verify_user <username> <password_md5> <ip>
                print(VerifyAndLogUser(sys.argv[2], sys.argv[3], sys.argv[4]))
            else:
                print("ERROR: Missing arguments for verify_user")
        elif command == "test":
            TestAlgorithm()
        else:
            print("Unknown command")
    else:
        TestAlgorithm()
            raw_data = input()
        else:
            raw_data = "test_data"
            print(f"(自动输入): {raw_data}")
    except EOFError:
        raw_data = "test_data"

    if not raw_data:
        raw_data = "test_data"
    
    # MD5 Test
    try:
        md5_res = Md5Hash(raw_data)
        if md5_res:
            print("MD5算法，结果为OK")
        else:
            print("MD5算法，结果为ERROR")
    except Exception:
        print("MD5算法，结果为ERROR")

    # SHA1 Test
    try:
        sha1_res = Sha1Hash(raw_data)
        if sha1_res:
            print("SHA1算法，结果为OK")
        else:
            print("SHA1算法，结果为ERROR")
    except Exception:
        print("SHA1算法，结果为ERROR")

    # RSA Test
    try:
        enc_res = RsaEncrypt(raw_data)
        if enc_res:
            dec_res = RsaDecrypt(enc_res)
            # 解密出来的是 bytes，需要 decode 比较
            if dec_res and dec_res.decode('utf-8') == raw_data:
                print("RSA加密以及解密算法，结果为OK")
            else:
                print("RSA加密以及解密算法，结果为ERROR")
        else:
            print("RSA加密以及解密算法，结果为ERROR")
    except Exception as e:
        print(f"RSA加密以及解密算法，结果为ERROR")

if __name__ == "__main__":
    TestAlgorithm()
