import hashlib
from Crypto.PublicKey import RSA
from Crypto.Util.number import bytes_to_long, long_to_bytes
import os

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

    # 获取模数长度(字节)
    key_size = key.size_in_bytes()
    
    # 为了确保 m < n，我们使用 key_size - 1 作为输入块大小
    # 这样填充后的每个块都能被安全加密
    input_block_size = key_size - 1
    
    # PKCS#7 填充
    padded_data = Pkcs7Padding(pre_data, input_block_size)
    
    encrypted_blocks = []
    
    # ECB 模式: 分组加密
    for i in range(0, len(padded_data), input_block_size):
        block = padded_data[i : i + input_block_size]
        
        # 将块转换为整数
        m = bytes_to_long(block)
        
        # 加密: c = m^e mod n
        # 使用公钥进行加密
        pub_key = key.publickey()
        c = pow(m, pub_key.e, pub_key.n)
        
        # 将密文转回字节，长度固定为 key_size
        c_bytes = long_to_bytes(c, key_size)
        encrypted_blocks.append(c_bytes)
        
    return b"".join(encrypted_blocks)

def RsaDecrypt(pre_data, key_path="key.txt"):
    """
    功能: RSA解密 (ECB模式, PKCS#7去填充)
    传入值: pre_data (bytes), key_path (str)
    返回值: decrypted bytes (or str if possible, but returning bytes is safer)
    """
    try:
        with open(key_path, 'rb') as f:
            key_data = f.read()
            key = RSA.import_key(key_data)
    except Exception as e:
        print(f"Error loading key: {e}")
        return None

    key_size = key.size_in_bytes()
    
    # 密文块大小应该等于 key_size
    if len(pre_data) % key_size != 0:
        print("Error: Ciphertext length is not a multiple of key size")
        return None
        
    decrypted_blocks = []
    
    # ECB 模式: 分组解密
    for i in range(0, len(pre_data), key_size):
        block = pre_data[i : i + key_size]
        
        c = bytes_to_long(block)
        
        # 解密: m = c^d mod n
        m = pow(c, key.d, key.n)
        
        # 转回字节
        # 注意：这里转换回来的字节数可能小于 input_block_size，需要补齐吗？
        # bytes_to_long / long_to_bytes 是可逆的，但前导零会丢失。
        # PKCS#7 填充的数据块如果开头是0，bytes_to_long会忽略。
        # 但是我们选取的 input_block_size 是 key_size - 1。
        # 只要我们填充后的数据块转成int再转回来，如果丢失前导0，拼接回去可能会有问题。
        # 更好的做法是 pad 到 input_block_size。
        
        m_bytes = long_to_bytes(m)
        
        # 补齐前导零到 input_block_size (key_size - 1)
        # 因为我们在加密时是把 input_block_size 长度的 bytes 转为 long
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
