"""
web.py - 远程通信模块
用于从前端接收用户登录数据
"""

import socket
import json

# 常量定义
SERVER_IP = "192.114.514"
SERVER_PORT = 8080
BUFFER_SIZE = 4096

def ReceiveLoginData():
    """
    传入值: NULL
    返回值: dict - 包含用户名、密码、cookie信息的字典
            {
                "pre_user_name": str,
                "pre_user_psw": str,
                "pre_cookie": str
            }
            若接收失败返回 None
    """
    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((SERVER_IP, SERVER_PORT))
        
        raw_data = client_socket.recv(BUFFER_SIZE)
        client_socket.close()
        
        json_data = json.loads(raw_data.decode('utf-8'))
        
        pre_user_name = json_data.get("username", "")
        pre_user_psw = json_data.get("password", "")
        pre_cookie = json_data.get("cookie", "")
        
        ret_data = {
            "pre_user_name": pre_user_name,
            "pre_user_psw": pre_user_psw,
            "pre_cookie": pre_cookie
        }
        
        return ret_data
    
    except Exception as e:
        print(f"接收数据失败: {e}")
        return None


def SendResponse(ret_status, ret_message):
    """
    传入值: ret_status - 响应状态码 (int)
            ret_message - 响应消息 (str)
    返回值: bool - 发送成功返回 True，失败返回 False
    """
    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((SERVER_IP, SERVER_PORT))
        
        response_data = {
            "ret_status": ret_status,
            "ret_message": ret_message
        }
        
        json_response = json.dumps(response_data).encode('utf-8')
        client_socket.send(json_response)
        client_socket.close()
        
        return True
    
    except Exception as e:
        print(f"发送响应失败: {e}")
        return False


# 验证相关常量
MAX_USER_NAME_LENGTH = 8
MIN_PASSWORD_LENGTH = 6
MAX_PASSWORD_LENGTH = 12
COOKIE_FLAG_TAG = "flag"


def ValidateLoginData(pre_user_name, pre_user_psw, pre_cookie):
    """
    传入值: pre_user_name - 用户名 (str)
            pre_user_psw - 用户密码 (str)
            pre_cookie - cookie信息 (str)
    返回值: tuple - (验证结果 bool, 错误信息 str)
            验证通过返回 (True, "ret_OK")
            验证失败返回 (False, 错误信息)
    """
    # 验证用户名长度
    user_name_length = len(pre_user_name)
    if user_name_length > MAX_USER_NAME_LENGTH:
        ret_message = "长度违法"
        return (False, ret_message)
    
    # 验证密码长度
    password_length = len(pre_user_psw)
    if password_length <= MIN_PASSWORD_LENGTH or password_length > MAX_PASSWORD_LENGTH:
        ret_message = "长度违法"
        return (False, ret_message)
    
    # 验证cookie中是否包含flag标签
    if COOKIE_FLAG_TAG not in pre_cookie:
        ret_message = "cookie错误"
        return (False, ret_message)
    
    ret_message = "ret_OK"
    return (True, ret_message)
