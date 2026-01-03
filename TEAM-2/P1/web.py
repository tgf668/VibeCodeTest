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
