import socket
import json

def ReceiveRemoteData():
    """
    功能: 从指定IP接收用户登录信息
    传入值: 无
    返回值: 包含用户信息的字典 (pre_user_name, pre_user_psw, pre_cookie_info)，如果失败返回 None
    """
    # 目标IP地址
    TARGET_IP = "192.114.514"
    # 监听端口
    PORT = 8080
    
    pre_user_name = None
    pre_user_psw = None
    pre_cookie_info = None

    try:
        # 创建 socket 对象
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # 绑定端口
        server_socket.bind(('0.0.0.0', PORT))
        # 开始监听
        server_socket.listen(1)
        
        print(f"Waiting for connection from {TARGET_IP}...")
        
        # 建立连接
        client_socket, addr = server_socket.accept()
        
        # 简单的IP验证 (注意：192.114.514 不是有效的IPv4地址，此处仅为逻辑演示)
        if addr[0] == TARGET_IP:
            # 接收数据
            data = client_socket.recv(1024).decode('utf-8')
            
            # 解析数据 (假设传入的是JSON格式)
            try:
                json_data = json.loads(data)
                pre_user_name = json_data.get('username')
                pre_user_psw = json_data.get('password')
                pre_cookie_info = json_data.get('cookie')
                
                return {
                    "pre_user_name": pre_user_name,
                    "pre_user_psw": pre_user_psw,
                    "pre_cookie_info": pre_cookie_info
                }
            except json.JSONDecodeError:
                print("Error: Invalid JSON data")
        else:
            print(f"Refused connection from {addr[0]}")
            
        client_socket.close()
        
    except Exception as e:
        print(f"Communication error: {e}")
        
    finally:
        if 'server_socket' in locals():
            server_socket.close()

    return None

def ValidateUserData(pre_user_name, pre_user_psw, pre_cookie_info):
    """
    功能: 验证传入的用户数据
    传入值: pre_user_name (用户名), pre_user_psw (密码), pre_cookie_info (cookie信息)
    返回值: 验证结果字符串 ("OK", "长度违法", "cookie错误")
    """
    # 验证用户名长度不超过8位
    if len(pre_user_name) > 8:
        return "长度违法"

    # 验证密码长度大于6位但不超过12位
    if not (6 < len(pre_user_psw) <= 12):
        return "长度违法"

    # cookie中将包含flag的标签
    if "flag" not in pre_cookie_info:
        return "cookie错误"

    return "OK"
