"""
Web通信模块 - 负责接收前端传入的登录数据
"""

from flask import Flask, request, jsonify
import json

app = Flask(__name__)

# 常量定义
SERVER_IP = "192.114.514.1"  # 服务器IP地址
SERVER_PORT = 5000  # 服务器端口
MAX_USERNAME_LENGTH = 8  # 用户名最大长度
MIN_PASSWORD_LENGTH = 6  # 密码最小长度
MAX_PASSWORD_LENGTH = 12  # 密码最大长度
REQUIRED_COOKIE_FLAG = "flag"  # cookie中必需的标签

def ValidateLoginData(pre_user_name, pre_user_psw, pre_cookie):
    """
    验证登录数据的合法性
    传入值: 
        pre_user_name (str) - 用户名
        pre_user_psw (str) - 密码
        pre_cookie (dict) - cookie信息
    返回值: tuple - (是否合法: bool, 错误信息: str)
    """
    # 验证用户名长度
    if len(pre_user_name) > MAX_USERNAME_LENGTH:
        ret_ERR = "长度违法"
        return False, ret_ERR
    
    # 验证密码长度
    if len(pre_user_psw) <= MIN_PASSWORD_LENGTH or len(pre_user_psw) > MAX_PASSWORD_LENGTH:
        ret_ERR = "长度违法"
        return False, ret_ERR
    
    # 验证cookie中是否包含flag标签
    if REQUIRED_COOKIE_FLAG not in pre_cookie:
        ret_ERR = "cookie错误"
        return False, ret_ERR
    
    # 验证通过
    ret_OK = "验证成功"
    return True, ret_OK


def ReceiveLoginData():
    """
    从远程接收登录数据
    传入值: 无 (从HTTP请求中获取)
    返回值: dict - 包含用户名、密码、cookie信息的字典
    """
    try:
        # 获取请求数据
        data = request.get_json()
        
        # 提取前端传入的数据
        pre_user_name = data.get('username', '')
        pre_user_psw = data.get('password', '')
        pre_cookie = request.cookies.to_dict()
        
        # 将数据封装到字典中
        login_data = {
            'pre_user_name': pre_user_name,
            'pre_user_psw': pre_user_psw,
            'pre_cookie': pre_cookie
        }
        
        return login_data
    except Exception as e:
        print(f"接收数据时发生错误: {e}")
        return None


@app.route('/login', methods=['POST'])
def HandleLoginRequest():
    """
    处理登录请求的路由函数
    传入值: 无 (从HTTP请求中获取)
    返回值: JSON响应
    """
    # 接收登录数据
    login_data = ReceiveLoginData()
    
    if login_data is None:
        return jsonify({
            'status': 'error',
            'message': '数据接收失败'
        }), 400
    
    # 验证登录数据
    is_valid, validation_message = ValidateLoginData(
        login_data['pre_user_name'],
        login_data['pre_user_psw'],
        login_data['pre_cookie']
    )
    
    if not is_valid:
        return jsonify({
            'status': 'error',
            'message': validation_message
        }), 400
    
    # 将数据写入共享文件供其他模块使用
    try:
        with open('share.txt', 'w', encoding='utf-8') as f:
            json.dump(login_data, f, ensure_ascii=False)
    except Exception as e:
        print(f"写入共享文件时发生错误: {e}")
        return jsonify({
            'status': 'error',
            'message': '数据处理失败'
        }), 500
    
    # 这里可以调用其他模块进行验证处理
    # 暂时返回接收成功的消息
    return jsonify({
        'status': 'success',
        'message': '数据接收成功',
        'data': {
            'username': login_data['pre_user_name']
        }
    }), 200


def StartServer():
    """
    启动Web服务器
    传入值: 无
    返回值: NULL
    """
    app.run(host=SERVER_IP, port=SERVER_PORT, debug=True)


if __name__ == '__main__':
    print(f"服务器启动于 {SERVER_IP}:{SERVER_PORT}")
    StartServer()
