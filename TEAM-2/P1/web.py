"""
web.py - 远程通信模块
用于从前端接收用户登录数据
"""

import socket
import json
from flask import Flask, request, render_template_string, make_response
import unittest

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


# ==================== 本地测试服务器 ====================

LOCAL_TEST_PORT = 5000

app = Flask(__name__)

# 登录页面HTML模板
LOGIN_PAGE_HTML = """
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <title>登录测试</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
            background-color: #f0f0f0;
        }
        .login-box {
            background: white;
            padding: 40px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        h2 { text-align: center; color: #333; }
        input {
            width: 100%;
            padding: 10px;
            margin: 10px 0;
            border: 1px solid #ddd;
            border-radius: 5px;
            box-sizing: border-box;
        }
        button {
            width: 100%;
            padding: 10px;
            background-color: #4CAF50;
            color: white;
            border: none;
            border-radius: 5px;
            cursor: pointer;
        }
        button:hover { background-color: #45a049; }
        .result {
            margin-top: 20px;
            padding: 10px;
            border-radius: 5px;
            text-align: center;
        }
        .success { background-color: #d4edda; color: #155724; }
        .error { background-color: #f8d7da; color: #721c24; }
    </style>
</head>
<body>
    <div class="login-box">
        <h2>登录验证测试</h2>
        <form method="POST" action="/login">
            <input type="text" name="username" placeholder="用户名 (最多8位)" required>
            <input type="password" name="password" placeholder="密码 (7-12位)" required>
            <button type="submit">登录</button>
        </form>
        {% if result %}
        <div class="result {{ 'success' if is_success else 'error' }}">
            {{ result }}
        </div>
        {% endif %}
    </div>
</body>
</html>
"""


@app.route('/')
def ShowLoginPage():
    """
    传入值: NULL
    返回值: str - 登录页面HTML
    """
    response = make_response(render_template_string(LOGIN_PAGE_HTML))
    # 设置包含flag的测试cookie
    response.set_cookie('test_cookie', 'session_flag_12345')
    return response


@app.route('/login', methods=['POST'])
def HandleLogin():
    """
    传入值: NULL (从表单获取数据)
    返回值: str - 验证结果页面HTML
    """
    pre_user_name = request.form.get('username', '')
    pre_user_psw = request.form.get('password', '')
    pre_cookie = str(request.cookies)
    
    is_valid, ret_message = ValidateLoginData(pre_user_name, pre_user_psw, pre_cookie)
    
    return render_template_string(
        LOGIN_PAGE_HTML,
        result=ret_message,
        is_success=is_valid
    )


def StartLocalTestServer():
    """
    传入值: NULL
    返回值: NULL
    启动本地测试服务器
    """
    print(f"本地测试服务器启动: http://127.0.0.1:{LOCAL_TEST_PORT}")
    print("请在浏览器中访问上述地址进行登录测试")
    app.run(host='127.0.0.1', port=LOCAL_TEST_PORT, debug=True)


# ==================== 测试单元 ====================

class TestValidateLoginData(unittest.TestCase):
    """ValidateLoginData 函数测试单元"""
    
    def test_valid_login(self):
        """测试合法的登录数据"""
        pre_user_name = "admin"
        pre_user_psw = "password1"
        pre_cookie = "session_flag_12345"
        is_valid, ret_message = ValidateLoginData(pre_user_name, pre_user_psw, pre_cookie)
        self.assertTrue(is_valid)
        self.assertEqual(ret_message, "ret_OK")
    
    def test_username_too_long(self):
        """测试用户名超过8位"""
        pre_user_name = "adminadmin"  # 10位
        pre_user_psw = "password1"
        pre_cookie = "session_flag_12345"
        is_valid, ret_message = ValidateLoginData(pre_user_name, pre_user_psw, pre_cookie)
        self.assertFalse(is_valid)
        self.assertEqual(ret_message, "长度违法")
    
    def test_password_too_short(self):
        """测试密码不超过6位"""
        pre_user_name = "admin"
        pre_user_psw = "123456"  # 6位，不合法（需要大于6位）
        pre_cookie = "session_flag_12345"
        is_valid, ret_message = ValidateLoginData(pre_user_name, pre_user_psw, pre_cookie)
        self.assertFalse(is_valid)
        self.assertEqual(ret_message, "长度违法")
    
    def test_password_too_long(self):
        """测试密码超过12位"""
        pre_user_name = "admin"
        pre_user_psw = "1234567890123"  # 13位
        pre_cookie = "session_flag_12345"
        is_valid, ret_message = ValidateLoginData(pre_user_name, pre_user_psw, pre_cookie)
        self.assertFalse(is_valid)
        self.assertEqual(ret_message, "长度违法")
    
    def test_cookie_without_flag(self):
        """测试cookie中不包含flag标签"""
        pre_user_name = "admin"
        pre_user_psw = "password1"
        pre_cookie = "session_12345"  # 无flag
        is_valid, ret_message = ValidateLoginData(pre_user_name, pre_user_psw, pre_cookie)
        self.assertFalse(is_valid)
        self.assertEqual(ret_message, "cookie错误")
    
    def test_boundary_username_length(self):
        """测试用户名边界值（8位）"""
        pre_user_name = "abcdefgh"  # 8位，合法
        pre_user_psw = "password1"
        pre_cookie = "session_flag_12345"
        is_valid, ret_message = ValidateLoginData(pre_user_name, pre_user_psw, pre_cookie)
        self.assertTrue(is_valid)
        self.assertEqual(ret_message, "ret_OK")
    
    def test_boundary_password_length(self):
        """测试密码边界值（7位和12位）"""
        pre_user_name = "admin"
        pre_cookie = "session_flag_12345"
        
        # 7位密码，合法
        pre_user_psw_7 = "1234567"
        is_valid, ret_message = ValidateLoginData(pre_user_name, pre_user_psw_7, pre_cookie)
        self.assertTrue(is_valid)
        
        # 12位密码，合法
        pre_user_psw_12 = "123456789012"
        is_valid, ret_message = ValidateLoginData(pre_user_name, pre_user_psw_12, pre_cookie)
        self.assertTrue(is_valid)


def RunTests():
    """
    传入值: NULL
    返回值: NULL
    运行所有测试单元
    """
    print("=" * 50)
    print("开始运行测试单元...")
    print("=" * 50)
    unittest.main(module=__name__, exit=False, verbosity=2)


# ==================== 主程序入口 ====================

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1:
        if sys.argv[1] == "test":
            RunTests()
        elif sys.argv[1] == "server":
            StartLocalTestServer()
        else:
            print("使用方法:")
            print("  python web.py server  - 启动本地测试服务器")
            print("  python web.py test    - 运行测试单元")
    else:
        print("使用方法:")
        print("  python web.py server  - 启动本地测试服务器")
        print("  python web.py test    - 运行测试单元")
