"""
Web通信模块 - 负责接收前端传入的登录数据
"""

from flask import Flask, request, jsonify, make_response, render_template_string
import json
import unittest
import re
import html

app = Flask(__name__)

# 添加安全配置
app.config['JSON_AS_ASCII'] = False
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024  # 限制请求大小为16KB

# 常量定义
SERVER_IP = "192.114.514.1"  # 服务器IP地址
SERVER_PORT = 5000  # 服务器端口
LOCAL_TEST_IP = "127.0.0.1"  # 本地测试IP
LOCAL_TEST_PORT = 5000  # 本地测试端口
MAX_USERNAME_LENGTH = 8  # 用户名最大长度
MIN_PASSWORD_LENGTH = 6  # 密码最小长度
MAX_PASSWORD_LENGTH = 12  # 密码最大长度
REQUIRED_COOKIE_FLAG = "flag"  # cookie中必需的标签

# HTML登录页面模板
LOGIN_PAGE_HTML = """
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>登录测试页面</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            margin: 0;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        }
        .login-container {
            background: white;
            padding: 40px;
            border-radius: 10px;
            box-shadow: 0 10px 25px rgba(0,0,0,0.2);
            width: 350px;
        }
        h2 {
            text-align: center;
            color: #333;
            margin-bottom: 30px;
        }
        .form-group {
            margin-bottom: 20px;
        }
        label {
            display: block;
            margin-bottom: 5px;
            color: #555;
            font-weight: bold;
        }
        input[type="text"], input[type="password"] {
            width: 100%;
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 5px;
            box-sizing: border-box;
            font-size: 14px;
        }
        button {
            width: 100%;
            padding: 12px;
            background: #667eea;
            color: white;
            border: none;
            border-radius: 5px;
            font-size: 16px;
            cursor: pointer;
            transition: background 0.3s;
        }
        button:hover {
            background: #5568d3;
        }
        .cookie-info {
            margin-top: 15px;
            padding: 10px;
            background: #f0f0f0;
            border-radius: 5px;
            font-size: 12px;
        }
        .result {
            margin-top: 20px;
            padding: 15px;
            border-radius: 5px;
            display: none;
        }
        .result.success {
            background: #d4edda;
            color: #155724;
            border: 1px solid #c3e6cb;
        }
        .result.error {
            background: #f8d7da;
            color: #721c24;
            border: 1px solid #f5c6cb;
        }
        .test-tips {
            margin-top: 20px;
            padding: 10px;
            background: #fff3cd;
            border-radius: 5px;
            font-size: 12px;
            color: #856404;
        }
    </style>
</head>
<body>
    <div class="login-container">
        <h2>登录测试系统</h2>
        <form id="loginForm">
            <div class="form-group">
                <label for="username">用户名 (不超过8位):</label>
                <input type="text" id="username" name="username" required>
            </div>
            <div class="form-group">
                <label for="password">密码 (大于6位且不超过12位):</label>
                <input type="password" id="password" name="password" required>
            </div>
            <button type="submit">登录</button>
        </form>
        
        <div class="cookie-info">
            <strong>Cookie状态:</strong> <span id="cookieStatus">检查中...</span>
        </div>
        
        <div id="result" class="result"></div>
        
        <div class="test-tips">
            <strong>测试提示:</strong><br>
            - 用户名: 1-8位<br>
            - 密码: 7-12位<br>
            - Cookie会自动设置flag标签
        </div>
    </div>

    <script>
        // 页面加载时设置cookie
        document.cookie = "flag=test_flag_value; path=/";
        
        // 检查cookie状态
        function checkCookie() {
            const cookies = document.cookie.split(';').map(c => c.trim());
            const hasFlag = cookies.some(c => c.startsWith('flag='));
            document.getElementById('cookieStatus').textContent = hasFlag ? 
                '✓ 已设置flag标签' : '✗ 未设置flag标签';
            document.getElementById('cookieStatus').style.color = hasFlag ? 'green' : 'red';
        }
        
        checkCookie();
        
        // 处理表单提交
        document.getElementById('loginForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;
            const resultDiv = document.getElementById('result');
            
            try {
                const response = await fetch('/login', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        username: username,
                        password: password
                    }),
                    credentials: 'include'
                });
                
                const data = await response.json();
                
                resultDiv.style.display = 'block';
                if (data.status === 'success') {
                    resultDiv.className = 'result success';
                    resultDiv.innerHTML = `<strong>✓ 成功:</strong> ${data.message}`;
                } else {
                    resultDiv.className = 'result error';
                    resultDiv.innerHTML = `<strong>✗ 错误:</strong> ${data.message}`;
                }
            } catch (error) {
                resultDiv.style.display = 'block';
                resultDiv.className = 'result error';
                resultDiv.innerHTML = `<strong>✗ 请求失败:</strong> ${error.message}`;
            }
        });
    </script>
</body>
</html>
"""

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
    
    # 验证密码长度（大于6位且不超过12位，即7-12位）
    if len(pre_user_psw) < (MIN_PASSWORD_LENGTH + 1) or len(pre_user_psw) > MAX_PASSWORD_LENGTH:
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
        
        if not data:
            return None
        
        # 提取前端传入的数据并清理
        pre_user_name = SanitizeInput(data.get('username', ''))        pre_user_psw = data.get('password', '')  # 密码不做HTML转义，但会做长度和字符验证
        pre_cookie = request.cookies.to_dict()
        
        # 验证密码只包含安全字符
        if not re.match(r'^[a-zA-Z0-9!@#$%^&*()_+=\-\[\]{}|:,.<>?/~]+$', pre_user_psw):
            return None        pre_user_psw = data.get('password', '')  # 密码不做HTML转义，但会做长度和字符验证
        pre_cookie = request.cookies.to_dict()
        
        # 验证密码只包含安全字符
        if not re.match(r'^[a-zA-Z0-9!@#$%^&*()_+=\-\[\]{}|:,.<>?/~]+$', pre_user_psw):
            return None
        
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


@app.route('/', methods=['GET'])
def ShowLoginPage():
    """
    显示登录测试页面
    传入值: 无
    返回值: HTML页面
    """
    response = make_response(render_template_string(LOGIN_PAGE_HTML))
    # 设置cookie中的flag标签用于测试
    response.set_cookie('flag', 'test_flag_value', path='/')
    return response


def StartServer():
    """
    启动Web服务器
    传入值: 无
    返回值: NULL
    """
    app.run(host=SERVER_IP, port=SERVER_PORT, debug=True)


def StartLocalTestServer():
    """
    启动本地测试服务器
    传入值: 无
    返回值: NULL
    """
    print(f"本地测试服务器启动于 http://{LOCAL_TEST_IP}:{LOCAL_TEST_PORT}")
    print("请在浏览器中访问该地址进行测试")
    app.run(host=LOCAL_TEST_IP, port=LOCAL_TEST_PORT, debug=True)


# 测试单元类
class TestLoginValidation(unittest.TestCase):
    """
    登录验证功能的测试单元
    """
    
    def setUp(self):
        """
        测试前的准备工作
        传入值: 无
        返回值: NULL
        """
        self.app = app
        self.client = self.app.test_client()
    
    def test_valid_login(self):
        """
        测试有效的登录数据
        传入值: 无
        返回值: NULL
        """
        # 设置cookie
        self.client.set_cookie('localhost', 'flag', 'test_value')
        
        # 发送有效的登录请求
        response = self.client.post('/login',
                                   json={'username': 'testuser', 'password': 'password123'},
                                   content_type='application/json')
        
        data = json.loads(response.data)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(data['status'], 'success')
        print("✓ 测试通过: 有效登录数据")
    
    def test_username_too_long(self):
        """
        测试用户名过长的情况
        传入值: 无
        返回值: NULL
        """
        self.client.set_cookie('localhost', 'flag', 'test_value')
        
        # 用户名超过8位
        response = self.client.post('/login',
                                   json={'username': 'verylongusername', 'password': 'password123'},
                                   content_type='application/json')
        
        data = json.loads(response.data)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(data['message'], '长度违法')
        print("✓ 测试通过: 用户名过长检测")
    
    def test_password_too_short(self):
        """
        测试密码过短的情况
        传入值: 无
        返回值: NULL
        """
        self.client.set_cookie('localhost', 'flag', 'test_value')
        
        # 密码只有6位（需要大于6位）
        response = self.client.post('/login',
                                   json={'username': 'testuser', 'password': '123456'},
                                   content_type='application/json')
        
        data = json.loads(response.data)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(data['message'], '长度违法')
        print("✓ 测试通过: 密码过短检测")
    
    def test_password_too_long(self):
        """
        测试密码过长的情况
        传入值: 无
        返回值: NULL
        """
        self.client.set_cookie('localhost', 'flag', 'test_value')
        
        # 密码超过12位
        response = self.client.post('/login',
                                   json={'username': 'testuser', 'password': 'verylongpassword123'},
                                   content_type='application/json')
        
        data = json.loads(response.data)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(data['message'], '长度违法')
        print("✓ 测试通过: 密码过长检测")
    
    def test_missing_cookie_flag(self):
        """
        测试缺少cookie中flag标签的情况
        传入值: 无
        返回值: NULL
        """
        # 不设置flag cookie
        response = self.client.post('/login',
                                   json={'username': 'testuser', 'password': 'password123'},
                                   content_type='application/json')
        
        data = json.loads(response.data)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(data['message'], 'cookie错误')
        print("✓ 测试通过: cookie标签缺失检测")
    
    def test_boundary_username_length(self):
        """
        测试用户名边界长度（正好8位）
        传入值: 无
        返回值: NULL
        """
        self.client.set_cookie('localhost', 'flag', 'test_value')
        
        # 用户名正好8位
        response = self.client.post('/login',
                                   json={'username': 'testuser', 'password': 'password1'},
                                   content_type='application/json')
        
        data = json.loads(response.data)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(data['status'], 'success')
        print("✓ 测试通过: 用户名边界长度（8位）")
    
    def test_boundary_password_length(self):
        """
        测试密码边界长度（7位和12位）
        传入值: 无
        返回值: NULL
        """
        self.client.set_cookie('localhost', 'flag', 'test_value')
        
        # 密码正好7位（最小合法长度）
        response = self.client.post('/login',
                                   json={'username': 'test', 'password': '1234567'},
                                   content_type='application/json')
        data = json.loads(response.data)
        self.assertEqual(response.status_code, 200)
        print("✓ 测试通过: 密码边界长度（7位）")
        
        # 密码正好12位（最大合法长度）
        response = self.client.post('/login',
                                   json={'username': 'test', 'password': '123456789012'},
                                   content_type='application/json')
        data = json.loads(response.data)
        self.assertEqual(response.status_code, 200)
        print("✓ 测试通过: 密码边界长度（12位）")


def RunTests():
    """
    运行所有测试单元
    传入值: 无
    返回值: NULL
    """
    print("\n" + "="*50)
    print("开始运行登录验证测试单元")
    print("="*50 + "\n")
    
    # 创建测试套件
    test_suite = unittest.TestLoader().loadTestsFromTestCase(TestLoginValidation)
    
    # 运行测试
    test_runner = unittest.TextTestRunner(verbosity=2)
    test_result = test_runner.run(test_suite)
    
    print("\n" + "="*50)
    print(f"测试结果: 运行 {test_result.testsRun} 个测试")
    print(f"成功: {test_result.testsRun - len(test_result.failures) - len(test_result.errors)}")
    print(f"失败: {len(test_result.failures)}")
    print(f"错误: {len(test_result.errors)}")
    print("="*50 + "\n")
    
    return test_result.wasSuccessful()


if __name__ == '__main__':
    import sys
    
    if len(sys.argv) > 1:
        if sys.argv[1] == 'test':
            # 运行测试模式
            RunTests()
        elif sys.argv[1] == 'local':
            # 启动本地测试服务器
            StartLocalTestServer()
        else:
            print("用法:")
            print("  python web.py          - 启动生产服务器")
            print("  python web.py local    - 启动本地测试服务器")
            print("  python web.py test     - 运行测试单元")
    else:
        # 默认启动本地测试服务器
        print("提示: 使用 'python web.py local' 启动本地测试")
        print("     使用 'python web.py test' 运行测试单元")
        print("\n正在启动本地测试服务器...")
        StartLocalTestServer()
