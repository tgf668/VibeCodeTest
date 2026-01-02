"""
Web通信模块
负责从远程服务器接收用户登录数据
"""

from flask import Flask, request, jsonify, render_template_string, make_response
import json

app = Flask(__name__)

# 配置常量
SERVER_HOST = '127.0.0.1'  # 修改为本地地址以便测试
SERVER_PORT = 5000
SHARE_FILE_PATH = 'share.txt'


def ReceiveLoginData():
    """
    从前端接收登录数据
    传入值: 无（通过HTTP请求获取）
    返回值: dict - 包含pre_user_name, pre_user_psw, pre_cookie的字典，失败返回None
    """
    try:
        # 获取POST请求的JSON数据
        data = request.get_json()
        
        if not data:
            return None
        
        # 提取用户名、密码和cookie信息（按照命名规范添加pre_前缀）
        pre_user_name = data.get('username', '')
        pre_user_psw = data.get('password', '')
        pre_cookie = data.get('cookie', '')
        
        # 验证必要字段
        if not pre_user_name or not pre_user_psw:
            return None
        
        login_data = {
            'pre_user_name': pre_user_name,
            'pre_user_psw': pre_user_psw,
            'pre_cookie': pre_cookie
        }
        
        return login_data
    
    except Exception as e:
        print(f"接收数据错误: {e}")
        return None


def WriteToShareFile(data):
    """
    将接收到的数据写入全局共享文件
    传入值: data (dict) - 登录数据字典
    返回值: bool - 写入成功返回True，失败返回False
    """
    try:
        with open(SHARE_FILE_PATH, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=4)
        return True
    except Exception as e:
        print(f"写入共享文件错误: {e}")
        return False


def ValidateLoginData(login_data):
    """
    验证登录数据的合法性
    传入值: login_data (dict) - 包含pre_user_name, pre_user_psw, pre_cookie的字典
    返回值: tuple - (bool, str) 验证是否通过和错误消息
    """
    pre_user_name = login_data.get('pre_user_name', '')
    pre_user_psw = login_data.get('pre_user_psw', '')
    pre_cookie = login_data.get('pre_cookie', '')
    
    # 验证用户名长度不超过8位
    if len(pre_user_name) > 8:
        return False, "长度违法"
    
    # 验证密码长度大于6位但不超过12位
    if len(pre_user_psw) <= 6 or len(pre_user_psw) > 12:
        return False, "长度违法"
    
    # 验证cookie中包含flag标签
    if 'flag' not in pre_cookie:
        return False, "cookie错误"
    
    return True, ""


def SendResponse(ret_status, ret_message):
    """
    向前端发送响应结果
    传入值: ret_status (str) - 状态码（'ret_OK'或'ret_ERR'）
            ret_message (str) - 响应消息
    返回值: Response - Flask响应对象
    """
    response_data = {
        'status': ret_status,
        'message': ret_message
    }
    return jsonify(response_data)


@app.route('/login', methods=['POST'])
def LoginEndpoint():
    """
    登录端点处理函数
    传入值: 无（通过HTTP POST请求）
    返回值: Response - 包含验证结果的JSON响应
    """
    # 接收登录数据
    login_data = ReceiveLoginData()
    
    if login_data is None:
        return SendResponse('ret_ERR', '接收数据失败或数据格式不正确')
    
    # 验证登录数据
    is_valid, error_message = ValidateLoginData(login_data)
    if not is_valid:
        return SendResponse('ret_ERR', error_message)
    
    # 将数据写入共享文件供其他模块处理
    if WriteToShareFile(login_data):
        return SendResponse('ret_OK', '数据接收成功，等待验证')
    else:
        return SendResponse('ret_ERR', '数据处理失败')


@app.route('/')
def TestPage():
    """
    测试页面路由，返回登录测试界面
    传入值: 无
    返回值: HTML - 登录测试页面
    """
    html_template = '''
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>登录验证测试系统</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            padding: 20px;
        }
        .container {
            background: white;
            border-radius: 15px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            padding: 40px;
            max-width: 500px;
            width: 100%;
        }
        h1 {
            color: #333;
            text-align: center;
            margin-bottom: 10px;
        }
        .subtitle {
            text-align: center;
            color: #666;
            margin-bottom: 30px;
            font-size: 14px;
        }
        .form-group {
            margin-bottom: 20px;
        }
        label {
            display: block;
            margin-bottom: 8px;
            color: #555;
            font-weight: 600;
        }
        input {
            width: 100%;
            padding: 12px;
            border: 2px solid #e0e0e0;
            border-radius: 8px;
            font-size: 14px;
            transition: border-color 0.3s;
        }
        input:focus {
            outline: none;
            border-color: #667eea;
        }
        .hint {
            font-size: 12px;
            color: #888;
            margin-top: 5px;
        }
        button {
            width: 100%;
            padding: 14px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            border-radius: 8px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.2s;
        }
        button:hover {
            transform: translateY(-2px);
        }
        button:active {
            transform: translateY(0);
        }
        .result {
            margin-top: 20px;
            padding: 15px;
            border-radius: 8px;
            display: none;
            animation: slideIn 0.3s ease-out;
        }
        @keyframes slideIn {
            from {
                opacity: 0;
                transform: translateY(-10px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }
        .result.success {
            background-color: #d4edda;
            border: 2px solid #28a745;
            color: #155724;
        }
        .result.error {
            background-color: #f8d7da;
            border: 2px solid #dc3545;
            color: #721c24;
        }
        .cookie-info {
            background: #f8f9fa;
            padding: 10px;
            border-radius: 5px;
            font-size: 12px;
            color: #666;
            margin-top: 10px;
        }
        .test-cases {
            margin-top: 30px;
            padding-top: 30px;
            border-top: 2px solid #e0e0e0;
        }
        .test-cases h3 {
            color: #333;
            margin-bottom: 15px;
            font-size: 18px;
        }
        .test-case {
            background: #f8f9fa;
            padding: 10px;
            border-radius: 5px;
            margin-bottom: 10px;
            font-size: 13px;
        }
        .test-case-title {
            font-weight: 600;
            color: #667eea;
            margin-bottom: 5px;
        }
        .test-case-data {
            color: #666;
            font-family: 'Courier New', monospace;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔐 登录验证测试系统</h1>
        <p class="subtitle">请输入登录信息进行验证测试</p>
        
        <form id="loginForm">
            <div class="form-group">
                <label for="username">用户名</label>
                <input type="text" id="username" name="username" placeholder="请输入用户名" required>
                <div class="hint">要求：不超过8位</div>
            </div>
            
            <div class="form-group">
                <label for="password">密码</label>
                <input type="password" id="password" name="password" placeholder="请输入密码" required>
                <div class="hint">要求：大于6位且不超过12位</div>
            </div>
            
            <div class="form-group">
                <label for="cookie">Cookie信息</label>
                <input type="text" id="cookie" name="cookie" placeholder="将自动获取浏览器Cookie" readonly>
                <div class="hint">系统将自动获取浏览器Cookie（需包含flag标签）</div>
            </div>
            
            <button type="submit">提交验证</button>
        </form>
        
        <div id="result" class="result"></div>
        
        <div class="cookie-info">
            <strong>当前Cookie:</strong> <span id="currentCookie"></span>
        </div>

        <div class="test-cases">
            <h3>📋 测试用例参考</h3>
            
            <div class="test-case">
                <div class="test-case-title">✅ 测试用例1: 正常登录（需手动设置cookie）</div>
                <div class="test-case-data">
                    用户名: admin<br>
                    密码: 1234567<br>
                    预期: 成功（如果cookie包含flag）
                </div>
            </div>
            
            <div class="test-case">
                <div class="test-case-title">❌ 测试用例2: 用户名过长</div>
                <div class="test-case-data">
                    用户名: admin12345<br>
                    密码: 1234567<br>
                    预期: "长度违法"
                </div>
            </div>
            
            <div class="test-case">
                <div class="test-case-title">❌ 测试用例3: 密码过短</div>
                <div class="test-case-data">
                    用户名: admin<br>
                    密码: 123456<br>
                    预期: "长度违法"
                </div>
            </div>
            
            <div class="test-case">
                <div class="test-case-title">❌ 测试用例4: 密码过长</div>
                <div class="test-case-data">
                    用户名: admin<br>
                    密码: 1234567890123<br>
                    预期: "长度违法"
                </div>
            </div>
            
            <div class="test-case">
                <div class="test-case-title">💡 如何测试Cookie验证</div>
                <div class="test-case-data">
                    1. 按F12打开开发者工具<br>
                    2. 进入Console标签页<br>
                    3. 执行: document.cookie = "flag=test123"<br>
                    4. 刷新页面，再次提交测试
                </div>
            </div>
        </div>
    </div>

    <script>
        // 获取并显示当前Cookie
        function UpdateCookieDisplay() {
            const cookies = document.cookie;
            document.getElementById('currentCookie').textContent = cookies || '(空)';
            document.getElementById('cookie').value = cookies;
        }

        // 页面加载时更新Cookie显示
        UpdateCookieDisplay();

        // 表单提交处理
        document.getElementById('loginForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            
            // 更新Cookie信息
            UpdateCookieDisplay();
            
            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;
            const cookie = document.getElementById('cookie').value;
            
            const resultDiv = document.getElementById('result');
            resultDiv.style.display = 'none';
            
            try {
                const response = await fetch('/login', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        username: username,
                        password: password,
                        cookie: cookie
                    })
                });
                
                const data = await response.json();
                
                resultDiv.style.display = 'block';
                if (data.status === 'ret_OK') {
                    resultDiv.className = 'result success';
                    resultDiv.innerHTML = `<strong>✅ 验证成功</strong><br>${data.message}`;
                } else {
                    resultDiv.className = 'result error';
                    resultDiv.innerHTML = `<strong>❌ 验证失败</strong><br>${data.message}`;
                }
            } catch (error) {
                resultDiv.style.display = 'block';
                resultDiv.className = 'result error';
                resultDiv.innerHTML = `<strong>❌ 请求错误</strong><br>${error.message}`;
            }
        });
        
        // 每2秒更新一次Cookie显示
        setInterval(UpdateCookieDisplay, 2000);
    </script>
</body>
</html>
    '''
    response = make_response(render_template_string(html_template))
    # 设置一个测试cookie
    response.set_cookie('test_flag', 'for_testing', max_age=3600)
    return response


def RunTestCases():
    """
    运行测试单元，验证ValidateLoginData函数
    传入值: 无
    返回值: NULL
    """
    print("\n" + "="*50)
    print("开始运行测试单元")
    print("="*50 + "\n")
    
    # 测试用例1: 正常情况
    test_case_1 = {
        'pre_user_name': 'admin',
        'pre_user_psw': '1234567',
        'pre_cookie': 'flag=test123; session=abc'
    }
    result, msg = ValidateLoginData(test_case_1)
    print(f"测试用例1 - 正常登录:")
    print(f"  输入: 用户名='admin', 密码='1234567', Cookie='flag=test123; session=abc'")
    print(f"  结果: {'✅ 通过' if result else '❌ 失败'} - {msg if msg else '验证成功'}\n")
    
    # 测试用例2: 用户名过长
    test_case_2 = {
        'pre_user_name': 'admin12345',
        'pre_user_psw': '1234567',
        'pre_cookie': 'flag=test123'
    }
    result, msg = ValidateLoginData(test_case_2)
    print(f"测试用例2 - 用户名过长:")
    print(f"  输入: 用户名='admin12345'(9位), 密码='1234567', Cookie='flag=test123'")
    print(f"  结果: {'❌ 拒绝' if not result else '⚠️ 异常通过'} - {msg}\n")
    
    # 测试用例3: 密码过短
    test_case_3 = {
        'pre_user_name': 'admin',
        'pre_user_psw': '123456',
        'pre_cookie': 'flag=test123'
    }
    result, msg = ValidateLoginData(test_case_3)
    print(f"测试用例3 - 密码过短:")
    print(f"  输入: 用户名='admin', 密码='123456'(6位), Cookie='flag=test123'")
    print(f"  结果: {'❌ 拒绝' if not result else '⚠️ 异常通过'} - {msg}\n")
    
    # 测试用例4: 密码过长
    test_case_4 = {
        'pre_user_name': 'admin',
        'pre_user_psw': '1234567890123',
        'pre_cookie': 'flag=test123'
    }
    result, msg = ValidateLoginData(test_case_4)
    print(f"测试用例4 - 密码过长:")
    print(f"  输入: 用户名='admin', 密码='1234567890123'(13位), Cookie='flag=test123'")
    print(f"  结果: {'❌ 拒绝' if not result else '⚠️ 异常通过'} - {msg}\n")
    
    # 测试用例5: Cookie缺少flag标签
    test_case_5 = {
        'pre_user_name': 'admin',
        'pre_user_psw': '1234567',
        'pre_cookie': 'session=abc; user=test'
    }
    result, msg = ValidateLoginData(test_case_5)
    print(f"测试用例5 - Cookie缺少flag标签:")
    print(f"  输入: 用户名='admin', 密码='1234567', Cookie='session=abc; user=test'")
    print(f"  结果: {'❌ 拒绝' if not result else '⚠️ 异常通过'} - {msg}\n")
    
    # 测试用例6: 用户名正好8位
    test_case_6 = {
        'pre_user_name': 'admin123',
        'pre_user_psw': '1234567',
        'pre_cookie': 'flag=test'
    }
    result, msg = ValidateLoginData(test_case_6)
    print(f"测试用例6 - 用户名边界值(8位):")
    print(f"  输入: 用户名='admin123'(8位), 密码='1234567', Cookie='flag=test'")
    print(f"  结果: {'✅ 通过' if result else '❌ 失败'} - {msg if msg else '验证成功'}\n")
    
    # 测试用例7: 密码正好7位
    test_case_7 = {
        'pre_user_name': 'admin',
        'pre_user_psw': '1234567',
        'pre_cookie': 'flag=test'
    }
    result, msg = ValidateLoginData(test_case_7)
    print(f"测试用例7 - 密码边界值(7位):")
    print(f"  输入: 用户名='admin', 密码='1234567'(7位), Cookie='flag=test'")
    print(f"  结果: {'✅ 通过' if result else '❌ 失败'} - {msg if msg else '验证成功'}\n")
    
    # 测试用例8: 密码正好12位
    test_case_8 = {
        'pre_user_name': 'admin',
        'pre_user_psw': '123456789012',
        'pre_cookie': 'flag=test'
    }
    result, msg = ValidateLoginData(test_case_8)
    print(f"测试用例8 - 密码边界值(12位):")
    print(f"  输入: 用户名='admin', 密码='123456789012'(12位), Cookie='flag=test'")
    print(f"  结果: {'✅ 通过' if result else '❌ 失败'} - {msg if msg else '验证成功'}\n")
    
    print("="*50)
    print("测试单元运行完成")
    print("="*50 + "\n")


def StartServer():
    """
    启动Web服务器
    传入值: 无
    返回值: NULL
    """
    # 先运行测试单元
    RunTestCases()
    
    print(f"\n启动服务器: http://{SERVER_HOST}:{SERVER_PORT}")
    print("请在浏览器中访问以进行测试")
    print("提示: 在浏览器控制台执行 document.cookie = \"flag=test123\" 来设置包含flag的cookie\n")
    app.run(host=SERVER_HOST, port=SERVER_PORT, debug=True)


if __name__ == '__main__':
    StartServer()
