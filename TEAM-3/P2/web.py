"""
Web通信模块 - 处理远程数据接收
遵循OWASP安全规范，防止XSS、CSRF等攻击
"""

from flask import Flask, request, jsonify, render_template_string
from werkzeug.security import safe_join
import os
import json
import time
from collections import defaultdict
import secrets

# Flask应用初始化
app = Flask(__name__)

# 从环境变量获取密钥，避免硬编码凭据 (CWE-798)
# 修复: 使用安全的随机密钥生成
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY') or secrets.token_hex(32)

# 速率限制：防止暴力破解 (CWE-307)
login_attempts = defaultdict(list)
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_TIME = 300  # 5分钟

# 全局数据交换文件路径
SHARE_FILE_PATH = 'share.txt'

# 验证规则常量
MAX_USERNAME_LENGTH = 8
MIN_PASSWORD_LENGTH = 6
MAX_PASSWORD_LENGTH = 12
REQUIRED_COOKIE_FLAG = 'flag'


def ValidateLoginData(pre_user_name, pre_user_psw, pre_cookie):
    """
    验证登录数据的合法性
    传入值：pre_user_name (str) - 用户名
            pre_user_psw (str) - 密码
            pre_cookie (str) - cookie信息
    返回值：dict - 包含ret_status和ret_message，验证成功返回{'ret_status': 'OK'}
                   验证失败返回{'ret_status': 'ERR', 'ret_message': '错误信息'}
    """
    # 验证用户名长度不超过8位
    if len(pre_user_name) > MAX_USERNAME_LENGTH:
        return {
            'ret_status': 'ERR',
            'ret_message': '长度违法'
        }
    
    # 验证密码长度大于6位但不超过12位
    # 修复逻辑bug: 密码长度应该 >= 7 (大于6位意味着至少7位)
    if len(pre_user_psw) < MIN_PASSWORD_LENGTH + 1 or len(pre_user_psw) > MAX_PASSWORD_LENGTH:
        return {
            'ret_status': 'ERR',
            'ret_message': '长度违法'
        }
    
    # 验证cookie中包含flag标签
    # 安全检查：防止注入攻击，使用简单的包含检查
    if REQUIRED_COOKIE_FLAG not in pre_cookie:
        return {
            'ret_status': 'ERR',
            'ret_message': 'cookie错误'
        }
    
    # 所有验证通过
    return {
        'ret_status': 'OK'
    }


def ReceiveLoginData():
    """
    接收前端传入的登录数据
    传入值：通过HTTP请求接收（request对象）
    返回值：dict - 包含pre_user_name, pre_user_psw, pre_cookie的字典，失败返回None
    """
    try:
        # 检查请求方法是否为POST (CWE-306: 确保只接受POST请求)
        if request.method != 'POST':
            return None
        
        # 检查Content-Type是否为JSON
        if not request.is_json:
            return None
        
        # 获取JSON数据
        data = request.get_json()
        
        # 验证必需字段是否存在
        if not data or 'username' not in data or 'password' not in data:
            return None
        
        # 提取数据并使用规范的命名（前端数据使用pre_前缀）
        pre_user_name = data.get('username', '').strip()
        pre_user_psw = data.get('password', '').strip()
        pre_cookie = data.get('cookie', '').strip()
        
        # 基本输入验证：检查是否为空
        if not pre_user_name or not pre_user_psw:
            return None
        
        # 返回处理后的数据字典
        return {
            'pre_user_name': pre_user_name,
            'pre_user_psw': pre_user_psw,
            'pre_cookie': pre_cookie
        }
        
    except Exception as e:
        # 记录错误但不暴露内部信息
        print(f"Error in ReceiveLoginData: {str(e)}")
        return None


def WriteToShareFile(data):
    """
    将接收到的数据写入全局数据交换文件
    传入值：dict - 包含登录数据的字典
    返回值：bool - 成功返回True，失败返回False
    """
    try:
        # 验证输入数据
        if not data or not isinstance(data, dict):
            return False
        
        # 安全地构建文件路径，防止路径遍历 (CWE-22)
        base_dir = os.path.dirname(os.path.abspath(__file__))
        safe_file_path = safe_join(base_dir, SHARE_FILE_PATH)
        
        if safe_file_path is None:
            return False
        
        # 将数据转换为JSON格式写入文件
        # 使用'w'模式确保每次写入都是全新的内容
        with open(safe_file_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        
        return True
        
    except Exception as e:
        print(f"Error in WriteToShareFile: {str(e)}")
        return False


@app.route('/api/login', methods=['POST'])
def LoginEndpoint():
    """
    登录API端点 - 接收来自192.114.514的登录请求
    传入值：HTTP POST请求（JSON格式）
    返回值：JSON响应 - 包含状态码和消息
    """
    # 修复CWE-307: 实施速率限制防止暴力破解
    client_ip = request.remote_addr
    current_time = time.time()
    
    # 清理过期的登录尝试记录
    login_attempts[client_ip] = [t for t in login_attempts[client_ip] 
                                  if current_time - t < LOCKOUT_TIME]
    
    # 检查是否超过尝试次数
    if len(login_attempts[client_ip]) >= MAX_LOGIN_ATTEMPTS:
        return jsonify({
            'ret_status': 'ERR',
            'ret_message': 'Too many login attempts. Please try again later.'
        }), 429
    
    # 记录本次尝试
    login_attempts[client_ip].append(current_time)
    
    # 接收登录数据
    login_data = ReceiveLoginData()
    
    if login_data is None:
        # 返回错误响应（使用ret_前缀的状态码）
        return jsonify({
            'ret_status': 'ERR',
            'ret_message': 'Invalid request data'
        }), 400
    
    # 验证登录数据的合法性
    validation_result = ValidateLoginData(
        login_data['pre_user_name'],
        login_data['pre_user_psw'],
        login_data['pre_cookie']
    )
    
    # 如果验证失败，返回相应的错误信息
    if validation_result['ret_status'] == 'ERR':
        return jsonify(validation_result), 400
    
    # 将数据写入共享文件供其他模块使用
    write_success = WriteToShareFile(login_data)
    
    if not write_success:
        return jsonify({
            'ret_status': 'ERR',
            'ret_message': 'Failed to process login data'
        }), 500
    
    # 此处应该调用C语言的登录验证模块
    # 临时返回接收成功的响应
    return jsonify({
        'ret_status': 'OK',
        'ret_message': 'Login data received successfully',
        'ret_data': {
            'username': login_data['pre_user_name']
            # 注意：不返回密码信息以保护安全
        }
    }), 200


@app.route('/')
def TestLoginPage():
    """
    测试登录页面 - 显示登录表单
    传入值：None
    返回值：HTML页面
    """
    # HTML模板，包含登录表单和Cookie获取功能
    # 使用Jinja2自动转义防止XSS攻击 (CWE-79)
    html_template = '''
    <!DOCTYPE html>
    <html lang="zh-CN">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>登录测试页面</title>
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body {
                font-family: 'Microsoft YaHei', Arial, sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                display: flex;
                justify-content: center;
                align-items: center;
                min-height: 100vh;
                padding: 20px;
            }
            .login-container {
                background: white;
                border-radius: 10px;
                box-shadow: 0 10px 40px rgba(0,0,0,0.2);
                padding: 40px;
                width: 100%;
                max-width: 450px;
            }
            h1 {
                color: #333;
                text-align: center;
                margin-bottom: 30px;
                font-size: 28px;
            }
            .form-group {
                margin-bottom: 20px;
            }
            label {
                display: block;
                color: #555;
                font-weight: bold;
                margin-bottom: 8px;
                font-size: 14px;
            }
            input[type="text"], input[type="password"] {
                width: 100%;
                padding: 12px 15px;
                border: 2px solid #e0e0e0;
                border-radius: 5px;
                font-size: 14px;
                transition: border-color 0.3s;
            }
            input[type="text"]:focus, input[type="password"]:focus {
                outline: none;
                border-color: #667eea;
            }
            .info-text {
                font-size: 12px;
                color: #888;
                margin-top: 5px;
            }
            .cookie-info {
                background: #f5f5f5;
                padding: 10px;
                border-radius: 5px;
                font-size: 12px;
                color: #666;
                margin-bottom: 20px;
                word-break: break-all;
            }
            button {
                width: 100%;
                padding: 14px;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                border: none;
                border-radius: 5px;
                font-size: 16px;
                font-weight: bold;
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
            .test-info {
                background: #fff3cd;
                color: #856404;
                padding: 15px;
                border-radius: 5px;
                margin-bottom: 20px;
                font-size: 13px;
                border: 1px solid #ffeaa7;
            }
            .test-info strong { display: block; margin-bottom: 5px; }
        </style>
    </head>
    <body>
        <div class="login-container">
            <h1>🔐 登录验证测试</h1>
            
            <div class="test-info">
                <strong>📋 测试规则说明：</strong>
                • 用户名：不超过8位<br>
                • 密码：大于6位且不超过12位<br>
                • Cookie：必须包含"flag"标签
            </div>
            
            <form id="loginForm">
                <div class="form-group">
                    <label for="username">用户名</label>
                    <input type="text" id="username" name="username" 
                           placeholder="请输入用户名（不超过8位）" required>
                    <div class="info-text">当前长度：<span id="usernameLength">0</span>/8</div>
                </div>
                
                <div class="form-group">
                    <label for="password">密码</label>
                    <input type="password" id="password" name="password" 
                           placeholder="请输入密码（7-12位）" required>
                    <div class="info-text">当前长度：<span id="passwordLength">0</span> (需要7-12位)</div>
                </div>
                
                <div class="form-group">
                    <label>浏览器Cookie</label>
                    <div class="cookie-info" id="cookieInfo">正在读取Cookie...</div>
                </div>
                
                <button type="submit">🚀 提交测试</button>
            </form>
            
            <div id="result" class="result"></div>
        </div>
        
        <script>
            // 获取并显示浏览器Cookie
            function getCookie() {
                const cookies = document.cookie;
                const cookieInfo = document.getElementById('cookieInfo');
                
                if (cookies) {
                    cookieInfo.textContent = '当前Cookie: ' + cookies;
                } else {
                    // 如果没有Cookie，设置一个测试Cookie（包含flag）
                    document.cookie = "test_flag=test_value; path=/";
                    cookieInfo.textContent = '当前Cookie: test_flag=test_value (已自动设置测试Cookie)';
                }
                
                return cookies || 'test_flag=test_value';
            }
            
            // 实时更新输入长度
            document.getElementById('username').addEventListener('input', function(e) {
                document.getElementById('usernameLength').textContent = e.target.value.length;
            });
            
            document.getElementById('password').addEventListener('input', function(e) {
                document.getElementById('passwordLength').textContent = e.target.value.length;
            });
            
            // 页面加载时获取Cookie
            window.onload = function() {
                getCookie();
            };
            
            // 表单提交处理
            document.getElementById('loginForm').addEventListener('submit', async function(e) {
                e.preventDefault();
                
                const username = document.getElementById('username').value;
                const password = document.getElementById('password').value;
                const cookie = getCookie();
                const resultDiv = document.getElementById('result');
                
                // 发送登录请求
                try {
                    const response = await fetch('/api/login', {
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
                    
                    // 显示结果
                    resultDiv.style.display = 'block';
                    if (data.ret_status === 'OK') {
                        resultDiv.className = 'result success';
                        resultDiv.innerHTML = '<strong>✅ 验证成功！</strong><br>' + 
                                            '消息：' + data.ret_message;
                    } else {
                        resultDiv.className = 'result error';
                        resultDiv.innerHTML = '<strong>❌ 验证失败！</strong><br>' + 
                                            '错误：' + data.ret_message;
                    }
                } catch (error) {
                    resultDiv.style.display = 'block';
                    resultDiv.className = 'result error';
                    resultDiv.innerHTML = '<strong>❌ 请求失败！</strong><br>' + 
                                        '错误：' + error.message;
                }
            });
        </script>
    </body>
    </html>
    '''
    
    return render_template_string(html_template)


def RunTestUnit():
    """
    运行测试单元 - 测试验证功能
    传入值：None
    返回值：None（打印测试结果）
    """
    print("\n" + "="*60)
    print("开始运行测试单元".center(60))
    print("="*60 + "\n")
    
    # 测试用例列表
    test_cases = [
        {
            'name': '测试1：正常登录（所有条件满足）',
            'username': 'admin',
            'password': '1234567',
            'cookie': 'session_id=abc123; flag=true; user=test',
            'expected': 'OK'
        },
        {
            'name': '测试2：用户名超过8位',
            'username': 'admin12345',
            'password': '1234567',
            'cookie': 'session_id=abc123; flag=true',
            'expected': 'ERR'
        },
        {
            'name': '测试3：密码少于7位',
            'username': 'admin',
            'password': '123456',
            'cookie': 'session_id=abc123; flag=true',
            'expected': 'ERR'
        },
        {
            'name': '测试4：密码超过12位',
            'username': 'admin',
            'password': '1234567890123',
            'cookie': 'session_id=abc123; flag=true',
            'expected': 'ERR'
        },
        {
            'name': '测试5：Cookie中没有flag标签',
            'username': 'admin',
            'password': '1234567',
            'cookie': 'session_id=abc123; user=test',
            'expected': 'ERR'
        },
        {
            'name': '测试6：边界测试-用户名8位',
            'username': 'admin123',
            'password': '1234567',
            'cookie': 'flag=1',
            'expected': 'OK'
        },
        {
            'name': '测试7：边界测试-密码7位',
            'username': 'admin',
            'password': '1234567',
            'cookie': 'flag=1',
            'expected': 'OK'
        },
        {
            'name': '测试8：边界测试-密码12位',
            'username': 'admin',
            'password': '123456789012',
            'cookie': 'flag=1',
            'expected': 'OK'
        }
    ]
    
    passed_count = 0
    failed_count = 0
    
    # 执行每个测试用例
    for i, test_case in enumerate(test_cases, 1):
        print(f"[测试 {i}/{len(test_cases)}] {test_case['name']}")
        print(f"  用户名: {test_case['username']} (长度: {len(test_case['username'])})")
        print(f"  密码: {'*' * len(test_case['password'])} (长度: {len(test_case['password'])})")
        print(f"  Cookie: {test_case['cookie']}")
        
        # 调用验证函数
        result = ValidateLoginData(
            test_case['username'],
            test_case['password'],
            test_case['cookie']
        )
        
        # 检查结果
        if result['ret_status'] == test_case['expected']:
            print(f"  结果: ✅ 通过")
            if result['ret_status'] == 'ERR':
                print(f"  错误消息: {result['ret_message']}")
            passed_count += 1
        else:
            print(f"  结果: ❌ 失败")
            print(f"  期望: {test_case['expected']}, 实际: {result['ret_status']}")
            if result['ret_status'] == 'ERR':
                print(f"  错误消息: {result['ret_message']}")
            failed_count += 1
        
        print()
    
    # 打印测试总结
    print("="*60)
    print(f"测试完成！总计: {len(test_cases)} | 通过: {passed_count} | 失败: {failed_count}")
    print("="*60 + "\n")


# 修复CWE-693: 添加安全响应头
@app.after_request
def AddSecurityHeaders(response):
    """添加安全响应头"""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    # 修复CWE-319: 不应传输敏感信息到不安全连接
    if not request.is_secure and request.headers.get('X-Forwarded-Proto') != 'https':
        response.headers['Content-Security-Policy'] = "upgrade-insecure-requests"
    return response


def StartServer():
    """
    启动Flask服务器
    传入值：None
    返回值：None
    """
    # 从环境变量获取配置，避免硬编码 (CWE-798)
    host = os.environ.get('FLASK_HOST', '127.0.0.1')  # 修复: 默认只监听本地
    port = int(os.environ.get('FLASK_PORT', 5000))
    debug = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    
    # 启动服务器
    # 生产环境中debug应设置为False
    app.run(host=host, port=port, debug=debug)


if __name__ == '__main__':
    # 运行测试单元
    RunTestUnit()
    
    # 开发环境启动说明
    print("Web通信模块启动中...")
    print("监听来自192.114.514的登录请求")
    print("API端点: POST /api/login")
    print("测试页面: http://localhost:5000/")
    print("\n请在浏览器中打开 http://localhost:5000/ 进行测试\n")
    StartServer()
