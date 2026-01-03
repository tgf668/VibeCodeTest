#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Web 通信模块
负责接收前端传入的登录数据
"""

from flask import Flask, request, jsonify, render_template_string, make_response
import json
import re
import html

app = Flask(__name__)

# 配置
SERVER_HOST = '192.114.514'
SERVER_PORT = 5000

# 本地测试配置
TEST_HOST = '127.0.0.1'
TEST_PORT = 5000


def SanitizeInput(input_str, max_length=256):
    """
    传入值: input_str (str) - 需要清洗的字符串, max_length (int) - 最大长度
    返回值: str - 清洗后的字符串
    
    功能: 清洗输入数据，防止XSS和注入攻击
    """
    if not input_str:
        return ""
    
    # 限制长度
    input_str = input_str[:max_length]
    
    # HTML转义防止XSS
    input_str = html.escape(input_str)
    
    # 移除危险字符
    input_str = re.sub(r'[<>"\'\\/;]', '', input_str)
    
    return input_str


def ReceiveLoginData():
    """
    传入值: 无 (从HTTP请求中获取)
    返回值: dict - 包含 pre_user_name, pre_user_psw, pre_cookie 的字典
    
    功能: 从远程客户端接收登录数据
    """
    try:
        # 从请求中获取JSON数据
        data = request.get_json()
        
        if not data:
            print("错误：没有接收到数据")
            return None
        
        # 提取并清洗前端传入的数据
        pre_user_name = SanitizeInput(data.get('username', ''), max_length=50)
        pre_user_psw = data.get('password', '')  # 密码不清洗，保持原样用于验证
        pre_cookie = SanitizeInput(data.get('cookie', ''), max_length=500)
        
        # 验证必要字段
        if not pre_user_name or not pre_user_psw:
            print("错误：用户名或密码为空")
            return None
        
        # 将数据写入全局交换文件
        share_data = {
            'pre_user_name': pre_user_name,
            'pre_user_psw': pre_user_psw,
            'pre_cookie': pre_cookie
        }
        
        WriteToShareFile(share_data)
        
        return share_data
    
    except Exception as e:
        print(f"接收数据时发生错误: {e}")
        return None
        
        # 将数据写入全局交换文件
        share_data = {
            'pre_user_name': pre_user_name,
            'pre_user_psw': pre_user_psw,
            'pre_cookie': pre_cookie
        }
        
        WriteToShareFile(share_data)
        
        return share_data
    
    except Exception as e:
        print(f"接收数据时发生错误: {e}")
        return None


def WriteToShareFile(data):
    """
    传入值: dict - 需要写入的数据字典
    返回值: NULL
    
    功能: 将接收到的数据写入 share.txt 全局数据交换文件
    """
    try:
        with open('share.txt', 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=4)
        print("数据已写入 share.txt")
    except Exception as e:
        print(f"写入文件时发生错误: {e}")


def ReadFromShareFile():
    """
    传入值: 无
    返回值: dict - 从 share.txt 读取的数据字典
    
    功能: 从 share.txt 全局数据交换文件读取数据
    """
    try:
        with open('share.txt', 'r', encoding='utf-8') as f:
            data = json.load(f)
        return data
    except Exception as e:
        print(f"读取文件时发生错误: {e}")
        return None


def ValidateLoginData(pre_user_name, pre_user_psw, pre_cookie):
    """
    传入值: pre_user_name (str) - 用户名, pre_user_psw (str) - 密码, pre_cookie (str) - cookie信息
    返回值: tuple - (is_valid (bool), error_message (str))
    
    功能: 验证登录数据的合法性
         - 用户名长度不超过8位
         - 密码长度大于6位但不超过12位 (7-12位)
         - cookie中必须包含flag标签
    """
    # 验证用户名长度
    if len(pre_user_name) == 0 or len(pre_user_name) > 8:
        return False, "长度违法"
    
    # 验证密码长度（7-12位）
    if len(pre_user_psw) < 7 or len(pre_user_psw) > 12:
        return False, "长度违法"
    
    # 验证cookie中是否包含flag标签
    if 'flag' not in pre_cookie:
        return False, "cookie错误"
    
    return True, "验证通过"


def SendResponse(status, message):
    """
    传入值: status (str) - 状态码, message (str) - 响应消息
    返回值: JSON响应对象
    
    功能: 向前端发送响应数据
    """
    response = {
        'status': status,
        'message': message
    }
    return jsonify(response)


@app.route('/login', methods=['POST'])
def LoginHandler():
    """
    传入值: 无 (从HTTP POST请求中获取)
    返回值: JSON响应
    
    功能: 处理登录请求的路由函数
    """
    # 接收登录数据
    login_data = ReceiveLoginData()
    
    if login_data is None:
        return SendResponse('ret_ERR', '接收数据失败')
    
    # 验证登录数据
    is_valid, error_message = ValidateLoginData(
        login_data.get('pre_user_name', ''),
        login_data.get('pre_user_psw', ''),
        login_data.get('pre_cookie', '')
    )
    
    if not is_valid:
        return SendResponse('ret_ERR', erro


@app.route('/')
def TestPage():
    """
    传入值: 无
    返回值: HTML页面
    
    功能: 提供测试登录页面
    """
    html_template = """
    <!DOCTYPE html>
    <html lang="zh-CN">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>登录测试页面</title>
        <style>
    import sys
    
    # 检查命令行参数
    if len(sys.argv) > 1 and sys.argv[1] == 'test':
        # 本地测试模式
        StartLocalTestServer()
    else:
        # 正常服务器模式
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
                width: 100%;
                max-width: 400px;
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
            input[type="text"],
            input[type="password"] {
                width: 100%;
                padding: 10px;
                border: 1px solid #ddd;
                border-radius: 5px;
                font-size: 14px;
                box-sizing: border-box;
            }
            input[type="text"]:focus,
            input[type="password"]:focus {
                outline: none;
                border-color: #667eea;
            }
            .cookie-info {
                background: #f5f5f5;
                padding: 10px;
                border-radius: 5px;
                font-size: 12px;
                color: #666;
                word-break: break-all;
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
            .hint {
                font-size: 12px;
                color: #999;
                margin-top: 5px;
            }
        </style>
    </head>
    <body>
        <div class="login-container">
            <h2>🔐 登录测试系统</h2>
            <form id="loginForm">
                <div class="form-group">
                    <label for="username">用户名</label>
                    <input type="text" id="username" name="username" required>
                    <div class="hint">长度不超过8位</div>
                </div>
                
                <div class="form-group">
                    <label for="password">密码</label>
                    <input type="password" id="password" name="password" required>
                    <div class="hint">长度大于6位但不超过12位</div>
                </div>
                
                <div class="form-group">
                    <label>当前Cookie</label>
                    <div class="cookie-info" id="cookieInfo">加载中...</div>
                    <div class="hint">Cookie中需包含"flag"标签</div>
                </div>
                
                <button type="submit">登录测试</button>
            </form>
            
            <div class="result" id="result"></div>
        </div>

        <script>
            // 获取浏览器Cookie
            function getCookie() {
                return document.cookie;
            }

            // 显示Cookie信息
            document.getElementById('cookieInfo').textContent = getCookie() || '(空)';

            // 设置测试Cookie (包含flag标签)
            document.cookie = "test_flag=test_value; path=/";
            document.cookie = "session_id=123456; path=/";
            
            // 更新显示
            document.getElementById('cookieInfo').textContent = getCookie() || '(空)';

            // 表单提交处理
            document.getElementById('loginForm').addEventListener('submit', async function(e) {
                e.preventDefault();
                
                const username = document.getElementById('username').value;
                const password = document.getElementById('password').value;
                const cookie = getCookie();
                
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
                        resultDiv.innerHTML = '<strong>✓ 成功：</strong>' + data.message;
                    } else {
                        resultDiv.className = 'result error';
                        resultDiv.innerHTML = '<strong>✗ 错误：</strong>' + data.message;
                    }
                } catch (error) {
                    resultDiv.style.display = 'block';
                    resultDiv.className = 'result error';
                    resultDiv.innerHTML = '<strong>✗ 错误：</strong>请求失败 - ' + error.message;
                }
            });
        </script>
    </body>
    </html>
    """
    return render_template_string(html_template)


def RunTestCases():
    """
    传入值: 无
    返回值: NULL
    
    功能: 执行测试单元，测试各种场景
    """
    print("\n" + "="*50)
    print("开始执行测试单元")
    print("="*50 + "\n")
    
    test_cases = [
        {
            'name': '测试1: 正常数据',
            'pre_user_name': 'user123',
            'pre_user_psw': 'pass1234',
            'pre_cookie': 'session=abc; flag=true',
            'expected': True
        },
        {
            'name': '测试2: 用户名过长',
            'pre_user_name': 'user12345',
            'pre_user_psw': 'pass1234',
            'pre_cookie': 'session=abc; flag=true',
            'expected': False
        },
        {
            'name': '测试3: 密码过短',
            'pre_user_name': 'user',
            'pre_user_psw': 'pass12',
            'pre_cookie': 'session=abc; flag=true',
            'expected': False
        },
        {
            'name': '测试4: 密码过长',
            'pre_user_name': 'user',
            'pre_user_psw': 'pass12345678',
            'pre_cookie': 'session=abc; flag=true',
            'expected': False
        },
        {
            'name': '测试5: Cookie缺少flag',
            'pre_user_name': 'user',
            'pre_user_psw': 'pass1234',
            'pre_cookie': 'session=abc; test=true',
            'expected': False
        },
        {
            'name': '测试6: 边界值 - 用户名8位',
            'pre_user_name': 'user1234',
            'pre_user_psw': 'pass1234',
            'pre_cookie': 'flag=test',
            'expected': True
        },
        {
            'name': '测试7: 边界值 - 密码7位',
            'pre_user_name': 'user',
            'pre_user_psw': 'pass123',
            'pre_cookie': 'flag=test',
            'expected': True
        },
        {
            'name': '测试8: 边界值 - 密码12位',
            'pre_user_name': 'user',
            'pre_user_psw': 'pass12345678',
            'pre_cookie': 'flag=test',
            'expected': False
        }
    ]
    
    passed = 0
    failed = 0
    
    for test in test_cases:
        is_valid, message = ValidateLoginData(
            test['pre_user_name'],
            test['pre_user_psw'],
            test['pre_cookie']
        )
        
        success = is_valid == test['expected']
        status = "✓ 通过" if success else "✗ 失败"
        
        print(f"{test['name']}: {status}")
        print(f"  用户名: {test['pre_user_name']} (长度: {len(test['pre_user_name'])})")
        print(f"  密码: {test['pre_user_psw']} (长度: {len(test['pre_user_psw'])})")
        print(f"  Cookie: {test['pre_cookie']}")
        print(f"  预期结果: {'通过' if test['expected'] else '失败'}")
        print(f"  实际结果: {'通过' if is_valid else '失败'} - {message}")
        print()
        
        if success:
            passed += 1
        else:
            failed += 1
    
    print("="*50)
    print(f"测试完成: {passed} 通过, {failed} 失败")
    print("="*50 + "\n")


def StartLocalTestServer():
    """
    传入值: 无
    返回值: NULL
    
    功能: 启动本地测试服务器
    """
    print("\n" + "="*50)
    print("本地测试模式")
    print("="*50)
    
    # 运行测试单元
    RunTestCases()
    
    print(f"\n启动本地测试服务器: http://{TEST_HOST}:{TEST_PORT}")
    print("请在浏览器中打开上述地址进行测试")
    print("按 Ctrl+C 停止服务器\n")
    
    app.run(host=TEST_HOST, port=TEST_PORT, debug=True)r_message)
    
    # 这里后续会调用 main.c 中的验证逻辑
    # 目前先返回验证成功的消息
    return SendResponse('ret_OK', '数据验证成功')


def StartServer():
    """
    传入值: 无
    返回值: NULL
    
    功能: 启动Web服务器
    """
    print(f"服务器启动在 {SERVER_HOST}:{SERVER_PORT}")
    app.run(host=SERVER_HOST, port=SERVER_PORT, debug=True)


if __name__ == '__main__':
    StartServer()
