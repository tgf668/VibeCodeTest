"""
main_helper.py - 主模块辅助脚本
为main.c提供Python功能支持
"""

import sys
import os
import time
from datetime import datetime

# 常量定义
SHARE_FILE_PATH = "share.txt"
LOCAL_TEST_PORT = 5000


def WriteLoginDataToShare(pre_user_name, pre_user_psw, pre_cookie, pre_ip):
    """
    传入值: pre_user_name - 用户名
            pre_user_psw - 用户密码
            pre_cookie - cookie信息
            pre_ip - 客户端IP
    返回值: bool - 写入成功返回True，失败返回False
    """
    try:
        with open(SHARE_FILE_PATH, "w", encoding="utf-8") as file:
            file.write(f"pre_user_name={pre_user_name}\n")
            file.write(f"pre_user_psw={pre_user_psw}\n")
            file.write(f"pre_cookie={pre_cookie}\n")
            file.write(f"pre_ip={pre_ip}\n")
        return True
    except Exception as e:
        print(f"写入共享文件失败: {e}")
        return False


def StartWebAndWaitForInput():
    """
    传入值: NULL
    返回值: int - 成功返回0，失败返回1
    说明: 启动简易Web服务器，等待用户输入登录信息
    """
    try:
        from flask import Flask, request, render_template_string, make_response
        
        app = Flask(__name__)
        
        # 用于存储接收到的数据
        received_data = {"completed": False}
        
        LOGIN_PAGE_HTML = """
        <!DOCTYPE html>
        <html lang="zh-CN">
        <head>
            <meta charset="UTF-8">
            <title>后端验证系统 - 登录</title>
            <style>
                body {
                    font-family: Arial, sans-serif;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    height: 100vh;
                    margin: 0;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                }
                .login-box {
                    background: white;
                    padding: 40px;
                    border-radius: 15px;
                    box-shadow: 0 10px 40px rgba(0,0,0,0.2);
                    width: 350px;
                }
                h2 {
                    text-align: center;
                    color: #333;
                    margin-bottom: 30px;
                }
                input {
                    width: 100%;
                    padding: 12px;
                    margin: 10px 0;
                    border: 2px solid #ddd;
                    border-radius: 8px;
                    box-sizing: border-box;
                    font-size: 14px;
                }
                input:focus {
                    border-color: #667eea;
                    outline: none;
                }
                button {
                    width: 100%;
                    padding: 12px;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    border: none;
                    border-radius: 8px;
                    cursor: pointer;
                    font-size: 16px;
                    margin-top: 15px;
                }
                button:hover {
                    opacity: 0.9;
                }
                .info {
                    text-align: center;
                    color: #666;
                    font-size: 12px;
                    margin-top: 20px;
                }
                .result {
                    margin-top: 20px;
                    padding: 15px;
                    border-radius: 8px;
                    text-align: center;
                }
                .success { background-color: #d4edda; color: #155724; }
                .error { background-color: #f8d7da; color: #721c24; }
                .processing { background-color: #fff3cd; color: #856404; }
            </style>
        </head>
        <body>
            <div class="login-box">
                <h2>🔐 用户登录</h2>
                <form method="POST" action="/submit_login">
                    <input type="text" name="username" placeholder="用户名 (最多8位)" required maxlength="8">
                    <input type="password" name="password" placeholder="密码 (7-12位)" required>
                    <button type="submit">登录验证</button>
                </form>
                <div class="info">
                    后端验证系统 v1.0<br>
                    Cookie将自动获取
                </div>
                {% if message %}
                <div class="result {{ result_class }}">
                    {{ message }}
                </div>
                {% endif %}
            </div>
        </body>
        </html>
        """
        
        @app.route('/')
        def ShowLoginPage():
            response = make_response(render_template_string(LOGIN_PAGE_HTML))
            # 设置包含flag的cookie
            response.set_cookie('session_token', 'user_flag_session_' + str(int(time.time())))
            return response
        
        @app.route('/submit_login', methods=['POST'])
        def HandleLoginSubmit():
            pre_user_name = request.form.get('username', '')
            pre_user_psw = request.form.get('password', '')
            pre_cookie = str(request.cookies)
            pre_ip = request.remote_addr
            
            # 将数据写入share.txt
            WriteLoginDataToShare(pre_user_name, pre_user_psw, pre_cookie, pre_ip)
            
            received_data["completed"] = True
            
            # 返回处理中的消息
            return render_template_string(
                LOGIN_PAGE_HTML,
                message="数据已提交，正在验证中...",
                result_class="processing"
            )
        
        @app.route('/shutdown')
        def Shutdown():
            func = request.environ.get('werkzeug.server.shutdown')
            if func is not None:
                func()
            return '服务器已关闭'
        
        print(f"[Web模块] 服务器启动: http://127.0.0.1:{LOCAL_TEST_PORT}")
        print("[Web模块] 请在浏览器中访问上述地址进行登录")
        print("[Web模块] 等待用户输入...")
        
        # 启动服务器（单次请求模式）
        from werkzeug.serving import make_server
        server = make_server('127.0.0.1', LOCAL_TEST_PORT, app, threaded=True)
        
        # 处理请求直到收到登录数据
        import threading
        
        def run_server():
            server.serve_forever()
        
        server_thread = threading.Thread(target=run_server)
        server_thread.daemon = True
        server_thread.start()
        
        # 等待用户提交登录表单
        while not received_data["completed"]:
            time.sleep(0.5)
        
        # 给用户一点时间看到"验证中"的消息
        time.sleep(1)
        
        # 关闭服务器
        server.shutdown()
        
        print("[Web模块] 已接收用户登录数据")
        return 0
        
    except ImportError:
        # 如果没有Flask，使用控制台输入
        print("[Web模块] Flask未安装，使用控制台输入模式")
        return StartConsoleInput()
    
    except Exception as e:
        print(f"[Web模块] 错误: {e}")
        return StartConsoleInput()


def StartConsoleInput():
    """
    传入值: NULL
    返回值: int - 成功返回0，失败返回1
    说明: 控制台模式接收用户输入
    """
    try:
        print("\n" + "=" * 40)
        print("       控制台登录模式")
        print("=" * 40)
        
        pre_user_name = input("请输入用户名: ")
        pre_user_psw = input("请输入密码: ")
        pre_cookie = "console_flag_session"
        pre_ip = "127.0.0.1"
        
        WriteLoginDataToShare(pre_user_name, pre_user_psw, pre_cookie, pre_ip)
        
        print("[控制台模块] 已接收用户登录数据")
        return 0
        
    except Exception as e:
        print(f"[控制台模块] 错误: {e}")
        return 1


def ProcessLogin():
    """
    传入值: NULL
    返回值: int - 成功返回0，失败返回1
    说明: 调用login_helper.py执行登录验证
    """
    try:
        # 首先读取share.txt中的数据
        login_data = {}
        with open(SHARE_FILE_PATH, "r", encoding="utf-8") as file:
            for line in file:
                line = line.strip()
                if "=" in line:
                    key, value = line.split("=", 1)
                    login_data[key] = value
        
        pre_user_name = login_data.get("pre_user_name", "")
        pre_user_psw = login_data.get("pre_user_psw", "")
        pre_cookie = login_data.get("pre_cookie", "")
        pre_ip = login_data.get("pre_ip", "127.0.0.1")
        
        # 导入所需模块
        from algorithm import CalculateMd5
        from login_helper import VerifyUserInExcel, UpdateLoginRecordInExcel
        from web import ValidateLoginData
        
        # 步骤1: 验证输入数据格式
        is_valid, ret_message = ValidateLoginData(pre_user_name, pre_user_psw, pre_cookie)
        if not is_valid:
            WriteResultToShare(0, ret_message)
            return 1
        
        # 步骤2: 计算密码MD5
        ret_md5_hash = CalculateMd5(pre_user_psw)
        
        # 步骤3: 验证用户
        if not VerifyUserInExcel(pre_user_name, ret_md5_hash):
            WriteResultToShare(0, "用户名或密码错误")
            return 1
        
        # 步骤4: 更新登录记录
        UpdateLoginRecordInExcel(pre_user_name, pre_ip)
        
        # 登录成功
        WriteResultToShare(1, "登录成功")
        return 0
        
    except Exception as e:
        print(f"[登录模块] 错误: {e}")
        WriteResultToShare(0, f"系统错误: {str(e)}")
        return 1


def WriteResultToShare(ret_status, ret_message):
    """
    传入值: ret_status - 状态码 (int)
            ret_message - 消息 (str)
    返回值: NULL
    """
    try:
        with open(SHARE_FILE_PATH, "w", encoding="utf-8") as file:
            file.write(f"ret_status={ret_status}\n")
            file.write(f"ret_message={ret_message}\n")
    except Exception as e:
        print(f"写入结果失败: {e}")


def SendResultToWeb():
    """
    传入值: NULL
    返回值: int - 成功返回0，失败返回1
    说明: 将验证结果发送回Web端（可选功能）
    """
    try:
        # 读取结果
        if os.path.exists("temp_result.txt"):
            with open("temp_result.txt", "r", encoding="utf-8") as file:
                lines = file.readlines()
            
            if len(lines) >= 2:
                ret_status = int(lines[0].strip())
                ret_message = lines[1].strip()
                
                print(f"[结果发送] 状态: {'成功' if ret_status else '失败'}")
                print(f"[结果发送] 消息: {ret_message}")
        
        return 0
        
    except Exception as e:
        print(f"[结果发送] 错误: {e}")
        return 1


# ==================== 主程序入口 ====================

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("使用方法:")
        print("  python main_helper.py start_web   - 启动Web服务器等待输入")
        print("  python main_helper.py login       - 执行登录验证")
        print("  python main_helper.py send_result - 发送结果到Web端")
        print("  python main_helper.py console     - 控制台输入模式")
        sys.exit(1)
    
    command = sys.argv[1].lower()
    
    if command == "start_web":
        sys.exit(StartWebAndWaitForInput())
    elif command == "login":
        sys.exit(ProcessLogin())
    elif command == "send_result":
        sys.exit(SendResultToWeb())
    elif command == "console":
        sys.exit(StartConsoleInput())
    else:
        print(f"未知命令: {command}")
        sys.exit(1)
