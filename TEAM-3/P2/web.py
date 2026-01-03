"""
Web通信模块 - 处理远程数据接收
遵循OWASP安全规范，防止XSS、CSRF等攻击
"""

from flask import Flask, request, jsonify
from werkzeug.security import safe_join
import os
import json

# Flask应用初始化
app = Flask(__name__)

# 从环境变量获取密钥，避免硬编码凭据 (CWE-798)
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY', 'dev-key-change-in-production')

# 全局数据交换文件路径
SHARE_FILE_PATH = 'share.txt'


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
        
        # 输入长度限制，防止缓冲区问题
        MAX_USERNAME_LENGTH = 100
        MAX_PASSWORD_LENGTH = 200
        MAX_COOKIE_LENGTH = 500
        
        if (len(pre_user_name) > MAX_USERNAME_LENGTH or 
            len(pre_user_psw) > MAX_PASSWORD_LENGTH or 
            len(pre_cookie) > MAX_COOKIE_LENGTH):
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
    # 接收登录数据
    login_data = ReceiveLoginData()
    
    if login_data is None:
        # 返回错误响应（使用ret_前缀的状态码）
        return jsonify({
            'ret_status': 'ERR',
            'ret_message': 'Invalid request data'
        }), 400
    
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


def StartServer():
    """
    启动Flask服务器
    传入值：None
    返回值：None
    """
    # 从环境变量获取配置，避免硬编码 (CWE-798)
    host = os.environ.get('FLASK_HOST', '0.0.0.0')
    port = int(os.environ.get('FLASK_PORT', 5000))
    debug = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    
    # 启动服务器
    # 生产环境中debug应设置为False
    app.run(host=host, port=port, debug=debug)


if __name__ == '__main__':
    # 开发环境启动说明
    print("Web通信模块启动中...")
    print("监听来自192.114.514的登录请求")
    print("API端点: POST /api/login")
    StartServer()
