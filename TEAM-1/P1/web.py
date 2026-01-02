"""
Web通信模块
负责从远程服务器接收用户登录数据
"""

from flask import Flask, request, jsonify
import json

app = Flask(__name__)

# 配置常量
SERVER_HOST = '192.114.514'
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


def StartServer():
    """
    启动Web服务器
    传入值: 无
    返回值: NULL
    """
    print(f"启动服务器: {SERVER_HOST}:{SERVER_PORT}")
    app.run(host=SERVER_HOST, port=SERVER_PORT, debug=True)


if __name__ == '__main__':
    StartServer()
