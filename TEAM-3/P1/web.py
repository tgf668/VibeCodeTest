#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Web 通信模块
负责接收前端传入的登录数据
"""

from flask import Flask, request, jsonify
import json

app = Flask(__name__)

# 配置
SERVER_HOST = '192.114.514'
SERVER_PORT = 5000


def ReceiveLoginData():
    """
    传入值: 无 (从HTTP请求中获取)
    返回值: dict - 包含 pre_user_name, pre_user_psw, pre_cookie 的字典
    
    功能: 从远程客户端接收登录数据
    """
    try:
        # 从请求中获取JSON数据
        data = request.get_json()
        
        # 提取前端传入的数据
        pre_user_name = data.get('username', '')
        pre_user_psw = data.get('password', '')
        pre_cookie = data.get('cookie', '')
        
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
    
    # 这里后续会调用 main.c 中的验证逻辑
    # 目前先返回接收成功的消息
    return SendResponse('ret_OK', '数据接收成功')


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
