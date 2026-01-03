"""
测试登录模块的脚本
"""

import json
import os
import subprocess

def CreateTestShareFile(username, password):
    """
    创建测试用的share.txt文件
    传入值: 
        username - 测试用户名
        password - 测试密码
    返回值: NULL
    """
    share_data = {
        'pre_user_name': username,
        'pre_user_psw': password,
        'pre_cookie': {'flag': 'test_value'}
    }
    
    with open('share.txt', 'w', encoding='utf-8') as f:
        json.dump(share_data, f, ensure_ascii=False)
    
    print(f"已创建测试共享文件: username={username}, password={password}")


def RunLoginTest(username, password):
    """
    运行登录测试
    传入值: 
        username - 测试用户名
        password - 测试密码
    返回值: NULL
    """
    print("\n" + "="*60)
    print(f"测试登录: {username}")
    print("="*60)
    
    # 创建测试共享文件
    CreateTestShareFile(username, password)
    
    # 编译并运行C程序
    print("\n编译login.c...")
    compile_result = os.system("gcc -o login login.c")
    
    if compile_result != 0:
        print("编译失败！")
        return
    
    print("\n运行登录程序...")
    os.system("./login" if os.name != 'nt' else "login.exe")


def MainTest():
    """
    主测试函数
    传入值: 无
    返回值: NULL
    """
    # 确保DATA.xlsx存在
    if not os.path.exists('DATA.xlsx'):
        print("DATA.xlsx不存在，正在创建...")
        os.system("python init_data.py")
        print()
    
    print("开始登录模块测试")
    print()
    
    # 测试1: 正确的用户名和密码
    RunLoginTest('admin', 'admin123')
    
    input("\n按Enter继续下一个测试...")
    
    # 测试2: 另一个正确的用户
    RunLoginTest('testuser', 'password1')
    
    input("\n按Enter继续下一个测试...")
    
    # 测试3: 错误的密码
    RunLoginTest('admin', 'wrongpassword')
    
    input("\n按Enter继续下一个测试...")
    
    # 测试4: 不存在的用户
    RunLoginTest('nonexistent', 'password123')
    
    print("\n" + "="*60)
    print("所有测试完成！")
    print("="*60)


if __name__ == '__main__':
    MainTest()
