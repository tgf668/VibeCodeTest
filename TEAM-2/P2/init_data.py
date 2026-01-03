"""
初始化DATA.xlsx数据文件的脚本
"""

import pandas as pd
from algorithm import CalculateMD5
import os

def InitDataFile():
    """
    创建初始的DATA.xlsx文件
    传入值: 无
    返回值: NULL
    """
    # 示例用户数据
    users_data = {
        'username': ['admin', 'testuser', 'user123'],
        'password_hash': [
            CalculateMD5('admin123'),      # 密码: admin123
            CalculateMD5('password1'),     # 密码: password1
            CalculateMD5('mypass456')      # 密码: mypass456
        ],
        'last_login_time': ['', '', ''],
        'last_login_ip': ['', '', '']
    }
    
    # 创建DataFrame
    df = pd.DataFrame(users_data)
    
    # 保存为Excel文件
    df.to_excel('DATA.xlsx', index=False)
    
    print("DATA.xlsx 文件已创建！")
    print("\n示例用户信息:")
    print("-" * 50)
    print("用户名: admin     | 密码: admin123")
    print("用户名: testuser  | 密码: password1")
    print("用户名: user123   | 密码: mypass456")
    print("-" * 50)
    
    # 显示密码哈希值（用于调试）
    print("\n密码哈希值:")
    for i, row in df.iterrows():
        print(f"{row['username']}: {row['password_hash']}")


if __name__ == '__main__':
    InitDataFile()
