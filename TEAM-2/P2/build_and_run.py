"""
系统构建和运行脚本
自动化编译和启动整个登录验证系统
"""

import os
import sys
import subprocess

def CheckPythonPackages():
    """
    检查并安装必要的Python包
    传入值: 无
    返回值: bool - 全部安装成功返回True
    """
    print("检查Python依赖包...")
    
    required_packages = [
        ('flask', 'Flask'),
        ('pandas', 'pandas'),
        ('openpyxl', 'openpyxl'),
        ('pycryptodome', 'Crypto')
    ]
    
    missing_packages = []
    
    for package_name, import_name in required_packages:
        try:
            __import__(import_name)
            print(f"  [✓] {package_name}")
        except ImportError:
            print(f"  [✗] {package_name} - 需要安装")
            missing_packages.append(package_name)
    
    if missing_packages:
        print(f"\n需要安装以下包: {', '.join(missing_packages)}")
        response = input("是否自动安装? (y/n): ")
        
        if response.lower() == 'y':
            for package in missing_packages:
                print(f"\n安装 {package}...")
                subprocess.run([sys.executable, "-m", "pip", "install", package])
            print("\n依赖包安装完成！")
            return True
        else:
            print("\n请手动安装依赖包后再运行")
            return False
    
    print("所有依赖包已安装 ✓\n")
    return True


def InitializeDataFile():
    """
    初始化数据文件
    传入值: 无
    返回值: NULL
    """
    if not os.path.exists('DATA.xlsx'):
        print("初始化数据文件...")
        subprocess.run([sys.executable, "init_data.py"])
        print()
    else:
        print("数据文件已存在 ✓\n")


def CompileLoginModule():
    """
    编译登录模块
    传入值: 无
    返回值: bool - 编译成功返回True
    """
    print("编译login.c模块...")
    
    # 检查是否有GCC
    try:
        result = subprocess.run(['gcc', '--version'], 
                              capture_output=True, 
                              text=True)
        if result.returncode != 0:
            print("  [✗] GCC未找到，请安装GCC编译器")
            return False
    except FileNotFoundError:
        print("  [✗] GCC未找到，请安装GCC编译器")
        return False
    
    # 编译login.c
    result = subprocess.run(['gcc', '-o', 'login', 'login.c'])
    
    if result.returncode == 0:
        print("  [✓] login.c 编译成功\n")
        return True
    else:
        print("  [✗] login.c 编译失败\n")
        return False


def CompileMainModule():
    """
    编译主模块
    传入值: 无
    返回值: bool - 编译成功返回True
    """
    print("编译main.c模块...")
    
    # 编译main.c
    result = subprocess.run(['gcc', '-o', 'main', 'main.c'])
    
    if result.returncode == 0:
        print("  [✓] main.c 编译成功\n")
        return True
    else:
        print("  [✗] main.c 编译失败\n")
        return False


def RunSystem():
    """
    运行系统
    传入值: 无
    返回值: NULL
    """
    print("="*60)
    print("启动用户登录验证系统")
    print("="*60)
    print()
    
    # 运行main程序
    if os.name == 'nt':  # Windows
        subprocess.run(['main.exe'])
    else:  # Linux/Mac
        subprocess.run(['./main'])


def ShowUsage():
    """
    显示使用说明
    传入值: 无
    返回值: NULL
    """
    print("\n" + "="*60)
    print("使用说明")
    print("="*60)
    print("""
本系统包含以下模块:
  1. web.py       - Web通信模块
  2. algorithm.py - 加密算法模块
  3. login.c      - 登录验证模块
  4. main.c       - 主集成模块

登录流程:
  1. 启动Web服务器
  2. 在浏览器中访问 http://127.0.0.1:5000
  3. 输入用户名和密码
  4. 系统自动验证并返回结果

测试账户:
  用户名: admin     密码: admin123
  用户名: testuser  密码: password1
  用户名: user123   密码: mypass456

注意事项:
  - 用户名不超过8位
  - 密码长度大于6位且不超过12位
  - Cookie中需包含flag标签
""")
    print("="*60)


def Main():
    """
    主函数
    传入值: 无
    返回值: NULL
    """
    print("\n")
    print("╔═══════════════════════════════════════════════════════╗")
    print("║                                                       ║")
    print("║         系统构建和运行脚本                            ║")
    print("║                                                       ║")
    print("╚═══════════════════════════════════════════════════════╝")
    print("\n")
    
    # 步骤1: 检查依赖
    if not CheckPythonPackages():
        return
    
    # 步骤2: 初始化数据
    InitializeDataFile()
    
    # 步骤3: 编译C模块
    if not CompileLoginModule():
        print("编译失败，无法继续")
        return
    
    if not CompileMainModule():
        print("编译失败，无法继续")
        return
    
    print("="*60)
    print("系统构建完成！")
    print("="*60)
    print()
    
    # 显示使用说明
    ShowUsage()
    
    # 询问是否立即运行
    response = input("\n是否立即运行系统? (y/n): ")
    if response.lower() == 'y':
        print()
        RunSystem()
    else:
        print("\n稍后可以运行以下命令启动系统:")
        if os.name == 'nt':
            print("  main.exe")
        else:
            print("  ./main")
        print()


if __name__ == '__main__':
    Main()
