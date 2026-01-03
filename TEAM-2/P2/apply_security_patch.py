"""
安全补丁 - 修复已识别的安全漏洞
运行此脚本以应用所有安全修复
"""

import os
import shutil
from datetime import datetime

def BackupFiles():
    """
    备份原始文件
    传入值: 无
    返回值: NULL
    """
    print("创建备份...")
    backup_dir = f"backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    os.makedirs(backup_dir, exist_ok=True)
    
    files_to_backup = ['login.c', 'web.py', 'algorithm.py']
    for file in files_to_backup:
        if os.path.exists(file):
            shutil.copy(file, os.path.join(backup_dir, file))
            print(f"  ✓ 已备份: {file}")
    
    print(f"\n备份已保存到: {backup_dir}\n")
    return backup_dir


def CreateSecureWebPy():
    """
    创建安全加固的web.py
    传入值: 无
    返回值: NULL
    """
    secure_web_content = '''"""
Web通信模块 - 负责接收前端传入的登录数据（安全加固版）
"""

from flask import Flask, request, jsonify, make_response, render_template_string
import json
import unittest
import re
import html
import secrets
from functools import wraps
import time

app = Flask(__name__)

# 安全配置
app.config['JSON_AS_ASCII'] = False
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024
app.config['SECRET_KEY'] = secrets.token_hex(32)

# 常量定义
SERVER_IP = "192.114.514.1"
SERVER_PORT = 5000
LOCAL_TEST_IP = "127.0.0.1"
LOCAL_TEST_PORT = 5000
MAX_USERNAME_LENGTH = 8
MIN_PASSWORD_LENGTH = 6
MAX_PASSWORD_LENGTH = 12
REQUIRED_COOKIE_FLAG = "flag"

# 速率限制字典
login_attempts = {}
MAX_ATTEMPTS = 5
LOCKOUT_DURATION = 300  # 5分钟

def RateLimitCheck(ip_address):
    """
    检查速率限制
    传入值: ip_address - 客户端IP
    返回值: bool - 是否允许请求
    """
    current_time = time.time()
    
    if ip_address in login_attempts:
        attempts, first_attempt_time = login_attempts[ip_address]
        
        # 如果锁定时间已过，重置
        if current_time - first_attempt_time > LOCKOUT_DURATION:
            login_attempts[ip_address] = (1, current_time)
            return True
        
        # 检查是否超过最大尝试次数
        if attempts >= MAX_ATTEMPTS:
            return False
        
        # 增加尝试次数
        login_attempts[ip_address] = (attempts + 1, first_attempt_time)
        return True
    else:
        login_attempts[ip_address] = (1, current_time)
        return True


def SanitizeInput(input_str):
    """
    清理输入字符串，防止注入攻击
    传入值: input_str (str) - 输入字符串
    返回值: str - 清理后的字符串
    """
    if not isinstance(input_str, str):
        return ""
    
    # 移除危险字符
    input_str = re.sub(r'[<>"\\';\\\\]', '', input_str)
    # HTML转义
    input_str = html.escape(input_str)
    # 移除前后空格
    return input_str.strip()


def ValidatePassword(password):
    """
    验证密码安全性
    传入值: password (str) - 密码
    返回值: bool - 是否符合安全要求
    """
    # 只允许安全字符
    if not re.match(r'^[a-zA-Z0-9!@#$%^&*()_+=\\-\\[\\]{}|:,.<>?/~]+$', password):
        return False
    return True


def ValidateLoginData(pre_user_name, pre_user_psw, pre_cookie):
    """
    验证登录数据的合法性（增强版）
    """
    # 验证用户名长度
    if not pre_user_name or len(pre_user_name) == 0:
        return False, "用户名不能为空"
    
    if len(pre_user_name) > MAX_USERNAME_LENGTH:
        return False, "长度违法"
    
    # 验证密码长度（7-12位）
    if len(pre_user_psw) < (MIN_PASSWORD_LENGTH + 1) or len(pre_user_psw) > MAX_PASSWORD_LENGTH:
        return False, "长度违法"
    
    # 验证密码字符
    if not ValidatePassword(pre_user_psw):
        return False, "密码包含非法字符"
    
    # 验证cookie
    if REQUIRED_COOKIE_FLAG not in pre_cookie:
        return False, "cookie错误"
    
    return True, "验证成功"


def ReceiveLoginData():
    """
    从远程接收登录数据（安全加固版）
    """
    try:
        data = request.get_json()
        
        if not data:
            return None
        
        # 提取并清理数据
        pre_user_name = SanitizeInput(data.get('username', ''))
        pre_user_psw = data.get('password', '')
        pre_cookie = request.cookies.to_dict()
        
        # 验证密码字符
        if not ValidatePassword(pre_user_psw):
            return None
        
        login_data = {
            'pre_user_name': pre_user_name,
            'pre_user_psw': pre_user_psw,
            'pre_cookie': pre_cookie
        }
        
        return login_data
    except Exception as e:
        print(f"接收数据时发生错误: {e}")
        return None


@app.route('/login', methods=['POST'])
def HandleLoginRequest():
    """
    处理登录请求（安全加固版）
    """
    # 速率限制检查
    client_ip = request.remote_addr
    if not RateLimitCheck(client_ip):
        return jsonify({
            'status': 'error',
            'message': '尝试次数过多，请稍后再试'
        }), 429
    
    # 接收登录数据
    login_data = ReceiveLoginData()
    
    if login_data is None:
        return jsonify({
            'status': 'error',
            'message': '数据接收失败'
        }), 400
    
    # 验证登录数据
    is_valid, validation_message = ValidateLoginData(
        login_data['pre_user_name'],
        login_data['pre_user_psw'],
        login_data['pre_cookie']
    )
    
    if not is_valid:
        return jsonify({
            'status': 'error',
            'message': validation_message
        }), 400
    
    # 写入共享文件
    try:
        with open('share.txt', 'w', encoding='utf-8') as f:
            json.dump(login_data, f, ensure_ascii=False)
    except Exception as e:
        print(f"写入共享文件时发生错误: {e}")
        return jsonify({
            'status': 'error',
            'message': '数据处理失败'
        }), 500
    
    return jsonify({
        'status': 'success',
        'message': '数据接收成功',
        'data': {
            'username': login_data['pre_user_name']
        }
    }), 200
'''
    
    with open('web_secure.py', 'w', encoding='utf-8') as f:
        f.write(secure_web_content)
    
    print("✓ 已创建安全加固的 web_secure.py")


def CreateSecureLoginC():
    """
    创建安全加固的login.c头部
    传入值: 无
    返回值: NULL
    """
    secure_login_header = '''/*
 * 登录验证模块 - 安全加固版
 * 
 * 安全改进:
 * 1. 添加命令注入防护
 * 2. 修复缓冲区溢出
 * 3. 增强输入验证
 */

// 转义字符串以防止命令注入
int EscapeString(const char* input, char* output, int max_len) {
    int j = 0;
    for (int i = 0; input[i] != '\\0' && j < max_len - 2; i++) {
        // 转义危险字符
        if (input[i] == '\\'' || input[i] == '\\\\' || input[i] == '\\"' || 
            input[i] == ';' || input[i] == '&' || input[i] == '|' ||
            input[i] == '$' || input[i] == '`' || input[i] == '\\n' || 
            input[i] == '\\r') {
            output[j++] = '\\\\';
            if (j >= max_len - 1) break;
        }
        output[j++] = input[i];
    }
    output[j] = '\\0';
    return SUCCESS;
}

// 使用安全的MD5计算（带转义）
int CalculateMD5HashSecure(const char* input_data, char* output_hash) {
    char command[2048];
    char escaped_data[512];
    FILE* fp;
    
    // 先转义输入
    if (EscapeString(input_data, escaped_data, sizeof(escaped_data)) != SUCCESS) {
        return FAILURE;
    }
    
    // 构建Python命令
    snprintf(command, sizeof(command), 
             "python -c \\"from algorithm import CalculateMD5; print(CalculateMD5('%s'), end='')\\"",
             escaped_data);
    
    fp = popen(command, "r");
    if (fp == NULL) {
        printf("错误: 无法调用Python算法\\n");
        return FAILURE;
    }
    
    if (fgets(output_hash, MD5_HASH_LENGTH, fp) == NULL) {
        printf("错误: 无法读取MD5哈希值\\n");
        pclose(fp);
        return FAILURE;
    }
    
    pclose(fp);
    output_hash[strcspn(output_hash, "\\n\\r")] = '\\0';
    
    return SUCCESS;
}
'''
    
    with open('login_secure_patch.c', 'w', encoding='utf-8') as f:
        f.write(secure_login_header)
    
    print("✓ 已创建安全补丁 login_secure_patch.c")


def CreateImprovedAlgorithm():
    """
    创建改进的加密算法模块
    传入值: 无
    返回值: NULL
    """
    improved_algo = '''"""
改进的算法模块 - 使用更安全的哈希方法
"""

import hashlib
import bcrypt
import secrets

def SecureHashPassword(password):
    """
    使用bcrypt安全哈希密码
    传入值: password (str) - 原始密码
    返回值: bytes - bcrypt哈希值
    """
    # 生成随机盐
    salt = bcrypt.gensalt(rounds=12)
    # 哈希密码
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed

def VerifySecurePassword(password, hashed):
    """
    验证bcrypt哈希密码
    传入值: 
        password (str) - 输入密码
        hashed (bytes) - 存储的哈希值
    返回值: bool - 是否匹配
    """
    return bcrypt.checkpw(password.encode('utf-8'), hashed)

def GenerateSecureToken(length=32):
    """
    生成安全的随机令牌
    传入值: length (int) - 令牌长度
    返回值: str - 十六进制令牌
    """
    return secrets.token_hex(length)

# 保留MD5用于非关键功能
def CalculateMD5(input_data):
    """
    计算MD5（仅用于非安全关键功能）
    传入值: input_data (str or bytes)
    返回值: str - MD5哈希值
    """
    if isinstance(input_data, str):
        input_data = input_data.encode('utf-8')
    return hashlib.md5(input_data).hexdigest()

# 使用SHA256替代SHA1
def CalculateSHA256(input_data):
    """
    计算SHA256哈希值（比SHA1更安全）
    传入值: input_data (str or bytes)
    返回值: str - SHA256哈希值
    """
    if isinstance(input_data, str):
        input_data = input_data.encode('utf-8')
    return hashlib.sha256(input_data).hexdigest()
'''
    
    with open('algorithm_improved.py', 'w', encoding='utf-8') as f:
        f.write(improved_algo)
    
    print("✓ 已创建改进的算法模块 algorithm_improved.py")


def GenerateSecurityChecklist():
    """
    生成安全检查清单
    传入值: 无
    返回值: NULL
    """
    checklist = """
# 安全部署检查清单

## 部署前必检项

### 网络安全
- [ ] 启用HTTPS（强制）
- [ ] 配置防火墙规则
- [ ] 关闭不必要的端口
- [ ] 配置反向代理（Nginx/Apache）

### 应用安全
- [ ] 更换为bcrypt密码哈希
- [ ] 启用CSRF保护
- [ ] 实施速率限制
- [ ] 配置会话超时
- [ ] 启用安全HTTP头

### 数据安全
- [ ] 加密敏感数据
- [ ] 设置适当的文件权限（600）
- [ ] 定期备份数据库
- [ ] 实施审计日志

### 代码安全
- [ ] 移除调试代码
- [ ] 移除测试账户
- [ ] 更新所有依赖
- [ ] 运行安全扫描工具

### 监控与响应
- [ ] 配置日志记录
- [ ] 设置入侵检测
- [ ] 建立事件响应计划
- [ ] 定期安全审计

## 推荐的安全配置

### Nginx配置示例
```nginx
server {
    listen 443 ssl http2;
    server_name yourdomain.com;
    
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    
    # 安全头
    add_header X-Frame-Options "SAMEORIGIN";
    add_header X-Content-Type-Options "nosniff";
    add_header X-XSS-Protection "1; mode=block";
    add_header Strict-Transport-Security "max-age=31536000";
    
    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

### Flask配置
```python
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=1800  # 30分钟
)
```

### 文件权限
```bash
chmod 600 key.txt DATA.xlsx share.txt
chmod 644 *.py *.c
chmod 755 main login
```

## 持续安全维护

### 每日
- 检查日志异常
- 监控失败登录

### 每周
- 更新系统补丁
- 审查访问日志

### 每月
- 依赖库更新
- 安全配置审查
- 备份验证

### 每季度
- 全面安全审计
- 渗透测试
- 应急演练

"""
    
    with open('SECURITY_CHECKLIST.md', 'w', encoding='utf-8') as f:
        f.write(checklist)
    
    print("✓ 已创建安全检查清单 SECURITY_CHECKLIST.md")


def Main():
    """
    主函数 - 应用安全补丁
    """
    print("\n" + "="*60)
    print("安全补丁应用程序")
    print("="*60 + "\n")
    
    print("此程序将:")
    print("1. 备份现有文件")
    print("2. 创建安全加固版本")
    print("3. 生成安全检查清单")
    print()
    
    response = input("是否继续? (y/n): ")
    if response.lower() != 'y':
        print("已取消")
        return
    
    print()
    
    # 备份
    backup_dir = BackupFiles()
    
    # 创建安全版本
    CreateSecureWebPy()
    CreateSecureLoginC()
    CreateImprovedAlgorithm()
    GenerateSecurityChecklist()
    
    print("\n" + "="*60)
    print("补丁应用完成！")
    print("="*60)
    print()
    print("创建的文件:")
    print("  - web_secure.py (安全加固的web模块)")
    print("  - login_secure_patch.c (登录模块安全补丁)")
    print("  - algorithm_improved.py (改进的算法模块)")
    print("  - SECURITY_CHECKLIST.md (安全检查清单)")
    print()
    print("原始文件已备份到:", backup_dir)
    print()
    print("⚠️  重要提示:")
    print("  1. 请仔细审查生成的文件")
    print("  2. 测试后再部署到生产环境")
    print("  3. 查看 SECURITY_AUDIT.md 了解所有漏洞")
    print("  4. 按照 SECURITY_CHECKLIST.md 完成部署前检查")
    print()


if __name__ == '__main__':
    Main()
