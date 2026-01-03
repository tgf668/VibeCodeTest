# 安全加固建议与修复指南

## 已修复的Bug

### ✅ Bug #1: 资源泄漏 - login_module.py
**修复内容**: 确保workbook在所有情况下都被正确关闭
**修复位置**: ValidateUserCredentials() 函数
**修复方法**: 使用临时变量存储结果，确保workbook.close()在return之前执行

### ✅ Bug #2: 无法获取真实客户端IP - web.py
**修复内容**: 添加GetClientIp()函数获取真实客户端IP地址
**修复位置**: web.py新增函数
**修复方法**: 
- 检查X-Forwarded-For头（代理场景）
- 检查X-Real-IP头
- 最后使用request.remote_addr

### ✅ Bug #3: 不安全的IP获取方式 - login_module.py
**修复内容**: 从HTTP请求头获取IP，而不是从cookie中提取
**修复位置**: ProcessLogin() 函数
**修复方法**: 使用web.py传递的pre_client_ip字段

### ✅ Bug #4: 输入验证不足 - web.py
**修复内容**: 加强输入验证，添加特殊字符过滤
**修复位置**: ValidateLoginData() 函数
**修复方法**: 
- 添加用户名最小长度检查
- 使用isalnum()验证用户名只包含字母数字和下划线
- 改进Cookie验证逻辑（检查"flag="而不是"flag"）

---

## 🔒 安全加固建议（建议立即实施）

### 1. 升级密码哈希算法
**当前问题**: 使用MD5（已被证明不安全）
**建议方案**: 

```python
# 在algorithm.py中添加bcrypt支持
import bcrypt

def HashPasswordSecure(password):
    """
    使用bcrypt安全地哈希密码
    传入值: password (str) - 明文密码
    返回值: str - bcrypt哈希值
    """
    if isinstance(password, str):
        password = password.encode('utf-8')
    
    salt = bcrypt.gensalt(rounds=12)
    hashed = bcrypt.hashpw(password, salt)
    return hashed.decode('utf-8')

def VerifyPasswordSecure(password, hashed):
    """
    验证密码是否匹配
    传入值: password (str) - 明文密码
            hashed (str) - bcrypt哈希值
    返回值: bool - 匹配返回True
    """
    if isinstance(password, str):
        password = password.encode('utf-8')
    if isinstance(hashed, str):
        hashed = hashed.encode('utf-8')
    
    return bcrypt.checkpw(password, hashed)
```

**迁移步骤**:
1. 安装bcrypt: `pip install bcrypt`
2. 在login_module.py中使用新函数
3. 更新DATA.xlsx中的密码哈希

---

### 2. 添加登录速率限制
**实现方案**:

```python
# 在web.py中添加
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute")  # 每分钟最多5次登录尝试
def LoginEndpoint():
    # ... 现有代码
```

**安装依赖**: `pip install Flask-Limiter`

---

### 3. 实现HTTPS加密传输
**配置方案**:

```python
# 在web.py的StartServer()中
if __name__ == '__main__':
    import ssl
    
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain('cert.pem', 'key.pem')
    
    app.run(
        host=SERVER_HOST,
        port=SERVER_PORT,
        ssl_context=context,
        debug=False  # 生产环境必须关闭debug
    )
```

**生成自签名证书**（开发环境）:
```bash
openssl req -x509 -newkey rsa:4096 -nodes -out cert.pem -keyout key.pem -days 365
```

---

### 4. 添加CSRF保护
**实现方案**:

```python
# 安装: pip install Flask-WTF
from flask_wtf.csrf import CSRFProtect

csrf = CSRFProtect(app)
app.config['SECRET_KEY'] = 'your-secret-key-here'  # 从环境变量读取

@app.route('/login', methods=['POST'])
@csrf.exempt  # 如果使用API，可以使用token验证代替
def LoginEndpoint():
    # ... 现有代码
```

---

### 5. 实现会话管理和账户锁定

```python
# 添加到login_module.py

# 用于跟踪登录失败次数
login_attempts = {}
LOCKOUT_THRESHOLD = 5
LOCKOUT_DURATION = 900  # 15分钟

def CheckAccountLockout(username):
    """
    检查账户是否被锁定
    传入值: username (str) - 用户名
    返回值: tuple - (bool, str) 是否锁定和消息
    """
    if username in login_attempts:
        attempts, last_attempt = login_attempts[username]
        
        # 检查是否在锁定期内
        if attempts >= LOCKOUT_THRESHOLD:
            time_diff = datetime.now() - last_attempt
            if time_diff.total_seconds() < LOCKOUT_DURATION:
                remaining = LOCKOUT_DURATION - time_diff.total_seconds()
                return True, f"账户已锁定，请在{int(remaining/60)}分钟后重试"
            else:
                # 锁定期已过，重置计数
                login_attempts[username] = (0, datetime.now())
    
    return False, ""

def RecordLoginAttempt(username, success):
    """
    记录登录尝试
    传入值: username (str) - 用户名
            success (bool) - 是否成功
    返回值: NULL
    """
    if success:
        # 成功登录，清除失败记录
        if username in login_attempts:
            del login_attempts[username]
    else:
        # 失败登录，增加计数
        if username in login_attempts:
            attempts, _ = login_attempts[username]
            login_attempts[username] = (attempts + 1, datetime.now())
        else:
            login_attempts[username] = (1, datetime.now())
```

---

### 6. 添加安全日志和审计

```python
# 创建security_log.py

import logging
from datetime import datetime
import json

# 配置安全日志
security_logger = logging.getLogger('security')
security_logger.setLevel(logging.INFO)

# 文件处理器
handler = logging.FileHandler('security_audit.log')
handler.setLevel(logging.INFO)

# 格式化器
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)

security_logger.addHandler(handler)

def LogSecurityEvent(event_type, username, ip_address, success, message=""):
    """
    记录安全事件
    传入值: event_type (str) - 事件类型
            username (str) - 用户名
            ip_address (str) - IP地址
            success (bool) - 是否成功
            message (str) - 附加消息
    返回值: NULL
    """
    event = {
        'timestamp': datetime.now().isoformat(),
        'event_type': event_type,
        'username': username,  # 在实际应用中考虑哈希处理
        'ip_address': ip_address,
        'success': success,
        'message': message
    }
    
    security_logger.info(json.dumps(event, ensure_ascii=False))

# 在login_module.py中使用:
# from security_log import LogSecurityEvent
# LogSecurityEvent('LOGIN_ATTEMPT', pre_user_name, login_ip, is_valid, row_or_msg)
```

---

### 7. 输入过滤和转义

```python
# 添加到web.py

import re
import html

def SanitizeInput(input_string, max_length=100):
    """
    清理和转义用户输入
    传入值: input_string (str) - 输入字符串
            max_length (int) - 最大长度
    返回值: str - 清理后的字符串
    """
    if not input_string:
        return ""
    
    # 限制长度
    input_string = input_string[:max_length]
    
    # HTML转义
    input_string = html.escape(input_string)
    
    # 移除可能的SQL注入字符
    dangerous_chars = ['--', ';', '/*', '*/', 'xp_', 'sp_', 'exec', 'execute']
    for char in dangerous_chars:
        input_string = input_string.replace(char, '')
    
    return input_string.strip()
```

---

### 8. 环境变量配置（移除硬编码）

创建 `.env` 文件:
```bash
# .env
SECRET_KEY=your-super-secret-key-here
DATABASE_PATH=DATA.xlsx
SERVER_HOST=127.0.0.1
SERVER_PORT=5000
DEBUG_MODE=False
MAX_LOGIN_ATTEMPTS=5
SESSION_TIMEOUT=1800
```

在代码中使用:
```python
# config.py
import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', 'default-dev-key')
    DATABASE_PATH = os.getenv('DATABASE_PATH', 'DATA.xlsx')
    SERVER_HOST = os.getenv('SERVER_HOST', '127.0.0.1')
    SERVER_PORT = int(os.getenv('SERVER_PORT', 5000))
    DEBUG_MODE = os.getenv('DEBUG_MODE', 'False') == 'True'
    MAX_LOGIN_ATTEMPTS = int(os.getenv('MAX_LOGIN_ATTEMPTS', 5))
    SESSION_TIMEOUT = int(os.getenv('SESSION_TIMEOUT', 1800))

# 安装: pip install python-dotenv
```

---

## 📝 部署前检查清单

- [ ] 将MD5替换为bcrypt或Argon2
- [ ] 启用HTTPS/TLS
- [ ] 实施登录速率限制
- [ ] 添加CSRF保护
- [ ] 实现账户锁定机制
- [ ] 配置安全日志
- [ ] 移除所有硬编码凭据
- [ ] 关闭DEBUG模式
- [ ] 添加输入验证和过滤
- [ ] 实施会话管理
- [ ] 设置安全响应头
- [ ] 配置WAF（Web应用防火墙）
- [ ] 进行渗透测试
- [ ] 建立安全监控

---

## 📚 依赖包安装

```bash
# 基础依赖
pip install flask openpyxl pycryptodome

# 安全增强依赖
pip install bcrypt flask-limiter flask-wtf python-dotenv

# 可选：生产环境
pip install gunicorn  # WSGI服务器
pip install redis     # 用于速率限制缓存
```

---

## ⚠️ 重要提醒

1. **永远不要在生产环境使用DEBUG=True**
2. **定期更新所有依赖包**
3. **定期审查安全日志**
4. **建立事件响应计划**
5. **定期进行安全培训**
6. **实施最小权限原则**
7. **定期备份数据**
8. **制定密码策略**

---

生成时间: 2026-01-03
版本: v2.0
