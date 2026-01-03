import socket
import json

def ReceiveRemoteData():
    """
    功能: 从指定IP接收用户登录信息
    传入值: 无
    返回值: 包含用户信息的字典 (pre_user_name, pre_user_psw, pre_cookie_info)，如果失败返回 None
    """
    # 目标IP地址
    TARGET_IP = "192.114.514"
    # 监听端口
    PORT = 8080
    
    pre_user_name = None
    pre_user_psw = None
    pre_cookie_info = None

    try:
        # 创建 socket 对象
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # 绑定端口
        server_socket.bind(('0.0.0.0', PORT))
        # 开始监听
        server_socket.listen(1)
        
        print(f"Waiting for connection from {TARGET_IP}...")
        
        # 建立连接
        client_socket, addr = server_socket.accept()
        
        # 简单的IP验证 (注意：192.114.514 不是有效的IPv4地址，此处仅为逻辑演示)
        if addr[0] == TARGET_IP:
            # 接收数据
            data = client_socket.recv(1024).decode('utf-8')
            
            # 解析数据 (假设传入的是JSON格式)
            try:
                json_data = json.loads(data)
                pre_user_name = json_data.get('username')
                pre_user_psw = json_data.get('password')
                pre_cookie_info = json_data.get('cookie')
                
                return {
                    "pre_user_name": pre_user_name,
                    "pre_user_psw": pre_user_psw,
                    "pre_cookie_info": pre_cookie_info,
                    "pre_user_ip": addr[0]
                }
            except json.JSONDecodeError:
                print("Error: Invalid JSON data")
        else:
            print(f"Refused connection from {addr[0]}")
            
        client_socket.close()
        
    except Exception as e:
        print(f"Communication error: {e}")
        
    finally:
        if 'server_socket' in locals():
            server_socket.close()

    return None

def ValidateUserData(pre_user_name, pre_user_psw, pre_cookie_info):
    """
    功能: 验证传入的用户数据
    传入值: pre_user_name (用户名), pre_user_psw (密码), pre_cookie_info (cookie信息)
    返回值: 验证结果字符串 ("OK", "长度违法", "cookie错误")
    """
    # 验证用户名长度不超过8位
    if len(pre_user_name) > 8:
        return "长度违法"

    # 验证密码长度大于6位但不超过12位
    if not (6 < len(pre_user_psw) <= 12):
        return "长度违法"

    # cookie中将包含flag的标签
    if "flag" not in pre_cookie_info:
        return "cookie错误"

    return "OK"

def WriteToShareFile(data):
    """
    功能: 将接收到的数据写入 share.txt
    传入值: data (dict)
    """
    try:
        with open('share.txt', 'w') as f:
            f.write(f"{data.get('pre_user_name', '')}\n")
            f.write(f"{data.get('pre_user_psw', '')}\n")
            f.write(f"{data.get('pre_cookie_info', '')}\n")
            f.write(f"{data.get('pre_user_ip', '')}\n")
    except Exception as e:
        print(f"Error writing to share.txt: {e}")

def LocalTestServer():
    """
    功能: 本地测试服务器，用于验证 ValidateUserData
    """
    HOST = '127.0.0.1'
    PORT = 8081 # 避免与 ReceiveRemoteData 的 8080 冲突

    print(f"Starting local test server at http://{HOST}:{PORT}")
    print("Please open your browser and visit the address above.")

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((HOST, PORT))
    server_socket.listen(1)

    while True:
        client_socket, addr = server_socket.accept()
        try:
            request = client_socket.recv(1024).decode('utf-8')
            if not request:
                continue
            
            # 解析请求头
            headers_part = request.split('\r\n\r\n')[0]
            headers = headers_part.split('\r\n')
            method, path, _ = headers[0].split(' ')
            
            # 获取 Cookie
            pre_cookie_info = ""
            for header in headers:
                if header.lower().startswith("cookie:"):
                    pre_cookie_info = header.split(":", 1)[1].strip()
            
            if method == 'GET':
                # 返回包含登录表单的页面，并设置测试用的 cookie
                response_body = """
                <html>
                <head>
                    <meta charset="utf-8">
                    <title>Login Test</title>
                    <script>
                        // 设置一个包含 flag 的 cookie 用于测试
                        document.cookie = "test_tag=flag; path=/";
                    </script>
                </head>
                <body>
                    <h2>Login Test</h2>
                    <form method="POST" action="/">
                        Username: <input type="text" name="username"><br><br>
                        Password: <input type="password" name="password"><br><br>
                        <input type="submit" value="Submit">
                    </form>
                </body>
                </html>
                """
                response = f"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n\r\n{response_body}"
                client_socket.sendall(response.encode('utf-8'))
            
            elif method == 'POST':
                # 获取 POST 数据
                body = request.split('\r\n\r\n')[1] if '\r\n\r\n' in request else ""
                
                # 简单的解析 form data (username=...&password=...)
                params = {}
                if body:
                    pairs = body.split('&')
                    for pair in pairs:
                        if '=' in pair:
                            key, value = pair.split('=')
                            params[key] = value
                
                pre_user_name = params.get('username', '')
                pre_user_psw = params.get('password', '')
                
                # 调用验证函数
                result = ValidateUserData(pre_user_name, pre_user_psw, pre_cookie_info)
                
                # 返回结果
                response_body = f"""
                <html>
                <head><meta charset="utf-8"></head>
                <body>
                    <h2>Validation Result</h2>
                    <p>Result: <strong>{result}</strong></p>
                    <p>Username: {pre_user_name}</p>
                    <p>Password: {pre_user_psw}</p>
                    <p>Cookie: {pre_cookie_info}</p>
                    <a href="/">Back</a>
                </body>
                </html>
                """
                response = f"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n\r\n{response_body}"
                client_socket.sendall(response.encode('utf-8'))
                
        except Exception as e:
            print(f"Error: {e}")
        finally:
            client_socket.close()

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "receive":
        data = ReceiveRemoteData()
        if data:
            WriteToShareFile(data)
            print("Data received and written to share.txt")
        else:
            print("Failed to receive data")
    else:
        LocalTestServer()
