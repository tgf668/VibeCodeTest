/*
 * 主模块 - 集成所有子模块
 * 功能：启动Web服务、处理登录验证、管理数据流
 * 遵循C语言安全规范（OWASP）
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef _WIN32
#include <windows.h>
#include <process.h>
#else
#include <sys/types.h>
#include <signal.h>
#endif

/* 常量定义 */
#define MAX_BUFFER_SIZE 2048
#define MAX_COMMAND_LENGTH 512
#define MAX_USERNAME_LENGTH 100
#define MAX_PASSWORD_LENGTH 200
#define MAX_COOKIE_LENGTH 500
#define MAX_MD5_LENGTH 33

#define SHARE_FILE "share.txt"
#define WEB_SERVER_SCRIPT "web.py"
#define DATA_HANDLER_SCRIPT "data_handler.py"

/* 返回状态码 */
#define RET_OK 0
#define RET_ERR -1

/* 验证结果结构体 */
typedef struct {
    int ret_status;                      /* 验证状态：RET_OK或RET_ERR */
    char ret_message[256];               /* 返回消息 */
    char ret_username[MAX_USERNAME_LENGTH];  /* 用户名 */
} t_verify_result;

/* 全局变量 */
#ifdef _WIN32
static HANDLE web_server_process = NULL;
#else
static pid_t web_server_pid = 0;
#endif


/*
 * 函数：StartWebServer
 * 功能：启动Web服务器（后台运行）
 * 传入值：None
 * 返回值：RET_OK(0)成功，RET_ERR(-1)失败
 */
int StartWebServer(void) {
    printf("\n[模块1] 启动Web通信服务\n");
    printf("======================================================================\n");
    
#ifdef _WIN32
    /* Windows系统 - 使用CreateProcess */
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    char command[MAX_COMMAND_LENGTH];
    
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;  /* 隐藏窗口 */
    ZeroMemory(&pi, sizeof(pi));
    
    /* CWE-119: 使用安全的字符串函数 */
    snprintf(command, MAX_COMMAND_LENGTH, "python %s", WEB_SERVER_SCRIPT);
    
    printf("正在启动Web服务器...\n");
    printf("命令: %s\n", command);
    
    if (!CreateProcess(NULL, command, NULL, NULL, FALSE, 
                      CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi)) {
        fprintf(stderr, "❌ 启动Web服务器失败\n");
        return RET_ERR;
    }
    
    web_server_process = pi.hProcess;
    CloseHandle(pi.hThread);
    
#else
    /* Unix/Linux系统 - 使用fork */
    web_server_pid = fork();
    
    if (web_server_pid < 0) {
        fprintf(stderr, "❌ Fork失败\n");
        return RET_ERR;
    }
    
    if (web_server_pid == 0) {
        /* 子进程 - 执行Python脚本 */
        execlp("python3", "python3", WEB_SERVER_SCRIPT, NULL);
        /* 如果execlp返回，说明执行失败 */
        fprintf(stderr, "❌ 启动Web服务器失败\n");
        exit(EXIT_FAILURE);
    }
#endif
    
    printf("✅ Web服务器已启动\n");
    printf("   访问地址: http://localhost:5000/\n");
    printf("   API端点: POST http://localhost:5000/api/login\n");
    
    /* 等待服务器启动 */
    printf("\n等待服务器启动");
    for (int i = 0; i < 3; i++) {
        printf(".");
        fflush(stdout);
#ifdef _WIN32
        Sleep(1000);  /* Windows: 毫秒 */
#else
        sleep(1);     /* Unix: 秒 */
#endif
    }
    printf(" 完成\n\n");
    
    return RET_OK;
}


/*
 * 函数：StopWebServer
 * 功能：停止Web服务器
 * 传入值：None
 * 返回值：None
 */
void StopWebServer(void) {
    printf("\n正在停止Web服务器...\n");
    
#ifdef _WIN32
    if (web_server_process != NULL) {
        TerminateProcess(web_server_process, 0);
        CloseHandle(web_server_process);
        web_server_process = NULL;
    }
#else
    if (web_server_pid > 0) {
        kill(web_server_pid, SIGTERM);
        web_server_pid = 0;
    }
#endif
    
    printf("✅ Web服务器已停止\n");
}


/*
 * 函数：WaitForUserInput
 * 功能：等待用户输入登录信息
 * 传入值：None
 * 返回值：RET_OK(0)成功，RET_ERR(-1)失败
 */
int WaitForUserInput(void) {
    printf("\n[模块2] 等待用户输入\n");
    printf("======================================================================\n");
    printf("\n您可以通过以下方式输入登录信息：\n\n");
    printf("方式1: 使用浏览器访问 http://localhost:5000/\n");
    printf("       在网页中输入用户名和密码\n\n");
    printf("方式2: 使用API工具（如Postman）发送POST请求\n");
    printf("       POST http://localhost:5000/api/login\n");
    printf("       Body: {\"username\": \"admin\", \"password\": \"123456\", \"cookie\": \"flag=test\"}\n\n");
    
    printf("默认测试账号：\n");
    printf("  用户名: admin  密码: 123456\n");
    printf("  用户名: test   密码: test\n\n");
    
    printf("----------------------------------------------------------------------\n");
    printf("等待用户登录");
    fflush(stdout);
    
    /* 循环检查share.txt文件是否有数据 */
    int max_wait_time = 300;  /* 最多等待300秒（5分钟） */
    int wait_count = 0;
    
    while (wait_count < max_wait_time) {
        /* 检查文件是否存在且非空 */
        FILE *fp = fopen(SHARE_FILE, "r");
        if (fp != NULL) {
            /* 检查文件大小 */
            fseek(fp, 0, SEEK_END);
            long file_size = ftell(fp);
            fclose(fp);
            
            if (file_size > 10) {  /* 文件有内容 */
                printf(" 收到！\n\n");
                printf("✅ 已接收到登录请求\n");
                return RET_OK;
            }
        }
        
        /* 每5秒打印一个点 */
        if (wait_count % 5 == 0) {
            printf(".");
            fflush(stdout);
        }
        
#ifdef _WIN32
        Sleep(1000);
#else
        sleep(1);
#endif
        wait_count++;
    }
    
    printf("\n❌ 等待超时，未收到登录请求\n");
    return RET_ERR;
}


/*
 * 函数：CallLoginVerification
 * 功能：调用login.c模块进行身份验证
 * 传入值：result - 存储验证结果的结构体指针
 * 返回值：RET_OK(0)成功，RET_ERR(-1)失败
 */
int CallLoginVerification(t_verify_result *result) {
    char command[MAX_COMMAND_LENGTH];
    FILE *fp = NULL;
    char buffer[MAX_BUFFER_SIZE];
    
    /* CWE-476: NULL指针检查 */
    if (result == NULL) {
        fprintf(stderr, "错误: result指针为NULL\n");
        return RET_ERR;
    }
    
    /* 初始化结果结构体 */
    memset(result, 0, sizeof(t_verify_result));
    result->ret_status = RET_ERR;
    strncpy(result->ret_message, "验证失败", sizeof(result->ret_message) - 1);
    
    printf("\n[模块3] 身份验证\n");
    printf("======================================================================\n");
    
    /* 方案1: 如果login.c已编译为可执行文件 */
    printf("\n正在调用登录验证模块...\n\n");
    
    /* 检查是否有编译好的login可执行文件 */
    fp = fopen("login.exe", "r");
    if (fp == NULL) {
        fp = fopen("login", "r");
    }
    
    if (fp != NULL) {
        fclose(fp);
        /* 使用编译好的login程序 */
#ifdef _WIN32
        snprintf(command, MAX_COMMAND_LENGTH, "login.exe");
#else
        snprintf(command, MAX_COMMAND_LENGTH, "./login");
#endif
    } else {
        /* 使用内联验证逻辑 */
        printf("注意: 未找到编译的login程序，使用内联验证\n\n");
        
        /* 直接调用Python进行验证 */
        snprintf(command, MAX_COMMAND_LENGTH,
                "python -c \"import json; "
                "from algorithm import CalculateMd5; "
                "from data_handler import ReadUserData, UpdateUserLoginInfo; "
                "data = json.load(open('share.txt', 'r', encoding='utf-8')); "
                "username = data['pre_user_name']; "
                "password = data['pre_user_psw']; "
                "user = ReadUserData(username); "
                "if user and CalculateMd5(password) == user['password_md5']: "
                "    UpdateUserLoginInfo(username, '192.114.514'); "
                "    print('LOGIN_SUCCESS:' + username); "
                "else: "
                "    print('LOGIN_FAILED')\"");
    }
    
    /* 执行验证命令 */
    fp = popen(command, "r");
    if (fp == NULL) {
        fprintf(stderr, "❌ 无法执行验证命令\n");
        return RET_ERR;
    }
    
    /* 读取输出 */
    size_t total_read = 0;
    size_t bytes_read;
    while ((bytes_read = fread(buffer + total_read, 1, 
            MAX_BUFFER_SIZE - total_read - 1, fp)) > 0) {
        total_read += bytes_read;
        if (total_read >= MAX_BUFFER_SIZE - 1) break;
    }
    buffer[total_read] = '\0';
    
    int exit_code = pclose(fp);
    
    /* 分析验证结果 */
    if (strstr(buffer, "登录成功") != NULL || 
        strstr(buffer, "LOGIN_SUCCESS") != NULL ||
        (exit_code == 0 && strlen(buffer) > 0)) {
        
        result->ret_status = RET_OK;
        strncpy(result->ret_message, "登录成功", sizeof(result->ret_message) - 1);
        
        /* 提取用户名 */
        char *username_start = strstr(buffer, "LOGIN_SUCCESS:");
        if (username_start != NULL) {
            username_start += 14;  /* 跳过 "LOGIN_SUCCESS:" */
            char *username_end = strchr(username_start, '\n');
            if (username_end != NULL) {
                size_t len = username_end - username_start;
                if (len < MAX_USERNAME_LENGTH) {
                    strncpy(result->ret_username, username_start, len);
                    result->ret_username[len] = '\0';
                }
            }
        }
        
        /* 如果没有提取到用户名，尝试从share.txt读取 */
        if (strlen(result->ret_username) == 0) {
            FILE *share_fp = fopen(SHARE_FILE, "r");
            if (share_fp != NULL) {
                char share_buffer[MAX_BUFFER_SIZE];
                if (fgets(share_buffer, MAX_BUFFER_SIZE, share_fp) != NULL) {
                    char *user_ptr = strstr(share_buffer, "\"pre_user_name\"");
                    if (user_ptr != NULL) {
                        user_ptr = strchr(user_ptr, ':');
                        if (user_ptr != NULL) {
                            user_ptr = strchr(user_ptr, '"');
                            if (user_ptr != NULL) {
                                user_ptr++;
                                char *end = strchr(user_ptr, '"');
                                if (end != NULL) {
                                    size_t len = end - user_ptr;
                                    if (len < MAX_USERNAME_LENGTH) {
                                        strncpy(result->ret_username, user_ptr, len);
                                        result->ret_username[len] = '\0';
                                    }
                                }
                            }
                        }
                    }
                }
                fclose(share_fp);
            }
        }
        
        printf("\n✅ 验证通过\n");
        return RET_OK;
        
    } else {
        result->ret_status = RET_ERR;
        
        /* 分析失败原因 */
        if (strstr(buffer, "用户不存在") != NULL) {
            strncpy(result->ret_message, "用户不存在", sizeof(result->ret_message) - 1);
        } else if (strstr(buffer, "密码错误") != NULL) {
            strncpy(result->ret_message, "密码错误", sizeof(result->ret_message) - 1);
        } else if (strstr(buffer, "长度违法") != NULL) {
            strncpy(result->ret_message, "用户名或密码长度不合法", sizeof(result->ret_message) - 1);
        } else if (strstr(buffer, "cookie错误") != NULL) {
            strncpy(result->ret_message, "Cookie验证失败", sizeof(result->ret_message) - 1);
        } else {
            strncpy(result->ret_message, "验证失败", sizeof(result->ret_message) - 1);
        }
        
        printf("\n❌ %s\n", result->ret_message);
        return RET_ERR;
    }
}


/*
 * 函数：ClearShareFile
 * 功能：清空share.txt文件，为下次使用做准备
 * 传入值：None
 * 返回值：RET_OK(0)成功，RET_ERR(-1)失败
 */
int ClearShareFile(void) {
    FILE *fp = NULL;
    
    printf("\n[模块4] 清理共享文件\n");
    printf("======================================================================\n");
    
    /* CWE-22: 使用安全的文件路径 */
    fp = fopen(SHARE_FILE, "w");
    if (fp == NULL) {
        fprintf(stderr, "❌ 无法打开共享文件进行清理\n");
        return RET_ERR;
    }
    
    /* 清空文件内容 */
    fclose(fp);
    
    printf("✅ 共享文件已清空，准备下次使用\n");
    
    return RET_OK;
}


/*
 * 函数：ReturnResultToUser
 * 功能：将验证结果返回给用户
 * 传入值：result - 验证结果结构体指针
 * 返回值：None
 */
void ReturnResultToUser(const t_verify_result *result) {
    /* CWE-476: NULL指针检查 */
    if (result == NULL) {
        fprintf(stderr, "错误: result指针为NULL\n");
        return;
    }
    
    printf("\n[模块5] 返回验证结果\n");
    printf("======================================================================\n\n");
    
    if (result->ret_status == RET_OK) {
        printf("╔════════════════════════════════════════════════════════════════╗\n");
        printf("║                      ✅ 登录验证成功                           ║\n");
        printf("╠════════════════════════════════════════════════════════════════╣\n");
        printf("║  状态:     SUCCESS                                             ║\n");
        printf("║  消息:     %s%-46s║\n", result->ret_message, "");
        if (strlen(result->ret_username) > 0) {
            printf("║  用户:     %s%-46s║\n", result->ret_username, "");
        }
        printf("║  时间:     当前时间                                            ║\n");
        printf("║  IP地址:   192.114.514                                         ║\n");
        printf("╚════════════════════════════════════════════════════════════════╝\n");
    } else {
        printf("╔════════════════════════════════════════════════════════════════╗\n");
        printf("║                      ❌ 登录验证失败                           ║\n");
        printf("╠════════════════════════════════════════════════════════════════╣\n");
        printf("║  状态:     FAILED                                              ║\n");
        printf("║  消息:     %s%-46s║\n", result->ret_message, "");
        printf("╚════════════════════════════════════════════════════════════════╝\n");
    }
    
    printf("\n");
}


/*
 * 函数：InitializeSystem
 * 功能：初始化系统，准备必要的文件和环境
 * 传入值：None
 * 返回值：RET_OK(0)成功，RET_ERR(-1)失败
 */
int InitializeSystem(void) {
    printf("\n[系统初始化]\n");
    printf("======================================================================\n");
    
    /* 初始化数据文件 */
    printf("正在初始化数据文件...\n");
    int ret = system("python data_handler.py init");
    if (ret != 0) {
        fprintf(stderr, "⚠️  警告: 数据文件初始化失败（可能已存在）\n");
    } else {
        printf("✅ 数据文件初始化完成\n");
    }
    
    /* 清空share.txt文件 */
    FILE *fp = fopen(SHARE_FILE, "w");
    if (fp != NULL) {
        fclose(fp);
        printf("✅ 共享文件已清空\n");
    }
    
    printf("\n");
    
    return RET_OK;
}


/*
 * 函数：main
 * 功能：主函数 - 集成所有模块
 * 传入值：argc - 参数个数，argv - 参数数组
 * 返回值：0成功，非0失败
 */
int main(int argc, char *argv[]) {
    t_verify_result verify_result;
    int result;
    
    printf("\n");
    printf("╔══════════════════════════════════════════════════════════════════╗\n");
    printf("║          网页后端验证系统 - 主控制程序                          ║\n");
    printf("║                   Version 1.0                                    ║\n");
    printf("╚══════════════════════════════════════════════════════════════════╝\n");
    
    /* 系统初始化 */
    result = InitializeSystem();
    if (result != RET_OK) {
        fprintf(stderr, "\n❌ 系统初始化失败\n");
        return EXIT_FAILURE;
    }
    
    /* 步骤1: 启动Web服务器 */
    result = StartWebServer();
    if (result != RET_OK) {
        fprintf(stderr, "\n❌ Web服务器启动失败\n");
        return EXIT_FAILURE;
    }
    
    /* 步骤2: 等待用户输入 */
    result = WaitForUserInput();
    if (result != RET_OK) {
        fprintf(stderr, "\n❌ 未收到用户输入\n");
        StopWebServer();
        return EXIT_FAILURE;
    }
    
    /* 步骤3: 调用身份验证模块 */
    result = CallLoginVerification(&verify_result);
    
    /* 步骤4: 清空共享文件 */
    ClearShareFile();
    
    /* 步骤5: 返回结果给用户 */
    ReturnResultToUser(&verify_result);
    
    /* 清理工作 */
    printf("\n正在关闭系统...\n");
    StopWebServer();
    
    printf("\n");
    printf("======================================================================\n");
    if (verify_result.ret_status == RET_OK) {
        printf("程序执行完成 - 登录成功\n");
    } else {
        printf("程序执行完成 - 登录失败\n");
    }
    printf("======================================================================\n\n");
    
    return (verify_result.ret_status == RET_OK) ? EXIT_SUCCESS : EXIT_FAILURE;
}
