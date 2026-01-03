/*
 * 主控制模块
 * 功能：集成所有子模块，协调web通信、登录验证等功能
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#ifdef _WIN32
#include <windows.h>
#define SLEEP(x) Sleep((x) * 1000)
#else
#define SLEEP(x) sleep(x)
#endif

#define MAX_LENGTH 256
#define SHARE_FILE "share.txt"
#define WEB_SCRIPT "web.py"
#define LOGIN_PROGRAM "login.exe"

// 系统状态常量
#define STATUS_SUCCESS 0
#define STATUS_ERROR 1

// 返回消息结构体
typedef struct {
    int ret_code;
    char ret_message[MAX_LENGTH];
    char ret_username[MAX_LENGTH];
    char ret_login_time[MAX_LENGTH];
    char ret_ip[MAX_LENGTH];
} t_response;


/*
 * 传入值: 无
 * 返回值: int - 启动状态码
 * 
 * 功能: 启动Web服务器（web.py）
 */
int StartWebServer() {
    printf("\n");
    printf("==================================================\n");
    printf("启动Web通信模块\n");
    printf("==================================================\n\n");

    printf("[提示] 正在启动Web服务器...\n");
    
    // 在后台启动web.py服务器
    char command[MAX_LENGTH];
    snprintf(command, sizeof(command), "start /B python %s test > nul 2>&1", WEB_SCRIPT);
    
    int result = system(command);
    
    if (result == 0) {
        printf("[成功] Web服务器启动命令已执行\n");
        printf("[信息] 服务器将在 http://127.0.0.1:5000 运行\n");
        printf("[提示] 请在浏览器中访问该地址进行登录测试\n\n");
        
        // 等待服务器启动
        printf("等待服务器初始化");
        for (int i = 0; i < 3; i++) {
            SLEEP(1);
            printf(".");
            fflush(stdout);
        }
        printf(" 完成!\n\n");
        
        return STATUS_SUCCESS;
    } else {
        printf("[错误] Web服务器启动失败\n");
        return STATUS_ERROR;
    }
}


/*
 * 传入值: 无
 * 返回值: int - 验证状态码
 * 
 * 功能: 等待并检测share.txt中是否有新的登录数据
 */
int WaitForLoginData() {
    printf("==================================================\n");
    printf("等待用户输入\n");
    printf("==================================================\n\n");

    printf("[提示] 系统正在等待用户通过Web界面输入登录信息...\n");
    printf("[信息] 请在浏览器中输入用户名、密码和Cookie\n");
    printf("[提示] 按 Ctrl+C 可以终止等待\n\n");

    int wait_count = 0;
    const int MAX_WAIT = 300; // 最多等待300秒（5分钟）

    while (wait_count < MAX_WAIT) {
        FILE* fp = fopen(SHARE_FILE, "r");
        if (fp != NULL) {
            char line[MAX_LENGTH];
            int has_data = 0;
            
            // 检查文件是否包含登录数据
            while (fgets(line, sizeof(line), fp)) {
                if (strstr(line, "pre_user_name") != NULL) {
                    has_data = 1;
                    break;
                }
            }
            
            fclose(fp);
            
            if (has_data) {
                printf("\n[成功] 检测到用户输入数据!\n\n");
                return STATUS_SUCCESS;
            }
        }
        
        // 每5秒显示一次等待提示
        if (wait_count % 5 == 0) {
            printf("等待中... (%d秒)\r", wait_count);
            fflush(stdout);
        }
        
        SLEEP(1);
        wait_count++;
    }

    printf("\n[超时] 等待用户输入超时\n");
    return STATUS_ERROR;
}


/*
 * 传入值: 无
 * 返回值: int - 验证状态码
 * 
 * 功能: 调用login.c模块进行身份验证
 */
int PerformLoginValidation() {
    printf("==================================================\n");
    printf("执行身份验证\n");
    printf("==================================================\n\n");

    printf("[步骤1] 调用登录验证模块...\n\n");

    // 调用login.exe进行验证
    int result = system(LOGIN_PROGRAM);

    if (result == 0) {
        printf("\n[成功] 身份验证流程完成\n\n");
        return STATUS_SUCCESS;
    } else {
        printf("\n[错误] 身份验证流程失败\n\n");
        return STATUS_ERROR;
    }
}


/*
 * 传入值: 无
 * 返回值: t_response* - 验证结果结构体指针
 * 
 * 功能: 从share.txt读取验证结果
 */
t_response* ReadValidationResult() {
    t_response* response = (t_response*)malloc(sizeof(t_response));
    if (response == NULL) {
        return NULL;
    }

    // 初始化结构体
    memset(response, 0, sizeof(t_response));
    response->ret_code = STATUS_ERROR;
    strcpy(response->ret_message, "未知错误");

    FILE* fp = fopen(SHARE_FILE, "r");
    if (fp == NULL) {
        strcpy(response->ret_message, "无法读取验证结果");
        return response;
    }

    char line[MAX_LENGTH];
    int in_result_section = 0;

    while (fgets(line, sizeof(line), fp)) {
        // 查找结果部分
        if (strstr(line, "Login Result") != NULL) {
            in_result_section = 1;
            continue;
        }

        if (in_result_section) {
            // 解析success字段
            if (strstr(line, "\"success\"") != NULL) {
                if (strstr(line, "true") != NULL) {
                    response->ret_code = STATUS_SUCCESS;
                } else {
                    response->ret_code = STATUS_ERROR;
                }
            }
            // 解析message字段
            else if (strstr(line, "\"message\"") != NULL) {
                char* msg_start = strchr(line, ':');
                if (msg_start) {
                    msg_start++;
                    while (*msg_start == ' ' || *msg_start == '"') msg_start++;
                    char* msg_end = strrchr(msg_start, '"');
                    if (msg_end) {
                        int len = msg_end - msg_start;
                        if (len > 0 && len < MAX_LENGTH) {
                            strncpy(response->ret_message, msg_start, len);
                            response->ret_message[len] = '\0';
                        }
                    }
                }
            }
            // 解析login_time字段
            else if (strstr(line, "\"login_time\"") != NULL) {
                char* time_start = strchr(line, ':');
                if (time_start) {
                    time_start++;
                    while (*time_start == ' ' || *time_start == '"') time_start++;
                    char* time_end = strrchr(time_start, '"');
                    if (time_end) {
                        int len = time_end - time_start;
                        if (len > 0 && len < MAX_LENGTH) {
                            strncpy(response->ret_login_time, time_start, len);
                            response->ret_login_time[len] = '\0';
                        }
                    }
                }
            }
            // 解析ip_address字段
            else if (strstr(line, "\"ip_address\"") != NULL) {
                char* ip_start = strchr(line, ':');
                if (ip_start) {
                    ip_start++;
                    while (*ip_start == ' ' || *ip_start == '"') ip_start++;
                    char* ip_end = strrchr(ip_start, '"');
                    if (ip_end) {
                        int len = ip_end - ip_start;
                        if (len > 0 && len < MAX_LENGTH) {
                            strncpy(response->ret_ip, ip_start, len);
                            response->ret_ip[len] = '\0';
                        }
                    }
                }
            }
        }
    }

    // 读取用户名
    fseek(fp, 0, SEEK_SET);
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, "pre_user_name") != NULL) {
            char* name_start = strchr(line, ':');
            if (name_start) {
                name_start++;
                while (*name_start == ' ' || *name_start == '"') name_start++;
                char* name_end = strrchr(name_start, '"');
                if (name_end) {
                    int len = name_end - name_start;
                    if (len > 0 && len < MAX_LENGTH) {
                        strncpy(response->ret_username, name_start, len);
                        response->ret_username[len] = '\0';
                    }
                }
            }
            break;
        }
    }

    fclose(fp);
    return response;
}


/*
 * 传入值: 无
 * 返回值: int - 清空状态码
 * 
 * 功能: 清空share.txt文件，为下次使用做准备
 */
int ClearShareFile() {
    printf("==================================================\n");
    printf("清理共享文件\n");
    printf("==================================================\n\n");

    FILE* fp = fopen(SHARE_FILE, "w");
    if (fp == NULL) {
        printf("[错误] 无法清空 %s\n\n", SHARE_FILE);
        return STATUS_ERROR;
    }

    fprintf(fp, "# 共享数据文件已清空\n");
    fprintf(fp, "# 等待下一次使用\n");
    
    fclose(fp);
    
    printf("[成功] %s 已清空，可供下次使用\n\n", SHARE_FILE);
    return STATUS_SUCCESS;
}


/*
 * 传入值: response (t_response*) - 验证结果结构体
 * 返回值: NULL
 * 
 * 功能: 向用户返回验证信息
 */
void ReturnResultToUser(const t_response* response) {
    printf("\n");
    printf("==================================================\n");
    printf("验证结果返回\n");
    printf("==================================================\n\n");

    if (response->ret_code == STATUS_SUCCESS) {
        printf("╔════════════════════════════════════════════════╗\n");
        printf("║           ✓ 登录验证成功                      ║\n");
        printf("╚════════════════════════════════════════════════╝\n\n");
        
        printf("用户名:     %s\n", response->ret_username);
        printf("状态:       成功\n");
        printf("消息:       %s\n", response->ret_message);
        printf("登录时间:   %s\n", response->ret_login_time);
        printf("登录IP:     %s\n", response->ret_ip);
    } else {
        printf("╔════════════════════════════════════════════════╗\n");
        printf("║           ✗ 登录验证失败                      ║\n");
        printf("╚════════════════════════════════════════════════╝\n\n");
        
        if (response->ret_username[0] != '\0') {
            printf("用户名:     %s\n", response->ret_username);
        }
        printf("状态:       失败\n");
        printf("错误:       %s\n", response->ret_message);
    }

    printf("\n==================================================\n\n");
}


/*
 * 传入值: 无
 * 返回值: NULL
 * 
 * 功能: 显示系统启动横幅
 */
void DisplayBanner() {
    printf("\n");
    printf("╔══════════════════════════════════════════════════════╗\n");
    printf("║                                                      ║\n");
    printf("║        网页后端验证系统 v1.0                        ║\n");
    printf("║        Web Backend Validation System                ║\n");
    printf("║                                                      ║\n");
    printf("║        模块集成主控制程序                           ║\n");
    printf("║        日期: 2026-01-03                             ║\n");
    printf("║                                                      ║\n");
    printf("╚══════════════════════════════════════════════════════╝\n");
    printf("\n");
}


/*
 * 传入值: 无
 * 返回值: NULL
 * 
 * 功能: 显示使用说明
 */
void DisplayInstructions() {
    printf("【系统说明】\n");
    printf("1. 系统将启动Web服务器等待用户输入\n");
    printf("2. 请在浏览器访问 http://127.0.0.1:5000\n");
    printf("3. 输入用户名和密码进行登录测试\n");
    printf("4. 系统将自动进行验证并返回结果\n\n");
    
    printf("【测试账号】\n");
    printf("- 用户名: admin    密码: admin123\n");
    printf("- 用户名: user123  密码: pass1234\n");
    printf("- 用户名: test     密码: test1234\n\n");
    
    printf("按Enter键继续...");
    getchar();
    printf("\n");
}


/*
 * 传入值: 无
 * 返回值: int - 程序退出码
 * 
 * 功能: 主流程函数，集成所有模块
 */
int MainProcess() {
    // 显示横幅和说明
    DisplayBanner();
    DisplayInstructions();

    // 步骤1: 启动Web服务器
    if (StartWebServer() != STATUS_SUCCESS) {
        printf("\n[致命错误] Web服务器启动失败，程序终止\n");
        return STATUS_ERROR;
    }

    // 步骤2: 等待用户输入
    if (WaitForLoginData() != STATUS_SUCCESS) {
        printf("\n[错误] 未检测到用户输入，程序终止\n");
        return STATUS_ERROR;
    }

    // 步骤3: 调用login.c进行验证
    if (PerformLoginValidation() != STATUS_SUCCESS) {
        printf("\n[错误] 身份验证失败\n");
    }

    // 步骤4: 读取验证结果
    t_response* result = ReadValidationResult();
    if (result == NULL) {
        printf("\n[错误] 无法读取验证结果\n");
        return STATUS_ERROR;
    }

    // 步骤5: 返回结果给用户
    ReturnResultToUser(result);

    // 步骤6: 清空share.txt
    ClearShareFile();

    // 清理资源
    free(result);

    printf("【提示】程序执行完毕，按Enter键退出...");
    getchar();

    return STATUS_SUCCESS;
}


/*
 * 主函数
 */
int main(int argc, char* argv[]) {
    int result = MainProcess();
    return result;
}
