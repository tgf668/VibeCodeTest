/*
 * 主控制模块 - main.c
 * 负责集成和协调所有子模块
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef _WIN32
    #include <windows.h>
    #define SLEEP(ms) Sleep(ms)
#else
    #include <unistd.h>
    #define SLEEP(ms) usleep((ms) * 1000)
#endif

// 配置常量
#define WEB_SERVER_SCRIPT "web.py"
#define LOGIN_MODULE "login_module.py"
#define SHARE_FILE "share.txt"
#define RESULT_FILE "login_result.txt"
#define MAX_BUFFER_SIZE 2048

// 全局变量
static FILE *web_server_process = NULL;

/*
 * 函数名: StartWebServer
 * 功能: 启动Web服务器
 * 传入值: 无
 * 返回值: int - 成功返回0，失败返回-1
 */
int StartWebServer() {
    char command[MAX_BUFFER_SIZE];
    
    printf("\n===========================================================\n");
    printf("【模块1】启动Web通信服务器\n");
    printf("===========================================================\n\n");
    
    printf("正在启动Web服务器...\n");
    
    #ifdef _WIN32
        // Windows下启动Python服务器（后台运行）
        snprintf(command, sizeof(command), "start /B python %s", WEB_SERVER_SCRIPT);
    #else
        // Linux/Mac下启动Python服务器（后台运行）
        snprintf(command, sizeof(command), "python %s &", WEB_SERVER_SCRIPT);
    #endif
    
    // 启动服务器
    int ret = system(command);
    
    if (ret != 0) {
        printf("✗ Web服务器启动失败\n");
        return -1;
    }
    
    // 等待服务器启动
    printf("等待服务器初始化");
    for (int i = 0; i < 3; i++) {
        printf(".");
        fflush(stdout);
        SLEEP(1000);
    }
    printf("\n\n");
    
    printf("✓ Web服务器启动成功\n");
    printf("服务器地址: http://127.0.0.1:5000\n");
    printf("请在浏览器中访问并输入登录信息\n");
    printf("提示: 请先在浏览器控制台执行 document.cookie = \"flag=test123\"\n\n");
    
    return 0;
}

/*
 * 函数名: WaitForUserInput
 * 功能: 等待用户通过Web界面输入登录信息
 * 传入值: 无
 * 返回值: int - 成功返回0，失败返回-1
 */
int WaitForUserInput() {
    printf("===========================================================\n");
    printf("【模块2】等待用户输入\n");
    printf("===========================================================\n\n");
    
    printf("等待用户通过Web界面输入登录信息...\n");
    printf("(系统将检测share.txt文件是否有新数据)\n\n");
    
    int timeout = 300; // 5分钟超时
    int check_interval = 2; // 每2秒检查一次
    
    for (int i = 0; i < timeout / check_interval; i++) {
        // 检查share.txt是否存在且不为空
        FILE *file = fopen(SHARE_FILE, "r");
        if (file != NULL) {
            fseek(file, 0, SEEK_END);
            long file_size = ftell(file);
            fclose(file);
            
            if (file_size > 10) { // 文件有内容
                printf("✓ 检测到用户输入数据\n\n");
                return 0;
            }
        }
        
        // 显示等待进度
        if (i % 5 == 0) {
            printf("等待中... (%d秒)\r", i * check_interval);
            fflush(stdout);
        }
        
        SLEEP(check_interval * 1000);
    }
    
    printf("\n✗ 等待超时，未检测到用户输入\n\n");
    return -1;
}

/*
 * 函数名: CallLoginModule
 * 功能: 调用登录验证模块
 * 传入值: 无
 * 返回值: int - 成功返回0，失败返回-1
 */
int CallLoginModule() {
    char command[MAX_BUFFER_SIZE];
    int ret_code;
    
    printf("===========================================================\n");
    printf("【模块3】执行身份验证\n");
    printf("===========================================================\n\n");
    
    printf("正在调用登录验证模块...\n\n");
    
    // 构建Python命令
    snprintf(command, sizeof(command), "python %s", LOGIN_MODULE);
    
    // 执行登录模块
    ret_code = system(command);
    
    if (ret_code != 0) {
        printf("\n✗ 登录验证模块执行失败，错误码: %d\n\n", ret_code);
        return -1;
    }
    
    printf("\n✓ 登录验证模块执行完成\n\n");
    
    return 0;
}

/*
 * 函数名: ReadAndDisplayResult
 * 功能: 读取并显示验证结果
 * 传入值: 无
 * 返回值: int - 成功返回0，失败返回-1
 */
int ReadAndDisplayResult() {
    FILE *file;
    char buffer[MAX_BUFFER_SIZE];
    char status[50] = "";
    char message[200] = "";
    char username[100] = "";
    char login_time[100] = "";
    int is_success = 0;
    
    printf("===========================================================\n");
    printf("【模块4】读取验证结果\n");
    printf("===========================================================\n\n");
    
    // 打开结果文件
    file = fopen(RESULT_FILE, "r");
    if (file == NULL) {
        printf("✗ 无法打开结果文件: %s\n\n", RESULT_FILE);
        return -1;
    }
    
    // 读取并解析JSON结果（简单解析）
    while (fgets(buffer, sizeof(buffer), file) != NULL) {
        // 提取状态
        if (strstr(buffer, "\"ret_status\"") != NULL) {
            if (strstr(buffer, "ret_OK") != NULL) {
                strcpy(status, "成功");
                is_success = 1;
            } else {
                strcpy(status, "失败");
            }
        }
        
        // 提取消息
        if (strstr(buffer, "\"ret_message\"") != NULL) {
            char *start = strchr(buffer, ':');
            if (start != NULL) {
                start = strchr(start, '"');
                if (start != NULL) {
                    start++;
                    char *end = strchr(start, '"');
                    if (end != NULL) {
                        int len = end - start;
                        if (len > 0 && len < sizeof(message)) {
                            strncpy(message, start, len);
                            message[len] = '\0';
                        }
                    }
                }
            }
        }
        
        // 提取用户名
        if (strstr(buffer, "\"ret_user_name\"") != NULL) {
            char *start = strchr(buffer, ':');
            if (start != NULL) {
                start = strchr(start, '"');
                if (start != NULL) {
                    start++;
                    char *end = strchr(start, '"');
                    if (end != NULL) {
                        int len = end - start;
                        if (len > 0 && len < sizeof(username)) {
                            strncpy(username, start, len);
                            username[len] = '\0';
                        }
                    }
                }
            }
        }
        
        // 提取登录时间
        if (strstr(buffer, "\"ret_login_time\"") != NULL) {
            char *start = strchr(buffer, ':');
            if (start != NULL) {
                start = strchr(start, '"');
                if (start != NULL) {
                    start++;
                    char *end = strchr(start, '"');
                    if (end != NULL) {
                        int len = end - start;
                        if (len > 0 && len < sizeof(login_time)) {
                            strncpy(login_time, start, len);
                            login_time[len] = '\0';
                        }
                    }
                }
            }
        }
    }
    
    fclose(file);
    
    // 显示验证结果
    printf("验证结果:\n");
    printf("-----------------------------------------------------------\n");
    printf("状态: %s\n", status);
    printf("消息: %s\n", message);
    
    if (is_success) {
        printf("用户: %s\n", username);
        printf("登录时间: %s\n", login_time);
    }
    
    printf("-----------------------------------------------------------\n\n");
    
    if (is_success) {
        printf("✓ 登录验证成功\n\n");
        return 0;
    } else {
        printf("✗ 登录验证失败\n\n");
        return -1;
    }
}

/*
 * 函数名: ClearShareFile
 * 功能: 清空共享文件，为下次使用做准备
 * 传入值: 无
 * 返回值: int - 成功返回0，失败返回-1
 */
int ClearShareFile() {
    FILE *file;
    
    printf("===========================================================\n");
    printf("【模块5】清理共享文件\n");
    printf("===========================================================\n\n");
    
    printf("正在清空share.txt文件...\n");
    
    // 以写模式打开文件（清空内容）
    file = fopen(SHARE_FILE, "w");
    if (file == NULL) {
        printf("✗ 无法清空共享文件\n\n");
        return -1;
    }
    
    fclose(file);
    
    printf("✓ 共享文件已清空，可供下次使用\n\n");
    
    return 0;
}

/*
 * 函数名: StopWebServer
 * 功能: 停止Web服务器
 * 传入值: 无
 * 返回值: NULL
 */
void StopWebServer() {
    printf("正在关闭Web服务器...\n");
    
    #ifdef _WIN32
        // Windows下杀死Python进程
        system("taskkill /F /IM python.exe 2>nul");
    #else
        // Linux/Mac下杀死Python进程
        system("pkill -f web.py");
    #endif
    
    SLEEP(1000);
    printf("✓ Web服务器已关闭\n\n");
}

/*
 * 函数名: PrintWelcome
 * 功能: 打印欢迎信息
 * 传入值: 无
 * 返回值: NULL
 */
void PrintWelcome() {
    printf("\n");
    printf("###########################################################\n");
    printf("#                                                         #\n");
    printf("#        用户登录验证系统 v1.0                            #\n");
    printf("#        User Login Validation System                    #\n");
    printf("#                                                         #\n");
    printf("###########################################################\n");
    printf("\n");
    printf("系统模块:\n");
    printf("  - Web通信模块 (web.py)\n");
    printf("  - 身份验证模块 (login_module.py)\n");
    printf("  - 加密算法模块 (algorithm.py)\n");
    printf("  - 数据存储模块 (DATA.xlsx)\n");
    printf("\n");
}

/*
 * 函数名: MainProcess
 * 功能: 主处理流程
 * 传入值: 无
 * 返回值: int - 成功返回0，失败返回-1
 */
int MainProcess() {
    int ret_code;
    
    printf("\n");
    printf("###########################################################\n");
    printf("#                 开始执行主流程                          #\n");
    printf("###########################################################\n");
    
    // 步骤1: 启动Web服务器
    ret_code = StartWebServer();
    if (ret_code != 0) {
        printf("主流程失败: Web服务器启动失败\n");
        return -1;
    }
    
    // 步骤2: 等待用户输入
    ret_code = WaitForUserInput();
    if (ret_code != 0) {
        printf("主流程失败: 未检测到用户输入\n");
        StopWebServer();
        return -1;
    }
    
    // 步骤3: 调用登录模块进行验证
    ret_code = CallLoginModule();
    if (ret_code != 0) {
        printf("主流程失败: 登录验证异常\n");
        ClearShareFile();
        StopWebServer();
        return -1;
    }
    
    // 步骤4: 读取并显示验证结果
    ret_code = ReadAndDisplayResult();
    
    // 步骤5: 清空共享文件
    ClearShareFile();
    
    // 关闭Web服务器
    StopWebServer();
    
    printf("###########################################################\n");
    printf("#                 主流程执行完成                          #\n");
    printf("###########################################################\n\n");
    
    return ret_code;
}

/*
 * 函数名: main
 * 功能: 程序入口
 * 传入值: 无
 * 返回值: int - 程序退出码
 */
int main() {
    int result;
    
    // 打印欢迎信息
    PrintWelcome();
    
    // 询问用户是否开始
    printf("按Enter键开始启动系统...");
    getchar();
    
    // 执行主流程
    result = MainProcess();
    
    // 打印最终结果
    if (result == 0) {
        printf("✓✓✓ 系统执行成功 ✓✓✓\n\n");
        return 0;
    } else {
        printf("✗✗✗ 系统执行失败 ✗✗✗\n\n");
        return 1;
    }
}
