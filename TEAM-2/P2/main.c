/*
 * 主模块 - 集成所有模块，完成整体登录验证流程
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
    #include <windows.h>
    #define SLEEP(ms) Sleep(ms)
    #define CLEAR_SCREEN "cls"
#else
    #include <unistd.h>
    #define SLEEP(ms) usleep((ms) * 1000)
    #define CLEAR_SCREEN "clear"
#endif

// 常量定义
#define MAX_INPUT_LENGTH 256
#define SHARE_FILE "share.txt"
#define WEB_SERVER_SCRIPT "web.py"
#define LOGIN_PROGRAM "login.exe"
#define SUCCESS 1
#define FAILURE 0
#define SERVER_STARTUP_DELAY 3000  // Web服务器启动延迟（毫秒）

// 全局变量
static int web_server_pid = -1;  // Web服务器进程ID


/**
 * 启动Web服务器
 * 传入值: 无
 * 返回值: int - 成功返回SUCCESS，失败返回FAILURE
 */
int StartWebServer() {
    printf("\n==============================================\n");
    printf("        启动Web通信服务器\n");
    printf("==============================================\n\n");
    
    printf("正在启动Web服务器...\n");
    
    // Windows下使用start命令后台启动Python服务器
    #ifdef _WIN32
        char command[512];
        snprintf(command, sizeof(command), 
                "start /B python %s local > web_server.log 2>&1", 
                WEB_SERVER_SCRIPT);
        int ret = system(command);
    #else
        char command[512];
        snprintf(command, sizeof(command), 
                "python %s local > web_server.log 2>&1 &", 
                WEB_SERVER_SCRIPT);
        int ret = system(command);
    #endif
    
    if (ret != 0) {
        printf("错误: Web服务器启动失败\n");
        return FAILURE;
    }
    
    printf("Web服务器正在后台启动...\n");
    printf("等待服务器初始化");
    
    // 等待服务器启动
    for (int i = 0; i < 3; i++) {
        SLEEP(1000);
        printf(".");
        fflush(stdout);
    }
    
    printf("\n\n✓ Web服务器已启动！\n");
    printf("✓ 服务器地址: http://127.0.0.1:5000\n");
    printf("✓ 请在浏览器中打开上述地址进行登录\n\n");
    
    return SUCCESS;
}


/**
 * 等待用户通过Web界面输入登录信息
 * 传入值: 无
 * 返回值: int - 用户输入完成返回SUCCESS，超时或错误返回FAILURE
 */
int WaitForUserInput() {
    printf("==============================================\n");
    printf("        等待用户登录\n");
    printf("==============================================\n\n");
    
    printf("请在浏览器中访问: http://127.0.0.1:5000\n");
    printf("并输入用户名和密码进行登录\n\n");
    printf("等待用户输入");
    
    int max_wait_time = 300;  // 最大等待时间（秒）
    int wait_count = 0;
    
    // 轮询检查share.txt文件是否被创建/更新
    while (wait_count < max_wait_time) {
        FILE* fp = fopen(SHARE_FILE, "r");
        if (fp != NULL) {
            // 检查文件是否有内容
            fseek(fp, 0, SEEK_END);
            long file_size = ftell(fp);
            fclose(fp);
            
            if (file_size > 10) {  // 文件有内容
                printf("\n\n✓ 检测到用户输入！\n");
                return SUCCESS;
            }
        }
        
        // 每5秒显示一次进度
        if (wait_count % 5 == 0) {
            printf(".");
            fflush(stdout);
        }
        
        SLEEP(1000);
        wait_count++;
    }
    
    printf("\n\n✗ 等待超时\n");
    return FAILURE;
}


/**
 * 调用登录模块进行身份验证
 * 传入值: 无
 * 返回值: int - 验证成功返回SUCCESS，失败返回FAILURE
 */
int PerformAuthentication() {
    printf("\n==============================================\n");
    printf("        执行身份验证\n");
    printf("==============================================\n\n");
    
    printf("正在调用登录验证模块...\n\n");
    
    // 调用login程序
    int ret = system(LOGIN_PROGRAM);
    
    printf("\n");
    
    if (ret == 0) {
        printf("✓ 身份验证成功！\n");
        return SUCCESS;
    } else {
        printf("✗ 身份验证失败！\n");
        return FAILURE;
    }
}


/**
 * 清空共享文件
 * 传入值: 无
 * 返回值: NULL
 */
void ClearShareFile() {
    printf("\n==============================================\n");
    printf("        清理共享文件\n");
    printf("==============================================\n\n");
    
    FILE* fp = fopen(SHARE_FILE, "w");
    if (fp != NULL) {
        fclose(fp);
        printf("✓ 共享文件已清空，准备下次使用\n");
    } else {
        printf("✗ 警告: 无法清空共享文件\n");
    }
}


/**
 * 返回验证结果给用户
 * 传入值: 
 *   success - 验证是否成功
 * 返回值: NULL
 */
void ReturnResultToUser(int success) {
    printf("\n==============================================\n");
    printf("        验证结果\n");
    printf("==============================================\n\n");
    
    if (success) {
        printf("┌─────────────────────────────────────────┐\n");
        printf("│                                         │\n");
        printf("│        ✓ 登录成功！                     │\n");
        printf("│                                         │\n");
        printf("│        欢迎使用系统                     │\n");
        printf("│                                         │\n");
        printf("└─────────────────────────────────────────┘\n");
        printf("\n返回信息: SUCCESS - 用户身份验证通过\n");
    } else {
        printf("┌─────────────────────────────────────────┐\n");
        printf("│                                         │\n");
        printf("│        ✗ 登录失败！                     │\n");
        printf("│                                         │\n");
        printf("│        请检查用户名和密码               │\n");
        printf("│                                         │\n");
        printf("└─────────────────────────────────────────┘\n");
        printf("\n返回信息: FAILURE - 用户身份验证失败\n");
    }
}


/**
 * 停止Web服务器
 * 传入值: 无
 * 返回值: NULL
 */
void StopWebServer() {
    printf("\n正在关闭Web服务器...\n");
    
    #ifdef _WIN32
        // Windows下杀死Python进程
        system("taskkill /F /IM python.exe /T >nul 2>&1");
    #else
        // Linux/Mac下杀死Python进程
        system("pkill -f \"python.*web.py\"");
    #endif
    
    SLEEP(1000);
    printf("✓ Web服务器已关闭\n");
}


/**
 * 显示欢迎信息
 * 传入值: 无
 * 返回值: NULL
 */
void ShowWelcome() {
    system(CLEAR_SCREEN);
    
    printf("\n");
    printf("╔═══════════════════════════════════════════════════════╗\n");
    printf("║                                                       ║\n");
    printf("║           用户登录验证系统 v1.0                       ║\n");
    printf("║                                                       ║\n");
    printf("║           Integration Module - Main Program          ║\n");
    printf("║                                                       ║\n");
    printf("╚═══════════════════════════════════════════════════════╝\n");
    printf("\n");
}


/**
 * 显示系统状态
 * 传入值: 无
 * 返回值: NULL
 */
void ShowSystemStatus() {
    printf("系统模块状态:\n");
    printf("  [✓] Web通信模块 (web.py)\n");
    printf("  [✓] 登录验证模块 (login.c)\n");
    printf("  [✓] 算法模块 (algorithm.py)\n");
    printf("  [✓] 数据存储 (DATA.xlsx)\n");
    printf("\n");
}


/**
 * 执行完整的登录流程
 * 传入值: 无
 * 返回值: int - 成功返回SUCCESS，失败返回FAILURE
 */
int ExecuteLoginFlow() {
    int ret_result = FAILURE;
    
    // 步骤1: 启动Web服务器
    if (StartWebServer() != SUCCESS) {
        printf("\n错误: Web服务器启动失败，无法继续\n");
        return FAILURE;
    }
    
    // 步骤2: 等待用户输入
    printf("按Enter键打开浏览器进行登录...\n");
    getchar();
    
    // 尝试自动打开浏览器
    #ifdef _WIN32
        system("start http://127.0.0.1:5000");
    #else
        system("xdg-open http://127.0.0.1:5000 2>/dev/null || open http://127.0.0.1:5000");
    #endif
    
    if (WaitForUserInput() != SUCCESS) {
        printf("\n错误: 未检测到用户输入\n");
        StopWebServer();
        return FAILURE;
    }
    
    // 步骤3: 执行身份验证
    ret_result = PerformAuthentication();
    
    // 步骤4: 清空共享文件
    ClearShareFile();
    
    // 步骤5: 返回结果给用户
    ReturnResultToUser(ret_result);
    
    // 关闭Web服务器
    StopWebServer();
    
    return ret_result;
}


/**
 * 显示菜单
 * 传入值: 无
 * 返回值: NULL
 */
void ShowMenu() {
    printf("\n");
    printf("请选择操作:\n");
    printf("  1. 开始登录流程\n");
    printf("  2. 查看系统状态\n");
    printf("  3. 清空共享文件\n");
    printf("  4. 退出系统\n");
    printf("\n请输入选项 (1-4): ");
}


/**
 * 主函数
 */
int main() {
    int choice;
    int running = 1;
    
    ShowWelcome();
    ShowSystemStatus();
    
    while (running) {
        ShowMenu();
        
        if (scanf("%d", &choice) != 1) {
            // 清空输入缓冲区
            while (getchar() != '\n');
            printf("\n无效输入，请输入数字 1-4\n");
            continue;
        }
        
        // 清空输入缓冲区
        while (getchar() != '\n');
        
        switch (choice) {
            case 1:
                // 开始登录流程
                printf("\n");
                if (ExecuteLoginFlow() == SUCCESS) {
                    printf("\n登录流程执行成功\n");
                } else {
                    printf("\n登录流程执行失败\n");
                }
                printf("\n按Enter键继续...");
                getchar();
                system(CLEAR_SCREEN);
                ShowWelcome();
                break;
                
            case 2:
                // 查看系统状态
                printf("\n");
                ShowSystemStatus();
                
                // 检查文件是否存在
                printf("文件状态检查:\n");
                FILE* fp;
                
                fp = fopen("web.py", "r");
                printf("  [%s] web.py\n", fp ? "✓" : "✗");
                if (fp) fclose(fp);
                
                fp = fopen("algorithm.py", "r");
                printf("  [%s] algorithm.py\n", fp ? "✓" : "✗");
                if (fp) fclose(fp);
                
                fp = fopen("login.exe", "r");
                printf("  [%s] login.exe\n", fp ? "✓" : "✗");
                if (fp) fclose(fp);
                
                fp = fopen("DATA.xlsx", "r");
                printf("  [%s] DATA.xlsx\n", fp ? "✓" : "✗");
                if (fp) fclose(fp);
                
                printf("\n按Enter键继续...");
                getchar();
                break;
                
            case 3:
                // 清空共享文件
                printf("\n");
                ClearShareFile();
                printf("\n按Enter键继续...");
                getchar();
                break;
                
            case 4:
                // 退出系统
                printf("\n");
                printf("正在退出系统...\n");
                StopWebServer();
                printf("感谢使用！再见！\n\n");
                running = 0;
                break;
                
            default:
                printf("\n无效选项，请输入 1-4\n");
                printf("按Enter键继续...");
                getchar();
                break;
        }
    }
    
    return 0;
}
