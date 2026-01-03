/**
 * main.c - 主模块
 * 集成各模块，完成完整的登录验证流程
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// 常量定义
#define SHARE_FILE_PATH "share.txt"
#define MAX_LINE_LENGTH 512
#define WEB_SERVER_SCRIPT "python web.py server"
#define LOGIN_MODULE "login.exe"

// 结构体定义
typedef struct {
    int ret_status;
    char ret_message[256];
} t_result_data;

/**
 * 传入值: NULL
 * 返回值: int - 启动成功返回1，失败返回0
 * 说明: 调用web.py启动Web服务器等待用户输入
 */
int StartWebServer() {
    printf("[主模块] 正在启动Web通信模块...\n");
    
    // 调用Python脚本处理Web通信
    int sys_result = system("python main_helper.py start_web");
    
    if (sys_result != 0) {
        printf("[主模块] Web通信模块启动失败\n");
        return 0;
    }
    
    printf("[主模块] Web通信完成，已接收用户数据\n");
    return 1;
}

/**
 * 传入值: NULL
 * 返回值: int - 验证成功返回1，失败返回0
 * 说明: 调用login模块进行身份验证
 */
int CallLoginModule() {
    printf("[主模块] 正在调用登录验证模块...\n");
    
    // 调用login模块（编译后的可执行文件或通过Python辅助调用）
    int sys_result = system("python main_helper.py login");
    
    if (sys_result != 0) {
        printf("[主模块] 登录验证模块调用失败\n");
        return 0;
    }
    
    printf("[主模块] 登录验证完成\n");
    return 1;
}

/**
 * 传入值: NULL
 * 返回值: int - 清空成功返回1，失败返回0
 * 说明: 清空share.txt文件，准备下一次使用
 */
int ClearShareFile() {
    FILE *file = fopen(SHARE_FILE_PATH, "w");
    if (file == NULL) {
        printf("[主模块] 无法清空共享文件\n");
        return 0;
    }
    
    fclose(file);
    printf("[主模块] 共享文件已清空\n");
    return 1;
}

/**
 * 传入值: ret_result - 指向结果结构体的指针
 * 返回值: int - 读取成功返回1，失败返回0
 * 说明: 从share.txt读取验证结果
 */
int ReadResultFromShare(t_result_data *ret_result) {
    FILE *file = fopen(SHARE_FILE_PATH, "r");
    if (file == NULL) {
        printf("[主模块] 无法读取共享文件\n");
        return 0;
    }
    
    char line[MAX_LINE_LENGTH];
    char key[64];
    char value[MAX_LINE_LENGTH];
    
    // 初始化结果
    ret_result->ret_status = 0;
    strcpy(ret_result->ret_message, "未知错误");
    
    while (fgets(line, sizeof(line), file) != NULL) {
        // 移除换行符
        line[strcspn(line, "\n")] = 0;
        line[strcspn(line, "\r")] = 0;
        
        // 解析键值对
        char *delimiter = strchr(line, '=');
        if (delimiter != NULL) {
            *delimiter = '\0';
            strcpy(key, line);
            strcpy(value, delimiter + 1);
            
            if (strcmp(key, "ret_status") == 0) {
                ret_result->ret_status = atoi(value);
            } else if (strcmp(key, "ret_message") == 0) {
                strncpy(ret_result->ret_message, value, sizeof(ret_result->ret_message) - 1);
            }
        }
    }
    
    fclose(file);
    return 1;
}

/**
 * 传入值: ret_result - 指向结果结构体的指针
 * 返回值: NULL
 * 说明: 将验证结果返回给用户（通过Web或控制台）
 */
void SendResultToUser(t_result_data *ret_result) {
    printf("\n");
    printf("========================================\n");
    printf("           验证结果\n");
    printf("========================================\n");
    printf("状态: %s\n", ret_result->ret_status ? "成功" : "失败");
    printf("消息: %s\n", ret_result->ret_message);
    printf("========================================\n");
    
    // 同时通过Python将结果发送回Web端
    FILE *temp_file = fopen("temp_result.txt", "w");
    if (temp_file != NULL) {
        fprintf(temp_file, "%d\n%s", ret_result->ret_status, ret_result->ret_message);
        fclose(temp_file);
        
        system("python main_helper.py send_result");
        
        remove("temp_result.txt");
    }
}

/**
 * 传入值: NULL
 * 返回值: NULL
 * 说明: 执行完整的登录验证流程
 */
void RunLoginProcess() {
    t_result_data ret_result;
    
    printf("\n");
    printf("################################################\n");
    printf("#         后端登录验证系统 v1.0                #\n");
    printf("################################################\n\n");
    
    // 步骤1: 启动Web通信，等待用户输入
    printf("[步骤1] 启动Web通信模块\n");
    if (!StartWebServer()) {
        ret_result.ret_status = 0;
        strcpy(ret_result.ret_message, "Web通信失败");
        SendResultToUser(&ret_result);
        return;
    }
    
    // 步骤2: 调用登录验证模块
    printf("\n[步骤2] 执行登录验证\n");
    if (!CallLoginModule()) {
        ret_result.ret_status = 0;
        strcpy(ret_result.ret_message, "登录模块调用失败");
        SendResultToUser(&ret_result);
        ClearShareFile();
        return;
    }
    
    // 步骤3: 读取验证结果
    printf("\n[步骤3] 获取验证结果\n");
    if (!ReadResultFromShare(&ret_result)) {
        ret_result.ret_status = 0;
        strcpy(ret_result.ret_message, "读取结果失败");
    }
    
    // 步骤4: 将结果返回给用户
    printf("\n[步骤4] 返回验证结果\n");
    SendResultToUser(&ret_result);
    
    // 步骤5: 清空share.txt文件
    printf("\n[步骤5] 清理临时数据\n");
    ClearShareFile();
    
    printf("\n[主模块] 登录流程完成\n");
}

/**
 * 传入值: argc - 命令行参数数量
 *         argv - 命令行参数数组
 * 返回值: int - 程序退出码
 */
int main(int argc, char *argv[]) {
    // 执行登录流程
    RunLoginProcess();
    
    return 0;
}
