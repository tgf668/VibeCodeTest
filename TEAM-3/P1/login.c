/*
 * 登录验证模块
 * 功能：从share.txt读取用户数据，验证登录，更新登录记录
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define MAX_LENGTH 256
#define SHARE_FILE "share.txt"
#define DATA_FILE "DATA.xlsx"
#define PYTHON_SCRIPT "login_helper.py"

// 用户登录信息结构体
typedef struct {
    char pre_user_name[MAX_LENGTH];
    char pre_user_psw[MAX_LENGTH];
    char pre_cookie[MAX_LENGTH];
} t_login_data;

// 登录结果结构体
typedef struct {
    int success;
    char message[MAX_LENGTH];
    char login_time[MAX_LENGTH];
    char ip_address[MAX_LENGTH];
} t_login_result;


/*
 * 传入值: filename (char*) - 文件名
 * 返回值: t_login_data* - 读取的登录数据结构体指针
 * 
 * 功能: 从share.txt读取共享的用户名、密码、cookie数据
 */
t_login_data* ReadFromShareFile(const char* filename) {
    FILE* fp = fopen(filename, "r");
    if (fp == NULL) {
        printf("错误: 无法打开文件 %s\n", filename);
        return NULL;
    }

    t_login_data* data = (t_login_data*)malloc(sizeof(t_login_data));
    if (data == NULL) {
        fclose(fp);
        return NULL;
    }

    // 初始化结构体
    memset(data, 0, sizeof(t_login_data));

    char line[MAX_LENGTH];
    while (fgets(line, sizeof(line), fp)) {
        // 解析JSON格式数据
        if (strstr(line, "pre_user_name")) {
            char* value_start = strchr(line, ':');
            if (value_start) {
                value_start++;
                // 跳过空格和引号
                while (*value_start == ' ' || *value_start == '"') value_start++;
                char* value_end = strrchr(value_start, '"');
                if (value_end) {
                    int len = value_end - value_start;
                    strncpy(data->pre_user_name, value_start, len);
                    data->pre_user_name[len] = '\0';
                }
            }
        } else if (strstr(line, "pre_user_psw")) {
            char* value_start = strchr(line, ':');
            if (value_start) {
                value_start++;
                while (*value_start == ' ' || *value_start == '"') value_start++;
                char* value_end = strrchr(value_start, '"');
                if (value_end) {
                    int len = value_end - value_start;
                    strncpy(data->pre_user_psw, value_start, len);
                    data->pre_user_psw[len] = '\0';
                }
            }
        } else if (strstr(line, "pre_cookie")) {
            char* value_start = strchr(line, ':');
            if (value_start) {
                value_start++;
                while (*value_start == ' ' || *value_start == '"') value_start++;
                char* value_end = strrchr(value_start, '"');
                if (value_end) {
                    int len = value_end - value_start;
                    strncpy(data->pre_cookie, value_start, len);
                    data->pre_cookie[len] = '\0';
                }
            }
        }
    }

    fclose(fp);
    return data;
}


/*
 * 传入值: password (char*) - 需要计算MD5的密码
 * 返回值: char* - MD5哈希值字符串
 * 
 * 功能: 调用Python的algorithm.py中的MD5算法计算密码哈希
 */
char* CalculateMD5WithPython(const char* password) {
    char command[MAX_LENGTH * 2];
    char* result = (char*)malloc(33); // MD5长度为32+结尾符
    
    if (result == NULL) {
        return NULL;
    }

    // 构造Python命令调用algorithm.py的MD5函数
    snprintf(command, sizeof(command), 
             "python -c \"import sys; sys.path.append('.'); from algorithm import CalculateMD5; print(CalculateMD5('%s'), end='')\"",
             password);

    FILE* pipe = popen(command, "r");
    if (pipe == NULL) {
        free(result);
        return NULL;
    }

    if (fgets(result, 33, pipe) == NULL) {
        fclose(pipe);
        free(result);
        return NULL;
    }

    pclose(pipe);
    return result;
}


/*
 * 传入值: username (char*) - 用户名, password_md5 (char*) - 密码MD5值, ip (char*) - IP地址
 * 返回值: t_login_result* - 登录验证结果结构体
 * 
 * 功能: 验证用户登录信息，读取DATA.xlsx进行比较
 */
t_login_result* ValidateLogin(const char* username, const char* password_md5, const char* ip) {
    t_login_result* result = (t_login_result*)malloc(sizeof(t_login_result));
    if (result == NULL) {
        return NULL;
    }

    memset(result, 0, sizeof(t_login_result));
    
    // 获取当前时间
    time_t now = time(NULL);
    struct tm* tm_info = localtime(&now);
    strftime(result->login_time, sizeof(result->login_time), "%Y-%m-%d %H:%M:%S", tm_info);
    strncpy(result->ip_address, ip, sizeof(result->ip_address) - 1);

    // 调用Python脚本验证登录并更新数据
    char command[MAX_LENGTH * 3];
    snprintf(command, sizeof(command),
             "python %s verify \"%s\" \"%s\" \"%s\" \"%s\"",
             PYTHON_SCRIPT, username, password_md5, result->login_time, ip);

    FILE* pipe = popen(command, "r");
    if (pipe == NULL) {
        strcpy(result->message, "调用验证脚本失败");
        result->success = 0;
        return result;
    }

    char output[MAX_LENGTH];
    if (fgets(output, sizeof(output), pipe) != NULL) {
        // 解析返回结果
        if (strstr(output, "SUCCESS") != NULL) {
            result->success = 1;
            strcpy(result->message, "登录成功");
        } else {
            result->success = 0;
            // 提取错误消息
            char* msg_start = strchr(output, ':');
            if (msg_start) {
                msg_start++;
                while (*msg_start == ' ') msg_start++;
                strncpy(result->message, msg_start, sizeof(result->message) - 1);
                // 移除换行符
                char* newline = strchr(result->message, '\n');
                if (newline) *newline = '\0';
            } else {
                strcpy(result->message, "用户名或密码错误");
            }
        }
    } else {
        result->success = 0;
        strcpy(result->message, "验证失败");
    }

    pclose(pipe);
    return result;
}


/*
 * 传入值: result (t_login_result*) - 登录结果
 * 返回值: NULL
 * 
 * 功能: 将登录结果写回share.txt供其他模块读取
 */
void WriteResultToShareFile(const t_login_result* result) {
    FILE* fp = fopen(SHARE_FILE, "a");
    if (fp == NULL) {
        printf("错误: 无法写入文件 %s\n", SHARE_FILE);
        return;
    }

    fprintf(fp, "\n--- Login Result ---\n");
    fprintf(fp, "{\n");
    fprintf(fp, "  \"success\": %s,\n", result->success ? "true" : "false");
    fprintf(fp, "  \"message\": \"%s\",\n", result->message);
    fprintf(fp, "  \"login_time\": \"%s\",\n", result->login_time);
    fprintf(fp, "  \"ip_address\": \"%s\"\n", result->ip_address);
    fprintf(fp, "}\n");

    fclose(fp);
    printf("登录结果已写入 %s\n", SHARE_FILE);
}


/*
 * 传入值: 无
 * 返回值: int - 程序退出码
 * 
 * 功能: 登录验证主流程函数
 */
int ProcessLogin() {
    printf("==================================================\n");
    printf("登录验证模块启动\n");
    printf("==================================================\n\n");

    // 1. 从share.txt读取登录数据
    printf("[步骤1] 读取共享数据...\n");
    t_login_data* login_data = ReadFromShareFile(SHARE_FILE);
    if (login_data == NULL) {
        printf("错误: 无法读取登录数据\n");
        return 1;
    }

    printf("用户名: %s\n", login_data->pre_user_name);
    printf("密码: %s\n", login_data->pre_user_psw);
    printf("Cookie: %s\n\n", login_data->pre_cookie);

    // 2. 调用algorithm.py计算密码的MD5
    printf("[步骤2] 计算密码MD5...\n");
    char* password_md5 = CalculateMD5WithPython(login_data->pre_user_psw);
    if (password_md5 == NULL) {
        printf("错误: 无法计算MD5\n");
        free(login_data);
        return 1;
    }

    printf("密码MD5: %s\n\n", password_md5);

    // 3. 从cookie中提取IP地址（简化处理）
    char ip_address[50] = "127.0.0.1"; // 默认IP
    if (strstr(login_data->pre_cookie, "ip=") != NULL) {
        // 尝试从cookie中提取IP
        char* ip_start = strstr(login_data->pre_cookie, "ip=");
        if (ip_start) {
            ip_start += 3;
            char* ip_end = strchr(ip_start, ';');
            int len = ip_end ? (ip_end - ip_start) : strlen(ip_start);
            if (len > 0 && len < 50) {
                strncpy(ip_address, ip_start, len);
                ip_address[len] = '\0';
            }
        }
    }

    // 4. 验证登录
    printf("[步骤3] 验证登录信息...\n");
    t_login_result* result = ValidateLogin(login_data->pre_user_name, password_md5, ip_address);
    
    if (result == NULL) {
        printf("错误: 验证过程失败\n");
        free(login_data);
        free(password_md5);
        return 1;
    }

    // 5. 输出结果
    printf("\n==================================================\n");
    printf("登录验证结果\n");
    printf("==================================================\n");
    printf("状态: %s\n", result->success ? "成功" : "失败");
    printf("消息: %s\n", result->message);
    printf("时间: %s\n", result->login_time);
    printf("IP: %s\n", result->ip_address);
    printf("==================================================\n\n");

    // 6. 将结果写回share.txt
    WriteResultToShareFile(result);

    // 清理内存
    free(login_data);
    free(password_md5);
    free(result);

    return 0;
}


/*
 * 主函数
 */
int main(int argc, char* argv[]) {
    return ProcessLogin();
}
