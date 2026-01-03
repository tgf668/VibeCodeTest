/*
 * 登录验证模块 - 负责用户登录验证和数据记录
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

// 常量定义
#define MAX_USERNAME_LENGTH 256
#define MAX_PASSWORD_LENGTH 256
#define MAX_COOKIE_LENGTH 1024
#define MAX_LINE_LENGTH 2048
#define MAX_IP_LENGTH 64
#define MD5_HASH_LENGTH 33
#define DATA_FILE "DATA.xlsx"
#define SHARE_FILE "share.txt"
#define TEMP_CSV_FILE "temp_data.csv"
#define SUCCESS 1
#define FAILURE 0

// 用户数据结构体
typedef struct {
    char t_user_name[MAX_USERNAME_LENGTH];
    char t_user_psw_hash[MAX_PASSWORD_LENGTH];
    char t_last_login_time[64];
    char t_last_login_ip[MAX_IP_LENGTH];
} t_user_data;

// 登录信息结构体
typedef struct {
    char pre_user_name[MAX_USERNAME_LENGTH];
    char pre_user_psw[MAX_PASSWORD_LENGTH];
    char pre_cookie[MAX_COOKIE_LENGTH];
    char pre_user_ip[MAX_IP_LENGTH];
} t_login_info;


/**
 * 从share.txt读取登录数据
 * 传入值: login_info - 存储登录信息的结构体指针
 * 返回值: int - 成功返回SUCCESS，失败返回FAILURE
 */
int ReadShareData(t_login_info* login_info) {
    FILE* fp = fopen(SHARE_FILE, "r");
    if (fp == NULL) {
        printf("错误: 无法打开共享文件 %s\n", SHARE_FILE);
        return FAILURE;
    }
    
    char line[MAX_LINE_LENGTH];
    char* ptr;
    
    // 初始化
    memset(login_info, 0, sizeof(t_login_info));
    strcpy(login_info->pre_user_ip, "127.0.0.1"); // 默认IP
    
    // 读取整个文件内容
    fread(line, 1, MAX_LINE_LENGTH - 1, fp);
    fclose(fp);
    
    // 简单解析JSON格式 {"pre_user_name": "xxx", "pre_user_psw": "xxx", ...}
    ptr = strstr(line, "\"pre_user_name\"");
    if (ptr != NULL) {
        ptr = strchr(ptr, ':');
        if (ptr != NULL) {
            ptr = strchr(ptr, '"');
            if (ptr != NULL) {
                ptr++;
                char* end = strchr(ptr, '"');
                if (end != NULL) {
                    int len = end - ptr;
                    // 修复：确保不超过缓冲区大小
                    if (len >= MAX_USERNAME_LENGTH) {
                        len = MAX_USERNAME_LENGTH - 1;
                    }
                    strncpy(login_info->pre_user_name, ptr, len);
                    login_info->pre_user_name[len] = '\0';
                }
            }
        }
    }
    
    ptr = strstr(line, "\"pre_user_psw\"");
    if (ptr != NULL) {
        ptr = strchr(ptr, ':');
        if (ptr != NULL) {
            ptr = strchr(ptr, '"');
            if (ptr != NULL) {
                ptr++;
                char* end = strchr(ptr, '"');
                if (end != NULL) {
                    int len = end - ptr;
                    // 修复：确保不超过缓冲区大小
                    if (len >= MAX_PASSWORD_LENGTH) {
                        len = MAX_PASSWORD_LENGTH - 1;
                    }
                    strncpy(login_info->pre_user_psw, ptr, len);
                    login_info->pre_user_psw[len] = '\0';
                }
            }
        }
    }
    
    // 检查是否成功读取
    if (strlen(login_info->pre_user_name) == 0 || strlen(login_info->pre_user_psw) == 0) {
        printf("错误: 无法从共享文件中解析用户名或密码\n");
        return FAILURE;
    }
    
    printf("成功读取共享数据: 用户名=%s\n", login_info->pre_user_name);
    return SUCCESS;
}


/**
 * 转义字符串中的特殊字符以防止命令注入
 * 传入值: 
 *   input - 输入字符串
 *   output - 输出缓冲区
 *   max_len - 输出缓冲区最大长度
 * 返回值: int - 成功返回SUCCESS，失败返回FAILURE
 */
int EscapeString(const char* input, char* output, int max_len) {
    int j = 0;
    for (int i = 0; input[i] != '\0' && j < max_len - 2; i++) {
        // 转义单引号、反斜杠等危险字符
        if (input[i] == '\'' || input[i] == '\\' || input[i] == '"' || 
            input[i] == ';' || input[i] == '&' || input[i] == '|' ||
            input[i] == '$' || input[i] == '`') {
            output[j++] = '\\';
            if (j >= max_len - 1) break;
        }
        output[j++] = input[i];
    }
    output[j] = '\0';
    return SUCCESS;
}

/**
 * 调用Python算法计算MD5哈希
 * 传入值: 
 *   input_data - 需要计算哈希的数据
 *   output_hash - 存储哈希结果的缓冲区
 * 返回值: int - 成功返回SUCCESS，失败返回FAILURE
 */
int CalculateMD5Hash(const char* input_data, char* output_hash) {
    char command[2048];
    char escaped_data[512];
    FILE* fp;
    
    // 转义输入数据以防止命令注入
    EscapeString(input_data, escaped_data, sizeof(escaped_data));
    
    // 构建Python命令
    snprintf(command, sizeof(command), 
             "python -c \"from algorithm import CalculateMD5; print(CalculateMD5('%s'), end='')\"",
             escaped_data);
    
    // 执行Python命令
    fp = popen(command, "r");
    if (fp == NULL) {
        printf("错误: 无法调用Python算法\n");
        return FAILURE;
    }
    
    // 读取MD5哈希结果
    if (fgets(output_hash, MD5_HASH_LENGTH, fp) == NULL) {
        printf("错误: 无法读取MD5哈希值\n");
        pclose(fp);
        return FAILURE;
    }
    
    pclose(fp);
    
    // 移除可能的换行符
    output_hash[strcspn(output_hash, "\n\r")] = '\0';
    
    printf("密码MD5哈希: %s\n", output_hash);
    return SUCCESS;
}


/**
 * 将Excel转换为CSV以便读取
 * 传入值: 无
 * 返回值: int - 成功返回SUCCESS，失败返回FAILURE
 */
int ConvertExcelToCSV() {
    char command[512];
    
    // 使用Python的pandas库将Excel转换为CSV
    snprintf(command, sizeof(command),
             "python -c \"import pandas as pd; df = pd.read_excel('%s'); df.to_csv('%s', index=False)\"",
             DATA_FILE, TEMP_CSV_FILE);
    
    int ret = system(command);
    if (ret != 0) {
        printf("警告: Excel转换失败，尝试直接读取CSV\n");
        return FAILURE;
    }
    
    return SUCCESS;
}


/**
 * 从数据文件中验证用户
 * 传入值: 
 *   user_name - 用户名
 *   psw_hash - 密码的MD5哈希值
 * 返回值: int - 验证成功返回SUCCESS，失败返回FAILURE
 */
int VerifyUserFromData(const char* user_name, const char* psw_hash) {
    FILE* fp;
    char line[MAX_LINE_LENGTH];
    int found = 0;
    
    // 尝试转换Excel到CSV
    ConvertExcelToCSV();
    
    // 打开CSV文件
    fp = fopen(TEMP_CSV_FILE, "r");
    if (fp == NULL) {
        printf("错误: 无法打开数据文件 %s\n", TEMP_CSV_FILE);
        return FAILURE;
    }
    
    // 跳过标题行
    fgets(line, sizeof(line), fp);
    
    // 逐行读取并比较
    while (fgets(line, sizeof(line), fp) != NULL) {
        char file_username[MAX_USERNAME_LENGTH];
        char file_password_hash[MAX_PASSWORD_LENGTH];
        
        // 解析CSV行 (假设格式: username,password_hash,...)
        char* token = strtok(line, ",");
        if (token != NULL) {
            strncpy(file_username, token, MAX_USERNAME_LENGTH - 1);
            file_username[MAX_USERNAME_LENGTH - 1] = '\0';
            
            token = strtok(NULL, ",");
            if (token != NULL) {
                strncpy(file_password_hash, token, MAX_PASSWORD_LENGTH - 1);
                file_password_hash[MAX_PASSWORD_LENGTH - 1] = '\0';
                
                // 移除换行符
                file_password_hash[strcspn(file_password_hash, "\n\r")] = '\0';
                
                // 比较用户名和密码哈希
                if (strcmp(file_username, user_name) == 0 && 
                    strcmp(file_password_hash, psw_hash) == 0) {
                    found = 1;
                    break;
                }
            }
        }
    }
    
    fclose(fp);
    
    if (found) {
        printf("用户验证成功: %s\n", user_name);
        return SUCCESS;
    } else {
        printf("用户验证失败: 用户名或密码错误\n");
        return FAILURE;
    }
}


/**
 * 获取当前时间字符串
 * 传入值: time_str - 存储时间字符串的缓冲区
 * 返回值: NULL
 */
void GetCurrentTime(char* time_str) {
    time_t now = time(NULL);
    struct tm* tm_info = localtime(&now);
    strftime(time_str, 64, "%Y-%m-%d %H:%M:%S", tm_info);
}


/**
 * 更新用户登录信息
 * 传入值: 
 *   user_name - 用户名
 *   login_ip - 登录IP地址
 * 返回值: int - 成功返回SUCCESS，失败返回FAILURE
 */
int UpdateLoginInfo(const char* user_name, const char* login_ip) {
    char command[1024];
    char current_time[64];
    
    GetCurrentTime(current_time);
    
    // 使用Python脚本更新Excel文件
    snprintf(command, sizeof(command),
             "python -c \"import pandas as pd; "
             "df = pd.read_excel('%s'); "
             "df.loc[df['username'] == '%s', 'last_login_time'] = '%s'; "
             "df.loc[df['username'] == '%s', 'last_login_ip'] = '%s'; "
             "df.to_excel('%s', index=False)\"",
             DATA_FILE, user_name, current_time, user_name, login_ip, DATA_FILE);
    
    int ret = system(command);
    if (ret != 0) {
        printf("警告: 更新登录信息失败\n");
        return FAILURE;
    }
    
    printf("登录信息已更新: 时间=%s, IP=%s\n", current_time, login_ip);
    return SUCCESS;
}


/**
 * 执行登录验证流程
 * 传入值: 无
 * 返回值: int - 成功返回SUCCESS，失败返回FAILURE
 */
int PerformLogin() {
    t_login_info login_info;
    char psw_hash[MD5_HASH_LENGTH];
    
    printf("\n===== 开始登录验证流程 =====\n\n");
    
    // 步骤1: 读取共享数据
    printf("步骤1: 读取共享数据...\n");
    if (ReadShareData(&login_info) != SUCCESS) {
        printf("登录失败: 无法读取共享数据\n");
        return FAILURE;
    }
    
    // 步骤2: 计算密码的MD5哈希
    printf("\n步骤2: 计算密码MD5哈希...\n");
    if (CalculateMD5Hash(login_info.pre_user_psw, psw_hash) != SUCCESS) {
        printf("登录失败: MD5计算失败\n");
        return FAILURE;
    }
    
    // 步骤3: 验证用户
    printf("\n步骤3: 验证用户信息...\n");
    if (VerifyUserFromData(login_info.pre_user_name, psw_hash) != SUCCESS) {
        printf("登录失败: 用户验证失败\n");
        return FAILURE;
    }
    
    // 步骤4: 更新登录信息
    printf("\n步骤4: 更新登录信息...\n");
    UpdateLoginInfo(login_info.pre_user_name, login_info.pre_user_ip);
    
    printf("\n===== 登录成功 =====\n");
    printf("欢迎, %s!\n", login_info.pre_user_name);
    
    return SUCCESS;
}


/**
 * 主函数
 */
int main() {
    int result = PerformLogin();
    
    if (result == SUCCESS) {
        printf("\n返回信息: 登录成功\n");
        return 0;
    } else {
        printf("\n返回信息: 登录失败\n");
        return 1;
    }
}
