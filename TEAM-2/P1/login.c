/**
 * login.c - 用户登录模块
 * 实现登录验证功能
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// 常量定义
#define MAX_USER_NAME_LENGTH 64
#define MAX_PASSWORD_LENGTH 128
#define MAX_COOKIE_LENGTH 256
#define MAX_IP_LENGTH 64
#define MAX_LINE_LENGTH 512
#define SHARE_FILE_PATH "share.txt"

// 结构体定义
typedef struct {
    char pre_user_name[MAX_USER_NAME_LENGTH];
    char pre_user_psw[MAX_PASSWORD_LENGTH];
    char pre_cookie[MAX_COOKIE_LENGTH];
    char pre_ip[MAX_IP_LENGTH];
} t_login_data;

typedef struct {
    int ret_status;         // 0: 失败, 1: 成功
    char ret_message[256];  // 返回消息
} t_login_result;

/**
 * 传入值: pre_login_data - 指向登录数据结构体的指针
 * 返回值: int - 读取成功返回1，失败返回0
 */
int ReadShareData(t_login_data *pre_login_data) {
    FILE *file = fopen(SHARE_FILE_PATH, "r");
    if (file == NULL) {
        printf("无法打开共享文件: %s\n", SHARE_FILE_PATH);
        return 0;
    }

    char line[MAX_LINE_LENGTH];
    char key[64];
    char value[MAX_LINE_LENGTH];

    // 初始化结构体
    memset(pre_login_data, 0, sizeof(t_login_data));

    while (fgets(line, sizeof(line), file) != NULL) {
        // 移除换行符
        line[strcspn(line, "\n")] = 0;
        line[strcspn(line, "\r")] = 0;

        // 解析键值对 (格式: key=value)
        char *delimiter = strchr(line, '=');
        if (delimiter != NULL) {
            *delimiter = '\0';
            strcpy(key, line);
            strcpy(value, delimiter + 1);

            if (strcmp(key, "pre_user_name") == 0) {
                strncpy(pre_login_data->pre_user_name, value, MAX_USER_NAME_LENGTH - 1);
            } else if (strcmp(key, "pre_user_psw") == 0) {
                strncpy(pre_login_data->pre_user_psw, value, MAX_PASSWORD_LENGTH - 1);
            } else if (strcmp(key, "pre_cookie") == 0) {
                strncpy(pre_login_data->pre_cookie, value, MAX_COOKIE_LENGTH - 1);
            } else if (strcmp(key, "pre_ip") == 0) {
                strncpy(pre_login_data->pre_ip, value, MAX_IP_LENGTH - 1);
            }
        }
    }

    fclose(file);
    return 1;
}

/**
 * 传入值: ret_result - 指向登录结果结构体的指针
 * 返回值: int - 写入成功返回1，失败返回0
 */
int WriteShareResult(t_login_result *ret_result) {
    FILE *file = fopen(SHARE_FILE_PATH, "w");
    if (file == NULL) {
        printf("无法写入共享文件: %s\n", SHARE_FILE_PATH);
        return 0;
    }

    fprintf(file, "ret_status=%d\n", ret_result->ret_status);
    fprintf(file, "ret_message=%s\n", ret_result->ret_message);

    fclose(file);
    return 1;
}

/**
 * 传入值: pre_user_psw - 用户密码
 *         ret_md5_hash - 用于存储MD5哈希值的缓冲区
 * 返回值: int - 计算成功返回1，失败返回0
 * 说明: 调用algorithm.py中的MD5算法
 */
int CalculateMd5Hash(const char *pre_user_psw, char *ret_md5_hash) {
    // 写入待计算的密码到临时文件
    FILE *temp_file = fopen("temp_md5_input.txt", "w");
    if (temp_file == NULL) {
        return 0;
    }
    fprintf(temp_file, "%s", pre_user_psw);
    fclose(temp_file);

    // 调用Python脚本计算MD5
    int sys_result = system("python login_helper.py md5");
    if (sys_result != 0) {
        return 0;
    }

    // 读取MD5结果
    FILE *result_file = fopen("temp_md5_output.txt", "r");
    if (result_file == NULL) {
        return 0;
    }
    if (fgets(ret_md5_hash, 64, result_file) == NULL) {
        fclose(result_file);
        return 0;
    }
    // 移除换行符
    ret_md5_hash[strcspn(ret_md5_hash, "\n")] = 0;
    ret_md5_hash[strcspn(ret_md5_hash, "\r")] = 0;
    fclose(result_file);

    // 清理临时文件
    remove("temp_md5_input.txt");
    remove("temp_md5_output.txt");

    return 1;
}

/**
 * 传入值: pre_user_name - 用户名
 *         pre_md5_hash - 密码的MD5哈希值
 * 返回值: int - 验证成功返回1，失败返回0
 * 说明: 调用login_helper.py验证用户数据
 */
int VerifyUserData(const char *pre_user_name, const char *pre_md5_hash) {
    // 写入验证数据到临时文件
    FILE *temp_file = fopen("temp_verify_input.txt", "w");
    if (temp_file == NULL) {
        return 0;
    }
    fprintf(temp_file, "%s\n%s", pre_user_name, pre_md5_hash);
    fclose(temp_file);

    // 调用Python脚本验证
    int sys_result = system("python login_helper.py verify");
    if (sys_result != 0) {
        return 0;
    }

    // 读取验证结果
    FILE *result_file = fopen("temp_verify_output.txt", "r");
    if (result_file == NULL) {
        return 0;
    }
    char result[16];
    if (fgets(result, sizeof(result), result_file) == NULL) {
        fclose(result_file);
        return 0;
    }
    fclose(result_file);

    // 清理临时文件
    remove("temp_verify_input.txt");
    remove("temp_verify_output.txt");

    // 检查结果
    if (strncmp(result, "OK", 2) == 0) {
        return 1;
    }
    return 0;
}

/**
 * 传入值: pre_user_name - 用户名
 *         pre_ip - 登录IP地址
 * 返回值: int - 更新成功返回1，失败返回0
 * 说明: 在DATA.xlsx中写入登录时间和IP
 */
int UpdateLoginRecord(const char *pre_user_name, const char *pre_ip) {
    // 写入更新数据到临时文件
    FILE *temp_file = fopen("temp_update_input.txt", "w");
    if (temp_file == NULL) {
        return 0;
    }
    fprintf(temp_file, "%s\n%s", pre_user_name, pre_ip);
    fclose(temp_file);

    // 调用Python脚本更新记录
    int sys_result = system("python login_helper.py update");

    // 清理临时文件
    remove("temp_update_input.txt");

    return (sys_result == 0) ? 1 : 0;
}

/**
 * 传入值: NULL
 * 返回值: t_login_result - 登录结果
 * 说明: 执行完整的登录验证流程
 */
t_login_result ProcessLogin() {
    t_login_result ret_result;
    t_login_data pre_login_data;

    // 初始化结果
    ret_result.ret_status = 0;
    strcpy(ret_result.ret_message, "登录失败");

    // 1. 从share.txt读取登录数据
    if (!ReadShareData(&pre_login_data)) {
        strcpy(ret_result.ret_message, "读取共享数据失败");
        return ret_result;
    }

    // 检查数据是否完整
    if (strlen(pre_login_data.pre_user_name) == 0 || 
        strlen(pre_login_data.pre_user_psw) == 0) {
        strcpy(ret_result.ret_message, "用户名或密码为空");
        return ret_result;
    }

    // 2. 计算密码的MD5哈希值
    char ret_md5_hash[64];
    if (!CalculateMd5Hash(pre_login_data.pre_user_psw, ret_md5_hash)) {
        strcpy(ret_result.ret_message, "MD5计算失败");
        return ret_result;
    }

    // 3. 验证用户数据
    if (!VerifyUserData(pre_login_data.pre_user_name, ret_md5_hash)) {
        strcpy(ret_result.ret_message, "用户名或密码错误");
        return ret_result;
    }

    // 4. 更新登录记录
    if (!UpdateLoginRecord(pre_login_data.pre_user_name, pre_login_data.pre_ip)) {
        // 登录成功但更新记录失败，仍然返回成功
        printf("警告: 更新登录记录失败\n");
    }

    // 登录成功
    ret_result.ret_status = 1;
    strcpy(ret_result.ret_message, "登录成功");

    return ret_result;
}

/**
 * 传入值: NULL
 * 返回值: int - 程序退出码
 * 说明: 主函数，执行登录验证并写入结果
 */
int main() {
    printf("=== 登录验证模块 ===\n");

    // 执行登录验证
    t_login_result ret_result = ProcessLogin();

    // 输出结果
    printf("状态: %s\n", ret_result.ret_status ? "成功" : "失败");
    printf("消息: %s\n", ret_result.ret_message);

    // 将结果写回share.txt
    WriteShareResult(&ret_result);

    return ret_result.ret_status ? 0 : 1;
}
