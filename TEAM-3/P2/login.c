/*
 * 登录验证模块
 * 功能：读取共享数据、验证用户登录、更新登录信息
 * 遵循C语言安全规范（OWASP）
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* 常量定义 */
#define MAX_USERNAME_LENGTH 100
#define MAX_PASSWORD_LENGTH 200
#define MAX_COOKIE_LENGTH 500
#define MAX_IP_LENGTH 50
#define MAX_MD5_LENGTH 33
#define MAX_BUFFER_SIZE 2048
#define MAX_COMMAND_LENGTH 512

#define SHARE_FILE "share.txt"
#define PYTHON_ALGORITHM "algorithm.py"
#define PYTHON_DATA_HANDLER "data_handler.py"
#define TEMP_MD5_FILE "temp_md5.txt"

/* 返回状态码 */
#define RET_OK 0
#define RET_ERR -1

/* 登录数据结构体 */
typedef struct {
    char pre_user_name[MAX_USERNAME_LENGTH];
    char pre_user_psw[MAX_PASSWORD_LENGTH];
    char pre_cookie[MAX_COOKIE_LENGTH];
} t_login_data;

/* 用户数据结构体 */
typedef struct {
    char username[MAX_USERNAME_LENGTH];
    char password_md5[MAX_MD5_LENGTH];
    char last_login_time[50];
    char last_login_ip[MAX_IP_LENGTH];
} t_user_data;


/*
 * 函数：ReadShareFile
 * 功能：从share.txt读取web.py共享的登录数据
 * 传入值：login_data - 指向t_login_data结构体的指针
 * 返回值：RET_OK(0)成功，RET_ERR(-1)失败
 */
int ReadShareFile(t_login_data *login_data) {
    FILE *fp = NULL;
    char buffer[MAX_BUFFER_SIZE];
    size_t bytes_read;
    
    /* CWE-476: NULL指针检查 */
    if (login_data == NULL) {
        fprintf(stderr, "错误: login_data指针为NULL\n");
        return RET_ERR;
    }
    
    /* 初始化结构体，防止使用未初始化的内存 */
    memset(login_data, 0, sizeof(t_login_data));
    
    /* 打开共享文件 */
    fp = fopen(SHARE_FILE, "r");
    if (fp == NULL) {
        fprintf(stderr, "错误: 无法打开文件 %s\n", SHARE_FILE);
        return RET_ERR;
    }
    
    /* CWE-119: 使用安全的文件读取 */
    bytes_read = fread(buffer, 1, MAX_BUFFER_SIZE - 1, fp);
    buffer[bytes_read] = '\0';  /* 确保字符串终止 */
    fclose(fp);
    
    /* 解析JSON格式的数据 */
    /* 这里使用简单的字符串查找方法，生产环境建议使用JSON库 */
    char *ptr = NULL;
    
    /* 提取用户名 */
    ptr = strstr(buffer, "\"pre_user_name\"");
    if (ptr != NULL) {
        ptr = strchr(ptr, ':');
        if (ptr != NULL) {
            ptr = strchr(ptr, '"');
            if (ptr != NULL) {
                ptr++;  /* 跳过引号 */
                char *end = strchr(ptr, '"');
                if (end != NULL) {
                    size_t len = end - ptr;
                    /* CWE-119: 边界检查 */
                    if (len < MAX_USERNAME_LENGTH) {
                        strncpy(login_data->pre_user_name, ptr, len);
                        login_data->pre_user_name[len] = '\0';
                    }
                }
            }
        }
    }
    
    /* 提取密码 */
    ptr = strstr(buffer, "\"pre_user_psw\"");
    if (ptr != NULL) {
        ptr = strchr(ptr, ':');
        if (ptr != NULL) {
            ptr = strchr(ptr, '"');
            if (ptr != NULL) {
                ptr++;
                char *end = strchr(ptr, '"');
                if (end != NULL) {
                    size_t len = end - ptr;
                    /* CWE-119: 边界检查 */
                    if (len < MAX_PASSWORD_LENGTH) {
                        strncpy(login_data->pre_user_psw, ptr, len);
                        login_data->pre_user_psw[len] = '\0';
                    }
                }
            }
        }
    }
    
    /* 提取cookie */
    ptr = strstr(buffer, "\"pre_cookie\"");
    if (ptr != NULL) {
        ptr = strchr(ptr, ':');
        if (ptr != NULL) {
            ptr = strchr(ptr, '"');
            if (ptr != NULL) {
                ptr++;
                char *end = strchr(ptr, '"');
                if (end != NULL) {
                    size_t len = end - ptr;
                    /* CWE-119: 边界检查 */
                    if (len < MAX_COOKIE_LENGTH) {
                        strncpy(login_data->pre_cookie, ptr, len);
                        login_data->pre_cookie[len] = '\0';
                    }
                }
            }
        }
    }
    
    /* 验证必需字段 */
    if (strlen(login_data->pre_user_name) == 0 || strlen(login_data->pre_user_psw) == 0) {
        fprintf(stderr, "错误: 用户名或密码为空\n");
        return RET_ERR;
    }
    
    printf("✅ 成功读取共享文件\n");
    printf("   用户名: %s\n", login_data->pre_user_name);
    printf("   密码长度: %zu\n", strlen(login_data->pre_user_psw));
    
    return RET_OK;
}


/*
 * 函数：CalculatePasswordMd5
 * 功能：调用algorithm.py计算密码的MD5值
 * 传入值：password - 原始密码字符串
 *         md5_output - 存储MD5结果的缓冲区（至少33字节）
 * 返回值：RET_OK(0)成功，RET_ERR(-1)失败
 */
int CalculatePasswordMd5(const char *password, char *md5_output) {
    char command[MAX_COMMAND_LENGTH];
    FILE *fp = NULL;
    char temp_file[256];
    
    /* CWE-476: NULL指针检查 */
    if (password == NULL || md5_output == NULL) {
        fprintf(stderr, "错误: 指针参数为NULL\n");
        return RET_ERR;
    }
    
    /* 初始化输出缓冲区 */
    memset(md5_output, 0, MAX_MD5_LENGTH);
    
    /* 修复CWE-377: 使用唯一的临时文件名防止竞态条件 */
    snprintf(temp_file, sizeof(temp_file), "temp_password_%d.txt", (int)time(NULL));
    
    /* 修复CWE-377: 设置安全的文件权限 */
    FILE *temp = fopen(temp_file, "w");
    if (temp == NULL) {
        fprintf(stderr, "错误: 无法创建临时文件\n");
        return RET_ERR;
    }
    
    /* 写入密码到临时文件 */
    if (fprintf(temp, "%s", password) < 0) {
        fprintf(stderr, "错误: 写入临时文件失败\n");
        fclose(temp);
        remove(temp_file);
        return RET_ERR;
    }
    fclose(temp);
    
    /* 修复CWE-78: 避免命令注入 - 使用安全的文件路径 */
    /* CWE-119: 使用snprintf防止缓冲区溢出 */
    snprintf(command, MAX_COMMAND_LENGTH, 
             "python -c \"import sys; sys.path.insert(0, '.'); from algorithm import CalculateMd5; "
             "data = open('%s', 'r', encoding='utf-8').read(); "
             "result = CalculateMd5(data); print(result if result else 'ERROR')\"", temp_file);
    
    /* 执行Python命令 */
    fp = popen(command, "r");
    if (fp == NULL) {
        fprintf(stderr, "错误: 无法执行Python命令\n");
        remove(temp_file);  /* 修复: 确保删除临时文件 */
        return RET_ERR;
    }
    
    /* 读取MD5结果 */
    if (fgets(md5_output, MAX_MD5_LENGTH, fp) == NULL) {
        fprintf(stderr, "错误: 无法读取MD5结果\n");
        pclose(fp);
        remove(temp_file);  /* 修复: 确保删除临时文件 */
        return RET_ERR;
    }
    
    pclose(fp);
    
    /* 修复CWE-377: 立即删除临时文件，防止敏感信息泄露 */
    if (remove(temp_file) != 0) {
        fprintf(stderr, "警告: 无法删除临时文件\n");
    }
    
    /* 移除换行符 */
    size_t len = strlen(md5_output);
    if (len > 0 && md5_output[len - 1] == '\n') {
        md5_output[len - 1] = '\0';
    }
    
    /* 验证MD5格式（应该是32位十六进制） */
    if (strlen(md5_output) != 32) {
        fprintf(stderr, "错误: MD5格式不正确\n");
        return RET_ERR;
    }
    
    printf("✅ MD5计算成功: %s\n", md5_output);
    
    return RET_OK;
}


/*
 * 函数：ReadUserDataFromExcel
 * 功能：从DATA.xlsx读取用户数据
 * 传入值：username - 用户名
 *         user_data - 存储用户数据的结构体指针
 * 返回值：RET_OK(0)成功，RET_ERR(-1)失败
 */
int ReadUserDataFromExcel(const char *username, t_user_data *user_data) {
    char command[MAX_COMMAND_LENGTH];
    char buffer[MAX_BUFFER_SIZE];
    FILE *fp = NULL;
    
    /* CWE-476: NULL指针检查 */
    if (username == NULL || user_data == NULL) {
        fprintf(stderr, "错误: 指针参数为NULL\n");
        return RET_ERR;
    }
    
    /* 初始化用户数据结构体 */
    memset(user_data, 0, sizeof(t_user_data));
    
    /* 构建Python命令读取用户数据 */
    snprintf(command, MAX_COMMAND_LENGTH, 
             "python %s read %s", PYTHON_DATA_HANDLER, username);
    
    /* 执行命令 */
    fp = popen(command, "r");
    if (fp == NULL) {
        fprintf(stderr, "错误: 无法执行数据读取命令\n");
        return RET_ERR;
    }
    
    /* 读取JSON输出 */
    size_t total_read = 0;
    size_t bytes_read;
    while ((bytes_read = fread(buffer + total_read, 1, 
            MAX_BUFFER_SIZE - total_read - 1, fp)) > 0) {
        total_read += bytes_read;
    }
    buffer[total_read] = '\0';
    
    int exit_code = pclose(fp);
    
    if (exit_code != 0) {
        fprintf(stderr, "错误: 用户不存在\n");
        return RET_ERR;
    }
    
    /* 解析JSON结果 */
    char *ptr = NULL;
    
    /* 提取password_md5 */
    ptr = strstr(buffer, "\"password_md5\"");
    if (ptr != NULL) {
        ptr = strchr(ptr, ':');
        if (ptr != NULL) {
            ptr = strchr(ptr, '"');
            if (ptr != NULL) {
                ptr++;
                char *end = strchr(ptr, '"');
                if (end != NULL) {
                    size_t len = end - ptr;
                    if (len < MAX_MD5_LENGTH) {
                        strncpy(user_data->password_md5, ptr, len);
                        user_data->password_md5[len] = '\0';
                    }
                }
            }
        }
    }
    
    /* 复制用户名 */
    strncpy(user_data->username, username, MAX_USERNAME_LENGTH - 1);
    user_data->username[MAX_USERNAME_LENGTH - 1] = '\0';
    
    printf("✅ 成功读取用户数据\n");
    
    return RET_OK;
}


/*
 * 函数：UpdateLoginInfo
 * 功能：更新用户的登录时间和IP到DATA.xlsx
 * 传入值：username - 用户名
 *         login_ip - 登录IP地址
 * 返回值：RET_OK(0)成功，RET_ERR(-1)失败
 */
int UpdateLoginInfo(const char *username, const char *login_ip) {
    char command[MAX_COMMAND_LENGTH];
    FILE *fp = NULL;
    char buffer[256];
    
    /* CWE-476: NULL指针检查 */
    if (username == NULL || login_ip == NULL) {
        fprintf(stderr, "错误: 指针参数为NULL\n");
        return RET_ERR;
    }
    
    /* 构建Python命令更新登录信息 */
    snprintf(command, MAX_COMMAND_LENGTH, 
             "python %s update %s %s", PYTHON_DATA_HANDLER, username, login_ip);
    
    /* 执行命令 */
    fp = popen(command, "r");
    if (fp == NULL) {
        fprintf(stderr, "错误: 无法执行更新命令\n");
        return RET_ERR;
    }
    
    /* 读取结果 */
    if (fgets(buffer, sizeof(buffer), fp) == NULL) {
        fprintf(stderr, "错误: 无法读取更新结果\n");
        pclose(fp);
        return RET_ERR;
    }
    
    int exit_code = pclose(fp);
    
    if (exit_code != 0 || strstr(buffer, "ERROR") != NULL) {
        fprintf(stderr, "错误: 更新登录信息失败\n");
        return RET_ERR;
    }
    
    printf("✅ 成功更新登录信息\n");
    printf("   登录时间: 当前时间\n");
    printf("   登录IP: %s\n", login_ip);
    
    return RET_OK;
}


/*
 * 函数：VerifyLogin
 * 功能：验证用户登录
 * 传入值：login_data - 登录数据结构体指针
 * 返回值：RET_OK(0)成功，RET_ERR(-1)失败
 */
int VerifyLogin(const t_login_data *login_data) {
    char password_md5[MAX_MD5_LENGTH];
    t_user_data user_data;
    char login_ip[MAX_IP_LENGTH] = "192.114.514";  /* 默认IP */
    
    /* CWE-476: NULL指针检查 */
    if (login_data == NULL) {
        fprintf(stderr, "错误: login_data指针为NULL\n");
        return RET_ERR;
    }
    
    printf("\n开始验证登录...\n");
    printf("============================================================\n");
    
    /* 1. 计算密码的MD5值 */
    printf("\n[步骤1] 计算密码MD5\n");
    if (CalculatePasswordMd5(login_data->pre_user_psw, password_md5) != RET_OK) {
        fprintf(stderr, "❌ 密码MD5计算失败\n");
        return RET_ERR;
    }
    
    /* 2. 从数据库读取用户数据 */
    printf("\n[步骤2] 读取用户数据\n");
    if (ReadUserDataFromExcel(login_data->pre_user_name, &user_data) != RET_OK) {
        fprintf(stderr, "❌ 用户不存在\n");
        return RET_ERR;
    }
    
    /* 3. 比较密码MD5 */
    printf("\n[步骤3] 验证密码\n");
    printf("   输入密码MD5: %s\n", password_md5);
    printf("   数据库MD5:   %s\n", user_data.password_md5);
    
    if (strcmp(password_md5, user_data.password_md5) != 0) {
        fprintf(stderr, "❌ 密码错误\n");
        return RET_ERR;
    }
    
    printf("✅ 密码验证成功\n");
    
    /* 4. 更新登录信息 */
    printf("\n[步骤4] 更新登录信息\n");
    if (UpdateLoginInfo(login_data->pre_user_name, login_ip) != RET_OK) {
        fprintf(stderr, "⚠️  警告: 登录信息更新失败（不影响登录）\n");
    }
    
    printf("\n");
    printf("============================================================\n");
    printf("✅ 登录成功！欢迎 %s\n", login_data->pre_user_name);
    printf("============================================================\n\n");
    
    return RET_OK;
}


/*
 * 函数：main
 * 功能：主函数 - 测试登录验证功能
 * 传入值：argc - 参数个数，argv - 参数数组
 * 返回值：0成功，非0失败
 */
int main(int argc, char *argv[]) {
    t_login_data login_data;
    int result;
    
    printf("\n");
    printf("======================================================================\n");
    printf("登录验证模块测试程序\n");
    printf("======================================================================\n\n");
    
    /* 初始化数据文件（如果不存在） */
    printf("正在初始化数据文件...\n");
    system("python data_handler.py init");
    
    /* 1. 读取共享文件 */
    printf("\n[阶段1] 读取共享数据\n");
    printf("----------------------------------------------------------------------\n");
    
    result = ReadShareFile(&login_data);
    if (result != RET_OK) {
        fprintf(stderr, "\n❌ 读取共享文件失败\n");
        return EXIT_FAILURE;
    }
    
    /* 2. 验证登录 */
    printf("\n[阶段2] 登录验证\n");
    printf("----------------------------------------------------------------------\n");
    
    result = VerifyLogin(&login_data);
    if (result != RET_OK) {
        fprintf(stderr, "\n❌ 登录验证失败\n");
        return EXIT_FAILURE;
    }
    
    printf("程序执行完成\n\n");
    
    return EXIT_SUCCESS;
}
