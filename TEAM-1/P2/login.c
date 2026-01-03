#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUFFER_SIZE 1024

// 函数声明
void LoginCheck();

int main() {
    LoginCheck();
    return 0;
}

void LoginCheck() {
    FILE *fp;
    char pre_user_name[BUFFER_SIZE];
    char pre_user_psw[BUFFER_SIZE];
    char pre_cookie_info[BUFFER_SIZE];
    char pre_user_ip[BUFFER_SIZE];
    char command[BUFFER_SIZE * 2];
    char md5_result[BUFFER_SIZE];
    char verify_result[BUFFER_SIZE];

    // 1. 读取 share.txt
    fp = fopen("share.txt", "r");
    if (fp == NULL) {
        printf("Error: Cannot open share.txt\n");
        return;
    }

    // 假设 share.txt 格式:
    // username
    // password
    // cookie
    // ip
    if (fgets(pre_user_name, BUFFER_SIZE, fp) != NULL) pre_user_name[strcspn(pre_user_name, "\n")] = 0;
    if (fgets(pre_user_psw, BUFFER_SIZE, fp) != NULL) pre_user_psw[strcspn(pre_user_psw, "\n")] = 0;
    if (fgets(pre_cookie_info, BUFFER_SIZE, fp) != NULL) pre_cookie_info[strcspn(pre_cookie_info, "\n")] = 0;
    if (fgets(pre_user_ip, BUFFER_SIZE, fp) != NULL) pre_user_ip[strcspn(pre_user_ip, "\n")] = 0;
    
    fclose(fp);

    printf("Read from share.txt:\nUser: %s\nPass: %s\nIP: %s\n", pre_user_name, pre_user_psw, pre_user_ip);

    // 2. 调用 algorithm.py 计算 MD5
    // 注意：这里假设 python 在环境变量中，或者使用相对路径
    // 为了稳健性，可以使用 python3 或 python
    sprintf(command, "python algorithm.py md5 \"%s\"", pre_user_psw);
    
    fp = _popen(command, "r"); // Windows 使用 _popen
    if (fp == NULL) {
        printf("Error: Failed to run python script for MD5\n");
        return;
    }
    
    if (fgets(md5_result, BUFFER_SIZE, fp) != NULL) {
        md5_result[strcspn(md5_result, "\n")] = 0; // 去除换行符
    }
    _pclose(fp);
    
    printf("Calculated MD5: %s\n", md5_result);

    // 3. 调用 algorithm.py 验证用户并更新 Excel
    sprintf(command, "python algorithm.py verify_user \"%s\" \"%s\" \"%s\"", pre_user_name, md5_result, pre_user_ip);
    
    fp = _popen(command, "r");
    if (fp == NULL) {
        printf("Error: Failed to run python script for verification\n");
        return;
    }
    
    if (fgets(verify_result, BUFFER_SIZE, fp) != NULL) {
        verify_result[strcspn(verify_result, "\n")] = 0;
    }
    _pclose(fp);

    // 4. 输出结果
    if (strcmp(verify_result, "OK") == 0) {
        printf("Login Successful!\n");
    } else {
        printf("Login Failed: %s\n", verify_result);
    }
}
