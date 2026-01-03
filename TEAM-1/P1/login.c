/*
 * 登录验证模块 (C语言版本)
 * 通过调用Python脚本实现登录验证功能
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// 配置常量
#define PYTHON_SCRIPT "login_module.py"
#define RESULT_FILE "login_result.txt"
#define MAX_BUFFER_SIZE 1024

/*
 * 函数名: ExecuteLogin
 * 功能: 执行登录验证流程
 * 传入值: 无
 * 返回值: int - 成功返回0，失败返回-1
 */
int ExecuteLogin() {
    char command[MAX_BUFFER_SIZE];
    int ret_code;
    
    printf("\n===========================================================\n");
    printf("Login.c - 登录验证模块\n");
    printf("===========================================================\n\n");
    
    printf("【步骤1】调用Python登录模块...\n");
    
    // 构建Python命令
    snprintf(command, sizeof(command), "python %s", PYTHON_SCRIPT);
    
    // 执行Python脚本
    ret_code = system(command);
    
    if (ret_code != 0) {
        printf("✗ Python脚本执行失败，错误码: %d\n", ret_code);
        return -1;
    }
    
    printf("✓ Python脚本执行成功\n\n");
    
    return 0;
}

/*
 * 函数名: ReadLoginResult
 * 功能: 读取登录结果
 * 传入值: 无
 * 返回值: int - 成功返回0，失败返回-1
 */
int ReadLoginResult() {
    FILE *file;
    char buffer[MAX_BUFFER_SIZE];
    int ret_success = 0;
    
    printf("【步骤2】读取登录结果...\n");
    
    // 打开结果文件
    file = fopen(RESULT_FILE, "r");
    if (file == NULL) {
        printf("✗ 无法打开结果文件: %s\n", RESULT_FILE);
        return -1;
    }
    
    // 读取并打印结果
    printf("\n登录结果内容:\n");
    printf("-----------------------------------------------------------\n");
    
    while (fgets(buffer, sizeof(buffer), file) != NULL) {
        printf("%s", buffer);
        
        // 检查是否登录成功
        if (strstr(buffer, "ret_OK") != NULL) {
            ret_success = 1;
        }
    }
    
    printf("-----------------------------------------------------------\n\n");
    
    fclose(file);
    
    if (ret_success) {
        printf("✓ 登录成功\n");
        return 0;
    } else {
        printf("✗ 登录失败\n");
        return -1;
    }
}

/*
 * 函数名: ValidateUserLogin
 * 功能: 完整的用户登录验证流程
 * 传入值: 无
 * 返回值: int - 成功返回0，失败返回-1
 * 
 * 功能说明:
 * 1. 读取share.txt中的用户名、密码等数据
 * 2. 调用algorithm.py中的MD5算法对密码进行校验
 * 3. 读取DATA.xlsx中的数据进行比较
 * 4. 若密码、用户名正确，返回成功登录信息
 * 5. 若成功登录，在DATA.xlsx中写入最新登录时间和IP
 */
int ValidateUserLogin() {
    int ret_code;
    
    printf("\n===========================================================\n");
    printf("开始执行登录验证\n");
    printf("===========================================================\n");
    
    // 执行登录验证
    ret_code = ExecuteLogin();
    if (ret_code != 0) {
        printf("\n登录验证失败\n");
        return -1;
    }
    
    // 读取登录结果
    ret_code = ReadLoginResult();
    
    printf("\n===========================================================\n");
    printf("登录验证流程完成\n");
    printf("===========================================================\n\n");
    
    return ret_code;
}

/*
 * 函数名: PrintUsage
 * 功能: 打印使用说明
 * 传入值: 无
 * 返回值: NULL
 */
void PrintUsage() {
    printf("\n用户登录验证模块 v1.0\n");
    printf("===================================\n");
    printf("功能说明:\n");
    printf("1. 从share.txt读取用户登录数据\n");
    printf("2. 调用MD5算法验证密码\n");
    printf("3. 从DATA.xlsx读取用户数据进行比较\n");
    printf("4. 验证成功后更新登录时间和IP\n");
    printf("===================================\n\n");
}

/*
 * 函数名: main
 * 功能: 主函数
 * 传入值: 无
 * 返回值: int - 程序退出码
 */
int main() {
    int result;
    
    // 打印使用说明
    PrintUsage();
    
    // 执行登录验证
    result = ValidateUserLogin();
    
    // 根据结果返回退出码
    if (result == 0) {
        printf("程序执行成功\n");
        return 0;
    } else {
        printf("程序执行失败\n");
        return 1;
    }
}
