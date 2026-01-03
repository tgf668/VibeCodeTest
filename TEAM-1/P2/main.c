#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
    char command[256];
    FILE *fp;
    char buffer[1024];

    printf("=== System Start ===\n");

    // 1. 调用 web.py 进行通信
    printf("[Step 1] Waiting for user connection and data...\n");
    // 注意：ReceiveRemoteData 监听 8080，且验证 IP 为 192.114.514 (逻辑演示)
    // 为了演示方便，我们可能需要手动发送数据或者修改 web.py 的 IP 限制
    // 这里直接调用 python web.py receive
    // 这是一个阻塞调用，直到收到数据
    int ret = system("python web.py receive");
    
    if (ret != 0) {
        printf("Error: Failed to receive data from web module.\n");
        return 1;
    }
    printf("Data received successfully.\n");

    // 2. 调用 login.c 模块 (假设编译为 login.exe)
    // 如果没有编译，我们可以尝试直接编译它，或者假设它已经存在
    // 为了确保能运行，我们先尝试编译 login.c
    printf("[Step 2] Verifying user identity...\n");
    system("gcc login.c -o login.exe"); // 尝试编译
    
    // 运行 login.exe 并捕获输出
    fp = _popen("login.exe", "r");
    if (fp == NULL) {
        printf("Error: Failed to run login module.\n");
        return 1;
    }

    char result_output[1024] = "";
    while (fgets(buffer, sizeof(buffer), fp) != NULL) {
        printf("%s", buffer); // 打印 login.c 的输出
        strcat(result_output, buffer);
    }
    _pclose(fp);

    // 3. 清空 share.txt
    printf("[Step 3] Clearing share.txt...\n");
    fp = fopen("share.txt", "w");
    if (fp != NULL) {
        fclose(fp);
        printf("share.txt cleared.\n");
    } else {
        printf("Warning: Failed to clear share.txt\n");
    }

    // 4. 将得到的验证信息返回给用户
    // 这里我们将结果打印在控制台，作为返回给用户的反馈
    printf("[Step 4] Final Result:\n");
    printf("--------------------------------------------------\n");
    printf("%s", result_output);
    printf("--------------------------------------------------\n");

    printf("=== System End ===\n");
    
    // 暂停一下以便查看结果
    system("pause");

    return 0;
}
