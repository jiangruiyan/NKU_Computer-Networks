#define _WIN32_WINNT 0x501
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <process.h>

#pragma comment(lib, "Ws2_32.lib")

#define BUFFER_SIZE 1024
#define MAX_NAME_LEN 32

SOCKET sock;
char username[MAX_NAME_LEN];
int connected = 1;

void trim_newline(char* str) {
    int len = strlen(str);
    if (len > 0 && str[len - 1] == '\n') {
        str[len - 1] = '\0';
    }
    if (len > 1 && str[len - 2] == '\r') {
        str[len - 2] = '\0';
    }
}

// 接收并显示来自聊天室的消息
unsigned __stdcall receive_messages(void* arg) {
    char buffer[BUFFER_SIZE];
    int recv_len;

    while (connected) {
        recv_len = recv(sock, buffer, BUFFER_SIZE - 1, 0);

        if (recv_len == SOCKET_ERROR) {
            int error = WSAGetLastError();
            if (error != WSAEWOULDBLOCK) { // 真正的错误，断开处理
                printf("\n与服务器断开连接，错误代码: %d\n", error);
                connected = 0;
                break;
            }
            // 非阻塞情况下无数据，稍后重试
            Sleep(100); // 避免忙等待
            continue;
        }

        if (recv_len == 0) {
            printf("\n服务器主动断开连接\n");
            connected = 0;
            break;
        }

        buffer[recv_len] = '\0';

        // 解析协议消息
        char* type = strtok(buffer, ":");
        char* sender = strtok(NULL, ":");
        char* length_str = strtok(NULL, ":");
        char* content = strtok(NULL, "");

        if (type && sender) {
            if (strcmp(type, "JOIN") == 0) {
                printf("\n>>> 系统: 用户 [%s] 加入了聊天室\n", sender);
            }
            else if (strcmp(type, "LEAVE") == 0) {
                printf("\n>>> 系统: 用户 [%s] 离开了聊天室\n", sender);
            }
            else if (strcmp(type, "MSG") == 0) {
                if (strcmp(sender, "系统") == 0) {
                    printf("\n>>> %s\n", content);
                }
                else {
                    printf("\n[%s]: %s\n", sender, content);
                }
            }
        }
        else {
            printf("\n>>> 收到无法解析的消息: %s\n", buffer);
        }

        printf("[%s]: ", username);
        fflush(stdout);
    }

    return 0;
}

int main(int argc, char* argv[]) {
    printf("南开大学《计算机网络》课程第1次实验作业\n");
    printf("——利用流式套接字编写聊天程序\n");
    printf("——蒋枘言  2313546\n");
    printf("这里是客户端client\n\n");

    if (argc != 3) {
        printf("请使用命令执行程序（不要直接点开）！\n");
        printf("命令格式: %s <服务器IP> <端口>\n", argv[0]);
        printf("例如: %s 127.0.0.1 8080\n", argv[0]);
        system("pause");
        return 1;
    }

    char* server_ip = argv[1];
    int port = atoi(argv[2]);
    struct sockaddr_in server_addr;
    char buffer[BUFFER_SIZE];
    WSADATA wsaData;
    int iResult;
    u_long mode = 1; // 非阻塞模式

    // 初始化Winsock
    iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0) {
        printf("WSAStartup失败: %d\n", iResult);
        return 1;
    }

    // 获取用户名（添加输入长度检查：不超过 MAX_NAME_LEN - 2 字节，并清理超长输入残留）
	// 减2是因为要留一个字节给换行符\n，一个给字符串结束符\0
    while (1) {
        printf("请输入你的用户名（最多%d字节）: ", MAX_NAME_LEN - 2);
        if (fgets(username, MAX_NAME_LEN, stdin) == NULL) {
            printf("读取用户名失败\n");
            WSACleanup();
            return 1;
        }

        size_t len = strlen(username);

        // 如果最后一个字符是换行则去掉
        if (len > 0 && username[len - 1] == '\n') {
            trim_newline(username);
            if (strlen(username) == 0) {
                printf("用户名不能为空，请重新输入。\n");
                continue;
            }
            break; // 合法输入
        }
        else {
            // 未读到换行，说明输入超出缓冲区（或输入恰好填满缓冲区）
            int ch;
            while ((ch = getchar()) != '\n' && ch != EOF) { } // 清理stdin中剩余的字符直到遇到换行或EOF（重要，不能删除这段代码！）

            printf("用户名不能超过 %d 字节，请重新输入。\n", MAX_NAME_LEN - 1);
            continue;
        }
    }

    if (strlen(username) == 0) {
        // （冗余）应该不会到这里，因为上面已检查
        printf("用户名不能为空\n");
        WSACleanup();
        return 1;
    }

    // 创建socket
    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        printf("Socket创建失败: %ld\n", WSAGetLastError());
        WSACleanup();
        return 1;
    }

    // 设置非阻塞模式
    ioctlsocket(sock, FIONBIO, &mode);

    // 连接服务器
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    inet_pton(AF_INET, server_ip, &server_addr.sin_addr);

    printf("正在连接服务器 %s:%d ...\n", server_ip, port);

    iResult = connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr));
    if (iResult == SOCKET_ERROR) {
        int error = WSAGetLastError();
        if (error != WSAEWOULDBLOCK) {
            printf("连接服务器失败: %d\n", error);
            closesocket(sock);
            WSACleanup();
            return 1;
        }

        // 等待连接完成
        fd_set writefds;
        FD_ZERO(&writefds);
        FD_SET(sock, &writefds);

        struct timeval timeout;
        timeout.tv_sec = 5;
        timeout.tv_usec = 0;

        iResult = select(0, NULL, &writefds, NULL, &timeout);
        if (iResult <= 0) {
            printf("连接超时或失败\n");
            closesocket(sock);
            WSACleanup();
            return 1;
        }
    }

    // 发送用户名
    if (send(sock, username, strlen(username), 0) == SOCKET_ERROR) {
        printf("发送用户名失败\n");
        closesocket(sock);
        WSACleanup();
        return 1;
    }

    printf("连接到聊天服务器成功!\n");
    printf("输入 'exit' 退出聊天室\n");
    printf("输入消息后按回车发送\n");
    for (int i = 0; i < 50; i++) printf("=");
    printf("\n");

    // 创建接收消息线程
    HANDLE recv_thread = (HANDLE)_beginthreadex(NULL, 0, receive_messages, NULL, 0, NULL);
    if (recv_thread == NULL) {
        printf("接收线程创建失败\n");
        closesocket(sock);
        WSACleanup();
        return 1;
    }

    // 主线程处理用户输入
    while (connected) {
        printf("[%s]: ", username);
        fflush(stdout);

        if (fgets(buffer, BUFFER_SIZE, stdin) == NULL) {
            break;
        }

        trim_newline(buffer);

        if (strcmp(buffer, "exit") == 0) {
            printf("退出聊天室...\n");
            break;
        }

        if (strlen(buffer) > 0) {
            if (send(sock, buffer, strlen(buffer), 0) == SOCKET_ERROR) {
                printf("发送消息失败\n");
                break;
            }
        }
    }

    connected = 0;
    closesocket(sock);
    WaitForSingleObject(recv_thread, 1000);
    CloseHandle(recv_thread);

    WSACleanup();
    printf("已退出聊天室\n");

    return 0;
}