#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _WIN32_WINNT 0x501
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <process.h>

#pragma comment(lib, "ws2_32.lib")

#define MAX_CLIENTS 100
#define BUFFER_SIZE 1024
#define MAX_NAME_LEN 32

typedef struct {
    SOCKET socket;
    char name[MAX_NAME_LEN];
    struct sockaddr_in address;
} client_t; // 客户端结构体

client_t* clients[MAX_CLIENTS];
HANDLE clients_mutex; // 客户端列表互斥锁
int client_count = 0;

// 去除字符串末尾的换行符和回车符
void trim_newline(char* str) {
    int len = strlen(str);
    if (len > 0 && str[len - 1] == '\n') {
        str[len - 1] = '\0';
    }
    if (len > 1 && str[len - 2] == '\r') {
        str[len - 2] = '\0';
    }
}

// 将消息广播给所有连接的客户端（除了发送者自己）
void broadcast_message(char* message, SOCKET sender_sock) {
    WaitForSingleObject(clients_mutex, INFINITE);

    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i] && clients[i]->socket != sender_sock) {
            if (send(clients[i]->socket, message, strlen(message), 0) == SOCKET_ERROR) {
                printf("发送失败到客户端 %s\n", clients[i]->name);
            }
        }
    }

    ReleaseMutex(clients_mutex);
}

// 添加客户端
void add_client(client_t* client) {
    WaitForSingleObject(clients_mutex, INFINITE);

    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (!clients[i]) {
            clients[i] = client;
            break;
        }
    }
    client_count++;

    ReleaseMutex(clients_mutex);
}

// 移除客户端
void remove_client(SOCKET sock) {
    WaitForSingleObject(clients_mutex, INFINITE);

    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i] && clients[i]->socket == sock) {
            free(clients[i]);
            clients[i] = NULL;
            break;
        }
    }
    client_count--;

    ReleaseMutex(clients_mutex);
}

// 处理客户端连接
unsigned __stdcall handle_client(void* arg) {
    client_t* client = (client_t*)arg;
	char buffer[BUFFER_SIZE];
	char message[BUFFER_SIZE + 100];
    int recv_len;
    int error = 0;

    // 接收用户名
    int name_len = recv(client->socket, buffer, MAX_NAME_LEN - 1, 0);
    if (name_len <= 0) {
        printf("接收用户名失败或客户端断开\n");
        closesocket(client->socket);
        remove_client(client->socket);
        //free(client);
        return 1;
    }
    buffer[name_len] = '\0';
    trim_newline(buffer);
    strcpy_s(client->name, MAX_NAME_LEN, buffer);

    // 广播用户加入消息
    sprintf_s(message, BUFFER_SIZE + 100, "JOIN:%s:0000:", client->name);
    printf("用户 %s 加入了聊天室\n", client->name);
    broadcast_message(message, client->socket);

    // 发送欢迎消息给新用户
    char welcome_msg[BUFFER_SIZE];
	int msg_len = 18 + strlen(client->name);
    sprintf_s(welcome_msg, BUFFER_SIZE, "MSG:系统:%04d:欢迎 %s 加入聊天室！", msg_len, client->name);
    send(client->socket, welcome_msg, strlen(welcome_msg), 0);

	// 接收客户端消息并广播
    while (1) {
        recv_len = recv(client->socket, buffer, BUFFER_SIZE - 1, 0);

        if (recv_len == SOCKET_ERROR) {
            int error_code = WSAGetLastError();
            if (error_code != WSAEWOULDBLOCK) {
                printf("接收错误: %d\n", error_code);
                error = 1;
            }
            break;
        }

        if (recv_len == 0) {
            printf("客户端 %s 主动断开连接\n", client->name);
            break;
        }

        buffer[recv_len] = '\0';
        trim_newline(buffer);

        if (strcmp(buffer, "exit") == 0) {
            printf("用户 %s 请求退出\n", client->name);
            break;
        }

        if (strlen(buffer) == 0) {
            continue;
        }

        // 格式化消息：MSG:用户名:内容长度:内容
        sprintf_s(message, BUFFER_SIZE + 100, "MSG:%s:%04d:%s", client->name, (int)strlen(buffer), buffer);
        printf("转发消息 [%s]: %s\n", client->name, buffer);
        broadcast_message(message, client->socket);
    }

    // 用户离开
    sprintf_s(message, BUFFER_SIZE + 100, "LEAVE:%s:0000:", client->name);
    printf("用户 %s 离开了聊天室\n", client->name);
    broadcast_message(message, client->socket);

    closesocket(client->socket);
    remove_client(client->socket);
    //free(client); // remove_client里已包含free，不能重复释放

    return 0;
}

int main(int argc, char* argv[]) {
    printf("南开大学《计算机网络》课程第1次实验作业\n");
    printf("——利用流式套接字编写聊天程序\n");
    printf("——蒋枘言  2313546\n");
    printf("这里是服务端server\n\n");

    if (argc != 2) {
        printf("请使用命令执行程序（不要直接点开）！\n");
        printf("命令格式: <程序路径> <端口>\n");
        printf("例如: %s 8080\n", argv[0]);
        system("pause");
        return 1;
    }

    int port = atoi(argv[1]);
    if (!(port >= 0 && port <= 65536)) {
		printf("端口号无效，请输入0-65536之间的整数！\n");
    }
    SOCKET server_socket, client_socket;
    struct sockaddr_in server_addr, client_addr;
    int client_len = sizeof(client_addr);
    WSADATA wsaData;
	int iResult; // 存储函数调用的返回值，以检查操作是否成功

    // 初始化Winsock
    iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0) {
        printf("WSAStartup失败: %d\n", iResult);
        return 1;
    }

    // 创建互斥锁
    clients_mutex = CreateMutex(NULL, FALSE, NULL);
    if (clients_mutex == NULL) {
        printf("创建互斥锁失败\n");
        WSACleanup();
        return 1;
    }

    // 创建socket
    server_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (server_socket == INVALID_SOCKET) {
        printf("Socket创建失败: %ld\n", WSAGetLastError());
        WSACleanup();
        return 1;
    }

    // 设置socket选项，避免地址占用错误
    int opt = 1;
    setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt));

    // 绑定地址
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);

	// 绑定socket
    if (bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        printf("绑定失败: %d\n", WSAGetLastError());
        closesocket(server_socket);
        WSACleanup();
        return 1;
    }

    // 开始监听
    if (listen(server_socket, SOMAXCONN) == SOCKET_ERROR) {
        printf("监听失败: %d\n", WSAGetLastError());
        closesocket(server_socket);
        WSACleanup();
        return 1;
    }

    printf("聊天服务器启动在端口 %d\n", port);
    // 初始化客户端数组
    for (int i = 0; i < MAX_CLIENTS; i++) {
        clients[i] = NULL;
    }
    printf("等待客户端连接...\n");

	// 主循环，接受客户端连接
    while (1) {
        client_socket = accept(server_socket, (struct sockaddr*)&client_addr, &client_len);

        if (client_socket == INVALID_SOCKET) {
            printf("接受连接失败: %d\n", WSAGetLastError());
            continue;
        }

        // 创建新客户端
        client_t* client = (client_t*)malloc(sizeof(client_t));
        if (!client) {
            printf("内存分配失败\n");
            closesocket(client_socket);
            continue;
        }

        client->socket = client_socket;
        client->address = client_addr;
        strcpy_s(client->name, MAX_NAME_LEN, "Unknown");

        add_client(client);

        // 创建线程处理客户端
        HANDLE thread_handle = (HANDLE)_beginthreadex(NULL, 0, handle_client, (void*)client, 0, NULL);
        if (thread_handle == NULL) {
            printf("线程创建失败\n");
            closesocket(client_socket);
            //free(client);
            remove_client(client_socket);
        }
        else {
            CloseHandle(thread_handle);
        }

        printf("新客户端连接，IP: %s, 端口: %d, 当前用户数: %d\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port), client_count);
    }

    closesocket(server_socket);
    WSACleanup();
    CloseHandle(clients_mutex);
    return 0;
}