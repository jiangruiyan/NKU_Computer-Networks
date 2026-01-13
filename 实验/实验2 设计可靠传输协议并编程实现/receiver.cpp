// ============================================================
// receiver.cpp  (不使用STL，单线程，Winsock2原生UDP)
// 可靠UDP接收端：连接管理 + 校验和 + 乱序缓存 + 累积ACK + SACK位图 + 固定窗口W
//
// 编译（MSVC）：cl /EHsc receiver.cpp ws2_32.lib
// 运行：receiver.exe <listen_port> <output_file> <W> [--loss=0.0]
//
// 示例：
//   receiver.exe 9000 recv.bin 32 --loss=0.05
// ============================================================

#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#pragma comment(lib, "Ws2_32.lib")

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static uint64_t now_ms() {
    return GetTickCount64();
}

static uint16_t ones_complement_checksum(const uint8_t* data, size_t len) {
    uint32_t sum = 0;
    size_t i = 0;
    while (i + 1 < len) {
        uint16_t word = (uint16_t(data[i]) << 8) | uint16_t(data[i + 1]);
        sum += word;
        if (sum & 0x10000) sum = (sum & 0xFFFF) + 1;
        i += 2;
    }
    if (i < len) {
        uint16_t word = uint16_t(data[i]) << 8;
        sum += word;
        if (sum & 0x10000) sum = (sum & 0xFFFF) + 1;
    }
    return (uint16_t)(~sum & 0xFFFF);
}

static uint64_t htonll_u64(uint64_t x) {
    uint32_t hi = htonl((uint32_t)(x >> 32));
    uint32_t lo = htonl((uint32_t)(x & 0xFFFFFFFFu));
    return ((uint64_t)lo << 32) | hi;
}
static uint64_t ntohll_u64(uint64_t x) {
    uint32_t hi = ntohl((uint32_t)(x >> 32));
    uint32_t lo = ntohl((uint32_t)(x & 0xFFFFFFFFu));
    return ((uint64_t)lo << 32) | hi;
}

// flags
enum {
    FLAG_SYN = 0x0001,
    FLAG_ACK = 0x0002,
    FLAG_FIN = 0x0004,
    FLAG_DATA = 0x0008,
    FLAG_RST = 0x0010
};

#pragma pack(push, 1)
typedef struct Header {
    uint32_t magic;
    uint16_t ver;
    uint16_t flags;
    uint32_t seq;
    uint32_t ack;
    uint16_t wnd;
    uint16_t len;
    uint64_t sack_mask;
    uint16_t checksum;
    uint16_t reserved;
} Header;
#pragma pack(pop)

static const uint32_t MAGIC = 0x52554450u; // 'RUDP'
static const uint16_t VER = 1;

static int build_packet(uint8_t* outbuf, int outcap,
    uint16_t flags, uint32_t seq, uint32_t ack,
    uint16_t wnd, uint64_t sack_mask,
    const uint8_t* payload, uint16_t len) {
    if (outcap < (int)sizeof(Header) + (int)len) return -1;

    Header h;
    h.magic = htonl(MAGIC);
    h.ver = htons(VER);
    h.flags = htons(flags);
    h.seq = htonl(seq);
    h.ack = htonl(ack);
    h.wnd = htons(wnd);
    h.len = htons(len);
    h.sack_mask = htonll_u64(sack_mask);
    h.checksum = 0;
    h.reserved = 0;

    memcpy(outbuf, &h, sizeof(Header));
    if (len > 0 && payload) {
        memcpy(outbuf + sizeof(Header), payload, len);
    }

    uint16_t cksum = ones_complement_checksum(outbuf, sizeof(Header) + len);
    uint16_t cksum_n = htons(cksum);
    memcpy(outbuf + offsetof(Header, checksum), &cksum_n, sizeof(uint16_t));

    return (int)(sizeof(Header) + len);
}

static int parse_packet(const uint8_t* buf, int n, Header* out_h,
    const uint8_t** out_payload, uint16_t* out_len) {
    if (n < (int)sizeof(Header)) return 0;

    Header h;
    memcpy(&h, buf, sizeof(Header));

    uint32_t magic = ntohl(h.magic);
    uint16_t ver = ntohs(h.ver);
    if (magic != MAGIC || ver != VER) return 0;

    uint16_t recv_ck = ntohs(h.checksum);

    uint8_t* tmp = (uint8_t*)malloc(n);
    if (!tmp) return 0;
    memcpy(tmp, buf, n);
    uint16_t zero = 0;
    memcpy(tmp + offsetof(Header, checksum), &zero, sizeof(uint16_t));
    uint16_t calc = ones_complement_checksum(tmp, n);
    free(tmp);

    if (calc != recv_ck) return 0;

    uint16_t len = ntohs(h.len);
    if ((int)sizeof(Header) + (int)len > n) return 0;

    *out_h = h;
    *out_payload = buf + sizeof(Header);
    *out_len = len;
    return 1;
}

static void set_nonblocking(SOCKET s) {
    u_long nb = 1;
    ioctlsocket(s, FIONBIO, &nb);
}

static int wait_readable(SOCKET s, int timeout_ms) {
    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(s, &rfds);
    timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    int r = select(0, &rfds, NULL, NULL, &tv);
    return (r > 0 && FD_ISSET(s, &rfds)) ? 1 : 0;
}

// 丢包模拟
static int should_drop(double lossP) {
    if (lossP <= 0.0) return 0;
    double x = (double)rand() / (double)RAND_MAX;
    return (x < lossP) ? 1 : 0;
}

static int get_arg_value(const char* arg, const char* key, char* out, int outcap) {
    size_t klen = strlen(key);
    if (strncmp(arg, key, klen) == 0) {
        strncpy(out, arg + klen, outcap - 1);
        out[outcap - 1] = '\0';
        return 1;
    }
    return 0;
}

// ---------------- 接收端乱序缓存 ----------------
// 由于窗口固定为W，接收端最多缓存W-1个乱序段（在rcv_nxt之后）
// 这里用一个数组做“槽位表”：每个槽位保存一个段的数据。
typedef struct RecvSlot {
    int used;
    uint32_t seq;
    uint16_t len;
    uint8_t* data;
} RecvSlot;

// 查找某段是否已缓存
static RecvSlot* slot_find(RecvSlot* slots, int cap, uint32_t seq) {
    for (int i = 0; i < cap; ++i) {
        if (slots[i].used && slots[i].seq == seq) return &slots[i];
    }
    return NULL;
}

// 找空槽位
static RecvSlot* slot_alloc(RecvSlot* slots, int cap) {
    for (int i = 0; i < cap; ++i) {
        if (!slots[i].used) return &slots[i];
    }
    return NULL;
}

// 释放槽位
static void slot_free(RecvSlot* s) {
    if (!s) return;
    if (s->data) { free(s->data); s->data = NULL; }
    s->used = 0;
    s->seq = 0;
    s->len = 0;
}

static void usage() {
    printf("Usage:\n");
    printf("  receiver.exe <listen_port> <output_file> <W> [--loss=0.0] [--delay=0.0]\n");
}

int main(int argc, char** argv) {
    if (argc < 4) {
        usage();
        return 1;
    }

    int port = atoi(argv[1]);
    const char* outFile = argv[2];
    int W = atoi(argv[3]);

    int send_delay_ms = 0;

    double lossP = 0.0;
    for (int i = 4; i < argc; ++i) {
        char val[64];
        if (get_arg_value(argv[i], "--loss=", val, sizeof(val))) {
            lossP = atof(val);
        }
        else if (get_arg_value(argv[i], "--delay=", val, sizeof(val))) {
            send_delay_ms = atoi(val);
        }
    }
    if (W <= 0) { printf("错误：W必须>0\n"); return 1; }
    if (lossP < 0.0) lossP = 0.0;
    if (lossP > 1.0) lossP = 1.0;
    if (send_delay_ms < 0) send_delay_ms = 0;

    if (W > 64) {
        printf("[警告] W>64：SACK位图只能覆盖ack之后前64段，建议W<=64。\n");
    }

    srand((unsigned int)GetTickCount());

    FILE* fp = fopen(outFile, "wb");
    if (!fp) {
        printf("无法打开输出文件：%s\n", outFile);
        return 1;
    }

    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        printf("WSAStartup失败\n");
        fclose(fp);
        return 1;
    }

    SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == INVALID_SOCKET) {
        printf("socket创建失败\n");
        WSACleanup();
        fclose(fp);
        return 1;
    }
    set_nonblocking(sock);

    sockaddr_in local;
    memset(&local, 0, sizeof(local));
    local.sin_family = AF_INET;
    local.sin_port = htons((uint16_t)port);
    local.sin_addr.s_addr = INADDR_ANY;

    if (bind(sock, (sockaddr*)&local, sizeof(local)) != 0) {
        printf("bind失败\n");
        closesocket(sock);
        WSACleanup();
        fclose(fp);
        return 1;
    }

    printf("接收端监听端口：%d\n", port);

    // peer记录：用于回包（ACK/FIN等）
    sockaddr_in peer;
    memset(&peer, 0, sizeof(peer));
	int hasPeer = 0; // 是否已记录peer

    // 发送缓冲
    uint8_t sbuf[2048];
    // 接收缓冲
    uint8_t rbuf[2048];

    auto send_pkt = [&](uint16_t flags, uint32_t seq, uint32_t ack, uint64_t sack_mask,
        const uint8_t* payload, uint16_t len) -> void {
            int plen = build_packet(sbuf, (int)sizeof(sbuf), flags, seq, ack, (uint16_t)W, sack_mask, payload, len);
            if (plen < 0) return;

            if (should_drop(lossP)) {
                // 丢包模拟：不发
                return;
            }
            if (!hasPeer) return;

            if (send_delay_ms > 0) {
                Sleep(send_delay_ms);
            }
            sendto(sock, (const char*)sbuf, plen, 0, (sockaddr*)&peer, sizeof(peer));
        };

    // 连接状态机
    enum { ST_LISTEN, ST_SYN_RCVD, ST_ESTABLISHED, ST_CLOSE_WAIT } st = ST_LISTEN;

    // 握手重传计时
    uint64_t hs_deadline = 0;
    int hs_retries = 0;

    // 接收端按序交付：rcv_nxt为“期望收到的下一个段号”
    uint32_t rcv_nxt = 1;

    // 乱序缓存容量：建议至少W
    int SLOT_CAP = (W > 0) ? (W + 4) : 32;
    if (SLOT_CAP < 32) SLOT_CAP = 32;
    RecvSlot* slots = (RecvSlot*)calloc(SLOT_CAP, sizeof(RecvSlot));
    if (!slots) {
        printf("内存分配失败\n");
        closesocket(sock);
        WSACleanup();
        fclose(fp);
        return 1;
    }

    // 计算SACK位图：bit i=1 表示 (rcv_nxt+i) 已缓存（乱序到达）
    auto build_sack_mask = [&]() -> uint64_t {
        uint64_t mask = 0ULL;
        int limit = W;
        if (limit > 64) limit = 64;
        for (int i = 0; i < limit; ++i) {
            uint32_t s = rcv_nxt + (uint32_t)i;
            if (slot_find(slots, SLOT_CAP, s)) {
                mask |= (1ULL << i);
            }
        }
        return mask;
    };

    // 发送ACK（携带SACK）
    auto send_ack = [&]() -> void {
        uint64_t sack = build_sack_mask();
        send_pkt(FLAG_ACK, 0, rcv_nxt, sack, NULL, 0);
    };

    // 发送SYN|ACK（握手第二步）
    auto send_synack = [&]() -> void {
        send_pkt((uint16_t)(FLAG_SYN | FLAG_ACK), 0, 1, 0ULL, NULL, 0);
    };

    // 挥手：收到对端FIN后，本端发FIN的序号
    uint32_t myFinSeq = 0;
    uint64_t fin_deadline = 0;
    int fin_retries = 0;
    int wait_fin_ack = 0;

    printf("等待连接（握手）...\n");

    while (1) {
        // 定时器事件（握手重传 / FIN重传）
        uint64_t now = now_ms();
        if (st == ST_SYN_RCVD && now >= hs_deadline) {
            if (hs_retries >= 50) {
                printf("握手超时：重试次数过多\n");
                break;
            }
            send_synack();
            hs_deadline = now + 300;
            hs_retries++;
        }
        if (wait_fin_ack && now >= fin_deadline) {
            if (fin_retries >= 50) {
                printf("挥手超时：FIN重试次数过多\n");
                break;
            }
            // 重发自己的FIN
            send_pkt(FLAG_FIN, myFinSeq, 0, 0ULL, NULL, 0);
            fin_deadline = now + 300;
            fin_retries++;
        }

        // 等待可读
        if (!wait_readable(sock, 100)) {
            continue;
        }

        sockaddr_in from;
        int fromlen = sizeof(from);
        int n = recvfrom(sock, (char*)rbuf, (int)sizeof(rbuf), 0, (sockaddr*)&from, &fromlen);
        if (n <= 0) continue;

        Header h;
        const uint8_t* payload = NULL;
        uint16_t len = 0;

        // 校验和失败的包直接丢弃（差错检测）
        if (!parse_packet(rbuf, n, &h, &payload, &len)) {
            continue;
        }

        uint16_t flags = ntohs(h.flags);
        uint32_t seq = ntohl(h.seq);
        uint32_t ack = ntohl(h.ack);

        // 第一次收到对端包时记录peer，用于回包
        if (!hasPeer) {
            peer = from;
            hasPeer = 1;
        }

        // -------- 连接管理：握手 --------
        if (st == ST_LISTEN) {
            if (flags & FLAG_SYN) {
                // 收到SYN，回SYN|ACK
                st = ST_SYN_RCVD;
                hs_retries = 0;
                send_synack();
                hs_deadline = now_ms() + 300;
            }
            continue;
        }

        if (st == ST_SYN_RCVD) {
            // 等待对端ACK（第三次握手）
            if ((flags & FLAG_ACK) && ack == 1) {
                st = ST_ESTABLISHED;
                printf("连接建立成功。\n");
                // 告知当前期望段号
                send_ack();
            }
            continue;
        }

        // -------- 已建立连接：数据接收/挥手 --------
        if (st == ST_ESTABLISHED) {
            if (flags & FLAG_DATA) {
                // 固定窗口流控：只接收[rcv_nxt, rcv_nxt+W-1]范围内的段
                if (seq < rcv_nxt) {
                    // 旧包（已经交付过），直接回ACK（帮助发送端收敛）
                    send_ack();
                    continue;
                }
                if (seq >= rcv_nxt + (uint32_t)W) {
                    // 超出接收窗口，丢弃并回ACK（让发送端知道窗口边界）
                    send_ack();
                    continue;
                }

                if (seq == rcv_nxt) {
                    // 按序到达：直接写文件
                    if (len > 0) {
                        fwrite(payload, 1, len, fp);
                    }
                    rcv_nxt++;

                    // 尝试把乱序缓存中连续的段按序交付
                    while (1) {
                        RecvSlot* s = slot_find(slots, SLOT_CAP, rcv_nxt);
                        if (!s) break;
                        if (s->len > 0 && s->data) {
                            fwrite(s->data, 1, s->len, fp);
                        }
                        slot_free(s);
                        rcv_nxt++;
                    }
                }
                else {
                    // 乱序到达：缓存（若未缓存过）
                    if (!slot_find(slots, SLOT_CAP, seq)) {
                        RecvSlot* slot = slot_alloc(slots, SLOT_CAP);
                        if (slot) {
                            uint8_t* buf2 = NULL;
                            if (len > 0) {
                                buf2 = (uint8_t*)malloc(len);
                                if (buf2) memcpy(buf2, payload, len);
                            }
                            slot->used = 1;
                            slot->seq = seq;
                            slot->len = len;
                            slot->data = buf2;
                        }
                        // 如果缓存满了，直接丢弃（仍然回ACK+SACK，让发送端决定重传）
                    }
                }

                // 回ACK + SACK位图（选择确认）
                send_ack();
                continue;
            }

            if (flags & FLAG_FIN) {
                // 收到发送端FIN：先ACK它的FIN，再发送自己的FIN
                uint32_t peerFinSeq = seq;

                // ACK对端FIN：ack=peerFinSeq+1
                send_pkt(FLAG_ACK, 0, peerFinSeq + 1, 0ULL, NULL, 0);

                // 发送自己的FIN（四次挥手）
                myFinSeq = peerFinSeq + 1;
                send_pkt(FLAG_FIN, myFinSeq, 0, 0ULL, NULL, 0);

                // 进入等待FIN ACK状态
                st = ST_CLOSE_WAIT;
                wait_fin_ack = 1;
                fin_retries = 0;
                fin_deadline = now_ms() + 300;

                printf("收到FIN，开始关闭连接...\n");
                continue;
            }

            // 其它控制包忽略
            continue;
        }

        if (st == ST_CLOSE_WAIT) {
            // 等待对端ACK确认我们的FIN
            if ((flags & FLAG_ACK) && ack >= myFinSeq + 1) {
                printf("连接关闭完成。\n");
                break;
            }
            continue;
        }
    }

    // 清理资源
    fflush(fp);
    fclose(fp);

    if (slots) {
        for (int i = 0; i < SLOT_CAP; ++i) {
            if (slots[i].used) slot_free(&slots[i]);
        }
        free(slots);
        slots = NULL;
    }

    closesocket(sock);
    WSACleanup();
    return 0;
}
