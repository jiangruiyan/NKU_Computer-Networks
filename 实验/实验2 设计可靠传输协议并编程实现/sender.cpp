// ============================================================
// sender.cpp  (不使用STL，单线程，Winsock2原生UDP)
// 可靠UDP发送端：连接管理 + 校验和 + 流水线 + SACK选择确认 + 固定窗口流控 + Reno拥塞控制
//
// 编译（MSVC）：cl /EHsc sender.cpp ws2_32.lib
// 运行：sender.exe <receiver_ip> <port> <input_file> <W> [--mss=1000] [--rto=300] [--loss=0.0]
//
// 示例：
//   sender.exe 127.0.0.1 9000 test.bin 32 --mss=1000 --rto=300 --loss=0.05
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

// 16-bit Internet checksum（ones' complement）
// 以16位为单位累加，最后取反。
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

// ---------------- 协议字段与报文格式 ----------------
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
    uint32_t magic;      // 'RUDP'
    uint16_t ver;        // 1
    uint16_t flags;      // SYN/ACK/FIN/DATA...
    uint32_t seq;        // 数据段号：1..N（控制包可用0或其它）
    uint32_t ack;        // 累积确认：接收端期望的下一个段号（rcv_nxt）
    uint16_t wnd;        // 接收窗口（段数），本实验固定=W
    uint16_t len;        // payload长度
    uint64_t sack_mask;  // SACK位图：bit i=1 表示(ack+i)这个段已收到（乱序缓冲中）
    uint16_t checksum;   // 校验和（对header+payload）
    uint16_t reserved;   // 0
} Header;
#pragma pack(pop)

static const uint32_t MAGIC = 0x52554450u; // 'RUDP'
static const uint16_t VER = 1;

// 构造一个数据包到 outbuf（返回总长度）
// 注意：checksum字段先填0，再计算后写入。
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

    // 计算校验和：checksum字段为0
    uint16_t cksum = ones_complement_checksum(outbuf, sizeof(Header) + len);
    uint16_t cksum_n = htons(cksum);
    memcpy(outbuf + offsetof(Header, checksum), &cksum_n, sizeof(uint16_t));

    return (int)(sizeof(Header) + len);
}

// 解析并校验一个包：成功返回1，失败返回0
static int parse_packet(const uint8_t* buf, int n, Header* out_h,
    const uint8_t** out_payload, uint16_t* out_len) {
    if (n < (int)sizeof(Header)) return 0;

    Header h;
    memcpy(&h, buf, sizeof(Header));

    uint32_t magic = ntohl(h.magic);
    uint16_t ver = ntohs(h.ver);
    if (magic != MAGIC || ver != VER) return 0;

    uint16_t recv_ck = ntohs(h.checksum);

    // 校验时把checksum字段置0再算
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

// 非阻塞
static void set_nonblocking(SOCKET s) {
    u_long nb = 1;
    ioctlsocket(s, FIONBIO, &nb);
}

// select等待可读
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

// 简单丢包模拟：概率lossP丢弃（不发送/不处理）
static int should_drop(double lossP) {
    if (lossP <= 0.0) return 0;
    double x = (double)rand() / (double)RAND_MAX;
    return (x < lossP) ? 1 : 0;
}

// 命令行参数解析：寻找 --key=value
static int get_arg_value(const char* arg, const char* key, char* out, int outcap) {
    // key形如 "--mss="
    size_t klen = strlen(key);
    if (strncmp(arg, key, klen) == 0) {
        strncpy(out, arg + klen, outcap - 1);
        out[outcap - 1] = '\0';
        return 1;
    }
    return 0;
}

// ---------------- 发送端：窗口与在途段缓存 ----------------
typedef struct InFlightSeg {
    uint32_t seq;        // 段号
    int used;            // 该槽位是否在用
    int acked;           // 是否已确认
    uint16_t len;        // 数据长度
    uint8_t* data;       // 数据指针（用于重传）
    uint64_t sent_time;  // 最近一次发送时间（ms）
    int tx_count;        // 发送次数
} InFlightSeg;

// 在inflight数组中查找某段
static InFlightSeg* inflight_find(InFlightSeg* arr, int cap, uint32_t seq) {
    for (int i = 0; i < cap; ++i) {
        if (arr[i].used && arr[i].seq == seq) return &arr[i];
    }
    return NULL;
}

// 找一个空槽位
static InFlightSeg* inflight_alloc(InFlightSeg* arr, int cap) {
    for (int i = 0; i < cap; ++i) {
        if (!arr[i].used) return &arr[i];
    }
    return NULL;
}

// 释放一个段槽位（释放data）
static void inflight_free_slot(InFlightSeg* s) {
    if (!s) return;
    if (s->data) {
        free(s->data);
        s->data = NULL;
    }
    s->used = 0;
    s->acked = 0;
    s->seq = 0;
    s->len = 0;
    s->sent_time = 0;
    s->tx_count = 0;
}

// 从文件读取指定段（seq从1开始），把数据存入槽位（用于后续重传）
static int load_segment_from_file(FILE* fp, long file_size, int MSS, uint32_t seq, InFlightSeg* slot) {
    long offset = (long)((seq - 1) * (uint32_t)MSS);
    if (offset >= file_size) return 0;

    long remain = file_size - offset;
    uint16_t len = (uint16_t)((remain >= MSS) ? MSS : remain);

    uint8_t* buf = (uint8_t*)malloc(len);
    if (!buf) return 0;

    if (fseek(fp, offset, SEEK_SET) != 0) {
        free(buf);
        return 0;
    }
    size_t n = fread(buf, 1, len, fp);
    if (n != len) {
        free(buf);
        return 0;
    }

    slot->data = buf;
    slot->len = len;
    return 1;
}

static void usage() {
    printf("Usage:\n");
    printf("  sender.exe <receiver_ip> <port> <input_file> <W> [--mss=1000] [--rto=300] [--loss=0.0] [--delay=0.0]\n");
}

int main(int argc, char** argv) {
    if (argc < 5) {
        usage();
        return 1;
    }

    const char* ip = argv[1];
    int port = atoi(argv[2]);
    const char* filename = argv[3];
    int W = atoi(argv[4]);

    int send_delay_ms = 0;   // 发送延时，单位毫秒，默认0

    int MSS = 1000;        // 每段最大payload
    int RTO = 300;         // 超时重传(ms)
    double lossP = 0.0;    // 丢包率模拟

    // 解析可选参数
    for (int i = 5; i < argc; ++i) {
        char val[64];
        if (get_arg_value(argv[i], "--mss=", val, sizeof(val))) {
            MSS = atoi(val);
        }
        else if (get_arg_value(argv[i], "--rto=", val, sizeof(val))) {
            RTO = atoi(val);
        }
        else if (get_arg_value(argv[i], "--loss=", val, sizeof(val))) {
            lossP = atof(val);
        }
        else if (get_arg_value(argv[i], "--delay=", val, sizeof(val))) {
            send_delay_ms = atoi(val);
        }
    }
    if (W <= 0) { printf("错误：W必须>0\n"); return 1; }
    if (MSS < 200) MSS = 200;
    if (RTO < 50) RTO = 50;
    if (lossP < 0.0) lossP = 0.0;
    if (lossP > 1.0) lossP = 1.0;
    if (send_delay_ms < 0) send_delay_ms = 0;

    if (W > 64) {
        printf("[警告] W>64：SACK位图只能覆盖ack之后前64段，建议W<=64。\n");
    }

    // 打开文件，计算文件大小与总段数
    FILE* fp = fopen(filename, "rb");
    if (!fp) {
        printf("无法打开输入文件：%s\n", filename);
        return 1;
    }
    fseek(fp, 0, SEEK_END);
    long fsz = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    if (fsz < 0) {
        printf("ftell失败\n");
        fclose(fp);
        return 1;
    }
    uint32_t totalSeg = (fsz == 0) ? 0u : (uint32_t)((fsz + MSS - 1) / MSS);

    printf("文件大小=%ld bytes, 总段数=%u, MSS=%d, 固定窗口W=%d, RTO=%dms, loss=%.3f\n",
        fsz, totalSeg, MSS, W, RTO, lossP);

    // 初始化随机数（用于丢包模拟）
    srand((unsigned int)GetTickCount());

    // Winsock
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

    sockaddr_in peer;
    memset(&peer, 0, sizeof(peer));
    peer.sin_family = AF_INET;
    peer.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, ip, &peer.sin_addr) != 1) {
        printf("IP地址解析失败：%s\n", ip);
        closesocket(sock);
        WSACleanup();
        fclose(fp);
        return 1;
    }

    // 发送函数封装（带loss模拟）
    uint8_t sbuf[2048];
    auto send_pkt = [&](uint16_t flags, uint32_t seq, uint32_t ack, uint64_t sack_mask, const uint8_t* payload, uint16_t len) -> int {
        int plen = build_packet(sbuf, (int)sizeof(sbuf), flags, seq, ack, (uint16_t)W, sack_mask, payload, len);
        if (plen < 0) return 0;
        if (should_drop(lossP)) {
            // 丢包模拟：直接当作“发出去了”，但实际不发
            return 1;
        }
        if (send_delay_ms > 0) {
            Sleep(send_delay_ms);   // Windows API，毫秒
        }
        int r = sendto(sock, (const char*)sbuf, plen, 0, (sockaddr*)&peer, sizeof(peer));
        return (r == plen) ? 1 : 0;
    };

    // 接收缓冲
    uint8_t rbuf[2048];

    // ---------------- 1) 连接管理：三次握手 ----------------
    printf("开始连接（3次握手）...\n");

	uint64_t hs_deadline = 0; // 握手重传截止时间
	int hs_retries = 0; // 握手重传次数

    // SYN: flags=SYN, seq=0, ack=0
    hs_deadline = now_ms(); // 立即发送
	int connected = 0; // 连接成功标志

    while (!connected) {
        uint64_t now = now_ms();

		// 超时重传SYN（包括第一次发送）
        if (now >= hs_deadline) {
            if (hs_retries >= 50) {
                printf("握手失败：重试次数过多\n");
                closesocket(sock);
                WSACleanup();
                fclose(fp);
                return 1;
            }
            send_pkt(FLAG_SYN, 0, 0, 0ULL, NULL, 0);
			hs_deadline = now + 300; // 300ms后重传
            hs_retries++;
        }

        // 等待接收SYN|ACK
        if (wait_readable(sock, 50)) {
            sockaddr_in from;
            int fromlen = sizeof(from);
            int n = recvfrom(sock, (char*)rbuf, (int)sizeof(rbuf), 0, (sockaddr*)&from, &fromlen);
            if (n <= 0) continue;

            Header h;
            const uint8_t* payload = NULL;
            uint16_t len = 0;
            if (!parse_packet(rbuf, n, &h, &payload, &len)) continue;

            uint16_t flags = ntohs(h.flags);
            uint32_t ack = ntohl(h.ack);

            if ((flags & (FLAG_SYN | FLAG_ACK)) == (FLAG_SYN | FLAG_ACK) && ack == 1) {
                // 发送最后ACK
                send_pkt(FLAG_ACK, 0, 1, 0ULL, NULL, 0);
                connected = 1;
                printf("连接建立成功。\n");
                break;
            }
        }
    }

    // ---------------- 2) 可靠传输：流水线 + SACK + Reno ----------------
    if (totalSeg == 0) {
        printf("文件为空，无数据段发送，直接进入挥手。\n");
    }
    else {
        printf("开始发送数据...\n");
    }

    // 在途段缓存：容量取 max(W, 64) 更稳妥，这里直接取 128
    // （W一般<=64；容量足够即可）
    const int INFLIGHT_CAP = 128;
    InFlightSeg* inflight = (InFlightSeg*)calloc(INFLIGHT_CAP, sizeof(InFlightSeg));
    if (!inflight) {
        printf("内存分配失败\n");
        closesocket(sock);
        WSACleanup();
        fclose(fp);
        return 1;
    }

    // 发送状态
    uint32_t base = 1; // 当前最小未确认段号
    uint32_t nextSend = 1; // 下一个“新段”段号（未发送过的）
	uint32_t lastAck = 0; // 上次收到的最大ACK段号
	int dupAckCnt = 0; // 重复ACK计数

    // Reno参数（单位：段）
    int cwnd = 1;
    int ssthresh = 64;
    int fastRecovery = 0;
    int ca_acc = 0; // 拥塞避免累加器（实现“每RTT+1”）

    // 统计
    uint64_t t0 = 0, t1 = 0;
    int started = 0;
    uint64_t retrans = 0;

    // 发送指定段（必须先在inflight中有缓存）
    auto send_segment = [&](InFlightSeg* s) -> void {
        if (!s || !s->used || !s->data) return;
        send_pkt(FLAG_DATA, s->seq, 0, 0ULL, s->data, s->len);
        s->sent_time = now_ms();
        s->tx_count++;
        if (!started) { started = 1; t0 = now_ms(); }
    };

    // 尝试填满窗口发送新段：允许的在途段数 = min(cwnd, W)
    auto try_send_more = [&]() -> void {
        int flight_limit = (cwnd < W) ? cwnd : W;
        uint32_t wnd_end = base + (uint32_t)flight_limit; // [base, wnd_end)
        while (nextSend <= totalSeg && nextSend < wnd_end) {
            // 若已在inflight，说明之前发过（一般不会发生），跳过
            InFlightSeg* ex = inflight_find(inflight, INFLIGHT_CAP, nextSend);
            if (ex) {
                nextSend++;
                continue;
            }

            InFlightSeg* slot = inflight_alloc(inflight, INFLIGHT_CAP);
            if (!slot) {
                // 理论上不应发生（容量足够），发生则暂停填充
                break;
            }

            memset(slot, 0, sizeof(InFlightSeg));
            slot->used = 1;
            slot->seq = nextSend;
            slot->acked = 0;

            // 从文件加载该段数据到内存（用于重传）
            if (!load_segment_from_file(fp, fsz, MSS, nextSend, slot)) {
                inflight_free_slot(slot);
                break;
            }

            // 发送该段
            send_segment(slot);
            nextSend++;
        }
    };

    // 标记某段已确认（若不在inflight中则忽略）
    auto mark_acked = [&](uint32_t seq) -> int {
        InFlightSeg* s = inflight_find(inflight, INFLIGHT_CAP, seq);
        if (s && s->used && !s->acked) {
            s->acked = 1;
            return 1;
        }
        return 0;
        };

    // 滑动base：只要base对应段已acked，就释放并base++
    auto slide_base = [&]() -> int {
        int moved = 0;
        while (base <= totalSeg) {
            InFlightSeg* s = inflight_find(inflight, INFLIGHT_CAP, base);
            if (s && s->used && s->acked) {
                inflight_free_slot(s);
                base++;
                moved++;
            }
            else {
                break;
            }
        }
        // nextSend至少不能落后于base
        if (nextSend < base) nextSend = base;
        return moved;
    };

    // 拥塞控制：收到“新ACK（ack前进）”后根据Reno更新cwnd
    auto reno_on_new_ack = [&](int newlyAckedCount) -> void {
        if (newlyAckedCount <= 0) return;

        if (cwnd < ssthresh) {
            // 慢启动：每收到一个新确认，cwnd+1（近似指数增长）
            cwnd += newlyAckedCount;
        }
        else {
            // 拥塞避免：每个RTT增长约1，这里用累加器实现
            ca_acc += newlyAckedCount;
            while (ca_acc >= cwnd) {
                ca_acc -= cwnd;
                cwnd += 1;
            }
        }

        if (cwnd < 1) cwnd = 1;
    };

    // 处理ACK/SACK（关键）：ackno为“下一个期望段号”
    auto process_ack = [&](uint32_t ackno, uint64_t sack_mask) -> void {
        int advanced = (ackno > lastAck);
        int newlyAcked = 0;

        // 1) 累积确认：所有 < ackno 的段都已收到
        if (ackno > 1) {
            uint32_t upto = ackno - 1;
            if (upto > totalSeg) upto = totalSeg;
            // 只需要从base开始标记即可（更高效）
            for (uint32_t s = base; s <= upto; ++s) {
                newlyAcked += mark_acked(s);
            }
        }

        // 2) SACK位图：bit i=1 表示 (ackno+i) 已收到（乱序缓冲中）
        if (sack_mask != 0ULL) {
            for (int i = 0; i < 64; ++i) {
                if ((sack_mask >> i) & 1ULL) {
                    uint32_t s = ackno + (uint32_t)i;
                    if (s >= 1 && s <= totalSeg) {
                        newlyAcked += mark_acked(s);
                    }
                }
            }
        }

        // 3) 尝试滑动窗口base（释放已确认段）
        slide_base();

        // 4) Reno逻辑：区分新ACK与重复ACK
        if (advanced) {
            // 新ACK：可能从快恢复退出
            if (fastRecovery) {
                // Reno：收到新ACK，退出快恢复，cwnd = ssthresh
                cwnd = ssthresh;
                fastRecovery = 0;
                dupAckCnt = 0;
                ca_acc = 0;
            }
            else {
                dupAckCnt = 0;
            }
            lastAck = ackno;
            reno_on_new_ack(newlyAcked);
        }
        else {
            // 重复ACK：ack不前进
            dupAckCnt++;

            if (!fastRecovery && dupAckCnt == 3) {
                // 触发快重传/快恢复
                ssthresh = cwnd / 2;
                if (ssthresh < 2) ssthresh = 2;

                // Reno：cwnd = ssthresh + 3
                cwnd = ssthresh + 3;
                fastRecovery = 1;

                // 立即重传“缺失段”：通常就是 ackno 段
                InFlightSeg* miss = inflight_find(inflight, INFLIGHT_CAP, ackno);
                if (miss && miss->used && !miss->acked) {
                    send_segment(miss);
                    retrans++;
                }
            }
            else if (fastRecovery) {
                // 快恢复期间：每多一个dupACK，cwnd再+1，允许多发一个新段
                cwnd += 1;
            }
        }

        if (cwnd < 1) cwnd = 1;
    };

    // 超时处理（RTO）：重传base段，并将cwnd回退到1（Reno）
    auto on_timeout = [&]() -> void {
        ssthresh = cwnd / 2;
        if (ssthresh < 2) ssthresh = 2;

        cwnd = 1;
        fastRecovery = 0;
        dupAckCnt = 0;
        ca_acc = 0;

        // 重传base段（最老未确认段）
        InFlightSeg* s = inflight_find(inflight, INFLIGHT_CAP, base);
        if (s && s->used && !s->acked) {
            send_segment(s);
            retrans++;
        }

        // 注意：RTO后通常会“从base开始重新发送新段”，这里让nextSend回退到base
        nextSend = base;
    };

    // 主循环：直到所有段确认（base > totalSeg）
    while (base <= totalSeg) {
        // 先尽量发送新段填满窗口
        try_send_more();

        // 检查超时：只检查base段（类似TCP的计时器策略）
        InFlightSeg* bs = inflight_find(inflight, INFLIGHT_CAP, base);
        if (bs && bs->used && !bs->acked && bs->sent_time != 0) {
            uint64_t now = now_ms();
            if (now - bs->sent_time > (uint64_t)RTO) {
                // 超时重传
                on_timeout();
            }
        }

        // 处理ACK
        if (wait_readable(sock, 20)) {
            sockaddr_in from;
            int fromlen = sizeof(from);
            int n = recvfrom(sock, (char*)rbuf, (int)sizeof(rbuf), 0, (sockaddr*)&from, &fromlen);
            if (n > 0) {
                Header h;
                const uint8_t* payload = NULL;
                uint16_t len = 0;
                if (parse_packet(rbuf, n, &h, &payload, &len)) {
                    uint16_t flags = ntohs(h.flags);
                    if (flags & FLAG_ACK) {
                        uint32_t ackno = ntohl(h.ack);
                        uint64_t sack = ntohll_u64(h.sack_mask);

                        // 合理范围修正
                        if (ackno < 1) ackno = 1;
                        if (ackno > totalSeg + 1) ackno = totalSeg + 1;

                        process_ack(ackno, sack);
                    }
                }
            }
        }
    }

    printf("所有数据段均已确认。\n");

    // ---------------- 3) 连接管理：四次挥手 ----------------
    // 发送方：发FIN(seq=totalSeg+1)，等待对端ACK与FIN，然后回ACK
    uint32_t finSeq = totalSeg + 1;

    printf("开始关闭连接（挥手）...\n");

    int gotFinAck = 0;
    int gotPeerFin = 0;
    int fin_retries = 0;
    uint64_t fin_deadline = now_ms(); // 立即发FIN

    while (!(gotFinAck && gotPeerFin)) {
        uint64_t now = now_ms();

        if (now >= fin_deadline) {
            if (fin_retries >= 50) {
                printf("挥手失败：重试次数过多\n");
                break;
            }
            // 若还没收到FIN的ACK，就重发FIN；若已收到ACK，就主要等对端FIN
            if (!gotFinAck) {
                send_pkt(FLAG_FIN, finSeq, 0, 0ULL, NULL, 0);
            }
            fin_deadline = now + 300;
            fin_retries++;
        }

        if (wait_readable(sock, 50)) {
            sockaddr_in from;
            int fromlen = sizeof(from);
            int n = recvfrom(sock, (char*)rbuf, (int)sizeof(rbuf), 0, (sockaddr*)&from, &fromlen);
            if (n <= 0) continue;

            Header h;
            const uint8_t* payload = NULL;
            uint16_t len = 0;
            if (!parse_packet(rbuf, n, &h, &payload, &len)) continue;

            uint16_t flags = ntohs(h.flags);

            if ((flags & FLAG_ACK) && !gotFinAck) {
                uint32_t ackno = ntohl(h.ack);
                if (ackno >= finSeq + 1) {
                    gotFinAck = 1;
                }
            }

            if (flags & FLAG_FIN) {
                gotPeerFin = 1;
                uint32_t peerFinSeq = ntohl(h.seq);
                // 回ACK确认对端FIN
                send_pkt(FLAG_ACK, 0, peerFinSeq + 1, 0ULL, NULL, 0);
            }
        }
    }

    t1 = now_ms();

    // 释放inflight
    if (inflight) {
        for (int i = 0; i < INFLIGHT_CAP; ++i) {
            if (inflight[i].used) inflight_free_slot(&inflight[i]);
        }
        free(inflight);
        inflight = NULL;
    }

    fclose(fp);
    closesocket(sock);
    WSACleanup();

    // 输出性能指标
    if (started && t1 > t0) {
        uint64_t dt = t1 - t0;
        double sec = (double)dt / 1000.0;
        double mbps = (sec > 0.0) ? ((double)fsz * 8.0 / sec / 1e6) : 0.0;
        printf("传输完成。\n");
        printf("传输时间：%llu ms\n", (unsigned long long)dt);
        printf("平均吞吐率：%.3f Mbps\n", mbps);
        printf("重传次数：%llu\n", (unsigned long long)retrans);
    }
    else {
        printf("完成。\n");
    }

    return 0;
}
