# TCP流重组与恶意软件检测项目代码分析

## 核心功能演示

### 实际应用场景示例

当你运行 `./pcap sample2.pcapng` 时，程序会生成一个名为 `cs-test.2` 的文件。这个过程展示了TCP流重组的核心价值：

#### 1. **sample2.pcapng 的内容**
- 这是一个网络数据包捕获文件
- 记录了某次 FTP 文件下载 `cs-test.2` 的完整网络通信过程
- 包含了从建立连接到文件传输完成的所有网络数据包

#### 2. **FTP 文件传输的网络层面**
```
客户端 → 服务器: "RETR cs-test.2"     (控制连接，端口21)
服务器 → 客户端: "150 Opening..."      (控制连接)
服务器 → 客户端: [文件数据包1]         (数据连接)
服务器 → 客户端: [文件数据包2]         (数据连接)
服务器 → 客户端: [文件数据包3]         (数据连接)
...
服务器 → 客户端: [FIN包]              (数据连接结束)
```

#### 3. **TCP 流重组的作用**
- **问题**：文件在网络传输时被分割成很多小的 TCP 数据包
- **挑战**：这些包可能乱序到达，可能有重复，可能有丢失
- **解决**：程序按照 TCP 序列号重新排序，去重，最终还原出完整文件

#### 4. **最终结果**
通过分析 `sample2.pcapng`，程序可以：
- 提取 FTP 会话信息（用户名、密码、文件名）
- **完整恢复出 `cs-test.2` 文件的原始内容！**

### 网络取证的核心技术

这就是网络取证的核心应用场景：
- **网络管理员**：发现有人通过 FTP 传输了可疑文件，想知道具体传输了什么
- **安全分析师**：怀疑有恶意软件通过 FTP 传播，需要提取样本进行分析
- **数字取证专家**：需要从网络流量中恢复证据文件

---

## 项目概述

这是一个用于分析pcap文件并重组FTP数据传输的网络安全工具。项目主要实现了TCP流重组功能，能够从网络数据包中提取和重建完整的文件传输过程。

## 项目整体架构

### 1. 编译构建 (Makefile)
```makefile
APP=pcap
gcc -o $(APP) pcap-sample.c TCPFlowReconstruction.c -lpcap
```
项目编译生成名为 `pcap` 的可执行文件，链接了libpcap库用于处理网络数据包。

### 2. 核心文件结构
- **pcap-sample.c**: 主程序，负责数据包解析和FTP协议分析
- **TCPFlowReconstruction.c**: TCP流重组核心算法实现
- **TCPFlowReconstruction.h**: TCP流重组模块接口定义
- **packet_header.h**: 网络协议头部数据结构定义
- **se_dbg.h**: 调试输出系统

### 3. 数据包处理流水线
```
pcap文件 → pkt_proc() → ip_proc() → tcp_proc() → ftp_ctrl_proc() / process_ftp_data()
```

## 数据包头部定义 (packet_header.h)

项目定义了完整的网络协议栈数据结构：

### 以太网帧头部 (EthHdr_t)
```c
typedef struct ethhdr {
    uint8_t h_dest[6];      // 目的MAC地址
    uint8_t h_source[6];    // 源MAC地址
    uint16_t h_type;        // 帧类型 (0x0800表示IP)
} EthHdr_t;
```

### IP数据报头部 (IPHdr_t)
```c
typedef struct iphdr {
    uint8_t ihl:4, version:4;   // 版本和头部长度
    uint8_t tos;                // 服务类型
    uint16_t tot_len;           // 总长度
    uint32_t saddr;             // 源IP地址
    uint32_t daddr;             // 目的IP地址
    uint8_t protocol;           // 协议类型 (6=TCP)
    // ... 其他字段
} IPHdr_t;
```

### TCP报文段头部 (TCPHdr_t)
```c
typedef struct tcphdr {
    uint16_t source;        // 源端口
    uint16_t dest;          // 目的端口
    uint32_t seq;           // 序列号
    uint32_t ack_seq;       // 确认号
    uint8_t syn:1, fin:1, ack:1, rst:1, psh:1, urg:1;  // TCP标志位
    uint16_t window;        // 窗口大小
    // ... 其他字段
} TCPHdr_t;
```

这些数据结构考虑了大小端字节序的兼容性，使用条件编译来适配不同的系统架构。

## 主程序流程分析 (pcap-sample.c)

### 程序入口点 (main函数)
```c
int main(int argc, char **argv)
{
    char *pfile;
    pcap_t *pd = NULL;
    char ebuf[PCAP_ERRBUF_SIZE];
    int count = 0;

    // 1. 参数检查
    if (argc != 2) {
        usage(argv[0]);
        return -1;
    }

    // 2. 打开pcap文件
    pfile = argv[1];
    pd = pcap_open_offline(pfile, ebuf);

    // 3. 循环处理每个数据包
    pcap_loop(pd, -1, pkt_proc, (u_char *) & count);

    // 4. 输出FTP会话信息
    printf("Client IP: %u.%u.%u.%u\n", NIPQUAD(ftp_client_ip));
    printf("Username : %s\n", ftp_username);
    printf("Password : %s\n", ftp_password);
    printf("File name: %s\n", ftp_filename);
}
```

### 数据包处理函数

#### 1. pkt_proc() - 以太网帧处理
```c
void pkt_proc(u_char * arg, const struct pcap_pkthdr *pkthdr, const u_char * packet)
{
    EthHdr_t *eth = (EthHdr_t *) packet;

    // 检查帧类型，如果是IP包(0x0800)则继续处理
    if (ntohs(eth->h_type) == 0x0800) {
        ip_proc(packet + sizeof(EthHdr_t), pkthdr->len - sizeof(EthHdr_t));
    }
}
```

#### 2. ip_proc() - IP数据报处理
```c
void ip_proc(const u_char * ip_pkt, __u32 pkt_len)
{
    IPHdr_t *iph = (IPHdr_t *) ip_pkt;

    // 如果是TCP协议，继续处理
    if (iph->protocol == IPPROTO_TCP) {
        tcp_proc(ip_pkt + iph->ihl * 4,
                ntohs(iph->tot_len) - iph->ihl * 4,
                iph->saddr, iph->daddr);
    }
}
```

#### 3. tcp_proc() - TCP报文段处理
```c
void tcp_proc(const u_char * tcp_pkt, __u32 pkt_len, __u32 srcip, __u32 dstip)
{
    TCPHdr_t *tcph = (TCPHdr_t *) tcp_pkt;

    // 检查是否为FTP控制连接 (端口21)
    if (ntohs(tcph->dest) == 21) {
        ftp_ctrl_proc(0, tcp_pkt + tcph->doff * 4,
                     pkt_len - tcph->doff * 4, srcip, dstip);
    } else if (ntohs(tcph->source) == 21) {
        ftp_ctrl_proc(1, tcp_pkt + tcph->doff * 4,
                     pkt_len - tcph->doff * 4, dstip, srcip);
    }

    // 调用TCP流重组模块
    const u_char *payload = tcp_pkt + tcph->doff * 4;
    __u32 payload_len = pkt_len - tcph->doff * 4;
    __u32 seq = ntohl(tcph->seq);
    process_ftp_data(payload, payload_len, seq, tcph->syn, tcph->fin);
}
```

## FTP协议解析功能

### FTP控制连接处理 (ftp_ctrl_proc函数)

该函数负责解析FTP控制连接中的命令和响应，提取关键的会话信息：

#### 1. 用户认证信息提取
```c
// 捕获用户名
if (strncmp(ftp_msg, "USER ", 5) == 0) {
    bzero(ftp_username, sizeof(ftp_username));
    strncpy(ftp_username, ftp_msg + 5, msg_len - 7); // 减去"USER "和"\r\n"
}
// 捕获密码
else if (strncmp(ftp_msg, "PASS ", 5) == 0) {
    bzero(ftp_password, sizeof(ftp_password));
    strncpy(ftp_password, ftp_msg + 5, msg_len - 7); // 减去"PASS "和"\r\n"
}
```

#### 2. 数据连接模式识别
FTP支持两种数据传输模式：

**PORT模式 (主动模式)**：
```c
if (strncmp(ftp_msg, FTP_CMD_PORT, strlen(FTP_CMD_PORT)) == 0) {
    // "PORT a1,a2,a3,a4,a5,a6"
    addrstr = ftp_msg + strlen(FTP_CMD_PORT);
    if (get_ftp_data_addr(addrstr) == 0) {
        ftp_data_mode = FTP_DATA_MODE_PORT;
    }
}
```

**PASV模式 (被动模式)**：
```c
else if (strncmp(ftp_msg, "227", strlen("227")) == 0) {
    // "227 Entering Passive Mode (a1,a2,a3,a4,a5,a6)"
    addrstr = strchr(ftp_msg, '(');
    if (addrstr != NULL) {
        addrstr++;
        if (get_ftp_data_addr(addrstr) == 0) {
            ftp_data_mode = FTP_DATA_MODE_PASV;
        }
    }
}
```

#### 3. 文件操作命令识别
```c
if (strncmp(ftp_msg, FTP_CMD_RETR, strlen(FTP_CMD_RETR)) == 0) {
    ftp_data_cmd = FTP_DATA_CMD_RETR;  // 下载文件
    strncpy(ftp_filename, ftp_msg + strlen(FTP_CMD_RETR),
            msg_len - strlen(FTP_CMD_RETR) - 2);
} else if (strncmp(ftp_msg, FTP_CMD_STOR, strlen(FTP_CMD_STOR)) == 0) {
    ftp_data_cmd = FTP_DATA_CMD_STOR;  // 上传文件
    strncpy(ftp_filename, ftp_msg + strlen(FTP_CMD_STOR),
            msg_len - strlen(FTP_CMD_STOR) - 2);
}
```

### 数据连接地址解析 (get_ftp_data_addr函数)

FTP协议中的地址格式为 "a1,a2,a3,a4,a5,a6"，需要转换为IP地址和端口：

```c
int get_ftp_data_addr(const char *addrstr)
{
    __u32 a1, a2, a3, a4, a5, a6;
    char ipstr[20];
    struct in_addr in;

    // 解析六个数字
    sscanf(addrstr, "%u,%u,%u,%u,%u,%u", &a1, &a2, &a3, &a4, &a5, &a6);

    // 构造IP地址: a1.a2.a3.a4
    sprintf(ipstr, "%u.%u.%u.%u", a1, a2, a3, a4);
    inet_aton(ipstr, &in);
    ftp_data_listen_ip = in.s_addr;

    // 构造端口号: a5 * 256 + a6
    ftp_data_listen_port = a5 * 256 + a6;

    return 0;
}
```

## TCP流重组核心算法 (TCPFlowReconstruction.c)

### 数据结构设计

#### 数据段结构体
```c
typedef struct segment {
    __u32 seq;           // TCP序列号
    __u32 len;           // 数据长度
    u_char *data;        // 数据内容
    struct segment *next; // 链表指针
} segment_t;
```

#### 全局状态变量
```c
static segment_t *stream_head = NULL;    // 链表头指针
static int stream_initialized = 0;       // 流初始化标志
static __u32 base_seq = 0;              // 基准序列号
```

### 核心算法实现

#### 1. 主处理函数 (process_ftp_data)
```c
void process_ftp_data(const u_char *payload, __u32 payload_len,
                     uint32_t seq, int syn, int fin)
{
    // 流初始化：检测SYN标志
    if(syn && !stream_initialized) {
        printf("~~~DEBUG~~~: SYN -> Stream Initialized\n");
        free_stream(); // 确保无旧数据
        stream_initialized = 1;
        base_seq = seq;
    }

    if(!stream_initialized)
        return;

    // 数据插入：按序号排序插入数据
    insert_segment(seq, payload, payload_len);

    // 流结束：检测FIN标志，触发文件写入
    if(fin) {
        printf("~~~DEBUG~~~: FIN -> Stream Ended\n");
        flush_stream();
        free_stream();
    }
}
```

#### 2. 有序插入算法 (insert_segment)
这是TCP流重组的核心算法，实现了按序列号排序的链表插入：

```c
static void insert_segment(__u32 seq, const u_char *data, __u32 len) {
    segment_t *seg, *prev = NULL, *cur = stream_head;

    // 忽略空载荷
    if (len == 0) {
        printf("~~~DEBUG~~~: 空载荷包，忽略\n");
        return;
    }

    // 查找插入位置并检查重复
    while(cur) {
        if(cur->seq == seq) {
            return;  // 去重：忽略重复的序列号
        }
        if(cur->seq > seq) break;  // 找到插入位置
        prev = cur;
        cur = cur->next;
    }

    // 创建新节点
    seg = (segment_t *)malloc(sizeof(segment_t));
    seg->seq = seq;
    seg->len = len;
    seg->data = (u_char *)malloc(len);
    memcpy(seg->data, data, len);

    // 插入链表
    seg->next = cur;
    if(prev)
        prev->next = seg;
    else
        stream_head = seg;

    printf("~~~DEBUG~~~: 普通数据包 -> Packet Inserted, seq=%u\n", seq);
}
```

**算法特点：**
- **有序性**：维护按TCP序列号排序的链表
- **去重性**：自动忽略重复的数据包
- **动态性**：支持乱序到达的数据包重组

#### 3. 文件重组输出 (flush_stream)
```c
static void flush_stream() {
    FILE *fp = NULL;
    segment_t *cur;

    // 检查文件名
    if(strlen(ftp_filename) == 0) {
        fprintf(stderr, "未获取到目标文件名，重组数据放弃\n");
        return;
    }

    // 打开输出文件
    fp = fopen(ftp_filename, "wb");
    if(!fp) {
        perror("fopen");
        return;
    }

    // 按链表顺序写入所有数据段
    cur = stream_head;
    while(cur) {
        fwrite(cur->data, 1, cur->len, fp);
        cur = cur->next;
    }

    fclose(fp);
    printf("文件[%s]重组完成并写入\n", ftp_filename);
}
```

#### 4. 内存管理 (free_stream)
```c
static void free_stream() {
    segment_t *cur = stream_head, *tmp;

    // 释放所有链表节点
    while(cur) {
        tmp = cur;
        cur = cur->next;
        free(tmp->data);  // 释放数据缓冲区
        free(tmp);        // 释放节点结构
    }

    // 重置全局状态
    stream_head = NULL;
    stream_initialized = 0;
    base_seq = 0;
}
```

## 调试系统分析 (se_dbg.h)

### 条件编译调试框架

项目实现了一个完整的调试输出系统，支持条件编译：

```c
#ifdef WITH_DBG
    #define DBG(fmt, arg...) fprintf(stderr, fmt, ##arg)
#else
    #define DBG(fmt, arg...) do { } while (0)
#endif
```

### 调试功能特性

#### 1. 数据包转储功能
```c
static inline void _DBG_DUMP_SIMPLE(const unsigned char *data, size_t len)
{
    const char hexdig[] = "0123456789ABCDEF";
    // 以十六进制格式输出数据包内容
    for (dp = data; dp < (data + len); dp++) {
        h[i++] = hexdig[(*dp >> 4) & 0x0F];
        h[i++] = hexdig[(*dp) & 0x0F];
        h[i++] = ' ';
    }
}
```

#### 2. 协议信息输出
- **IP包信息**：源IP、目的IP、协议类型、包长度
- **TCP包信息**：端口号、序列号、确认号、标志位
- **以太网帧信息**：MAC地址、帧类型

#### 3. 调试开关控制
```c
//#define _DBG_PKT      // 数据包级调试
//#define _DBG_ETH      // 以太网帧调试
//#define _DBG_IP       // IP层调试
//#define _DBG_TCP      // TCP层调试
#define _DBG_FTP_CTRL  // FTP控制连接调试
```

## 程序执行流程总结

### 1. 初始化阶段
```
命令行参数检查 → 打开pcap文件 → 初始化libpcap
```

### 2. 数据包处理循环
```
pcap_loop() → pkt_proc() → 以太网解析 → IP解析 → TCP解析
                                                    ↓
                                            FTP控制分析 ← → TCP流重组
```

### 3. 流重组过程
```
SYN检测 → 流初始化 → 数据包插入 → 有序排列 → FIN检测 → 文件输出
```

### 4. 结果输出
```
统计信息 → FTP会话信息 → 用户名密码 → 文件名 → 连接模式
```

## 技术特点与优势

### 1. 协议栈完整性
- 支持完整的网络协议栈解析：以太网 → IP → TCP → FTP
- 考虑字节序兼容性，支持大小端系统

### 2. TCP流重组算法
- **有序重组**：按TCP序列号排序处理乱序数据包
- **去重机制**：自动忽略重复传输的数据包
- **内存管理**：动态分配和释放，避免内存泄漏

### 3. FTP协议深度解析
- **双模式支持**：PORT主动模式和PASV被动模式
- **会话信息提取**：用户名、密码、文件名、连接信息
- **命令识别**：LIST、RETR、STOR等文件操作命令

### 4. 调试和监控
- **分层调试**：支持不同协议层的独立调试开关
- **数据可视化**：十六进制和ASCII双格式数据显示
- **实时监控**：流重组过程的详细状态输出

## 实际应用场景

### 1. 网络取证
- **文件恢复**：从网络流量中恢复传输的完整文件
- **证据收集**：提取FTP传输的用户认证信息
- **行为分析**：分析网络中的文件传输行为模式

### 2. 安全分析
- **恶意软件检测**：识别通过FTP传输的恶意文件
- **数据泄露监控**：监控敏感文件的外传行为
- **入侵检测**：分析异常的FTP传输活动

### 3. 协议学习
- **教学工具**：深入理解TCP/IP和FTP协议工作机制
- **调试辅助**：网络应用开发中的协议调试
- **性能分析**：TCP流重组算法的性能研究

### 4. 流量监控
- **带宽分析**：统计FTP传输占用的网络带宽
- **用户行为**：分析用户的文件传输习惯
- **系统优化**：基于流量分析优化网络配置

## 项目价值

这个TCP流重组项目展示了：
- 完整的网络数据包分析技术
- 高效的TCP流重组算法实现
- 深入的应用层协议解析
- 实用的网络安全工具开发

是学习网络协议、网络安全和系统编程的优秀实例，具有很强的教学和实践价值。
```