# 网络与系统安全课程设计使用指南

## 项目概述

本项目实现了两个主要功能：
1. **TCP流重组**：从pcap网络包文件中重组FTP数据传输
2. **恶意代码检测**：使用IDA Pro插件检测软件漏洞和恶意行为

## 环境要求

- Linux系统（推荐Ubuntu）
- gcc编译器
- libpcap开发库
- IDA Pro 7.5或更高版本
- Python 3.x
- QEMU模拟器（用于动态分析）

## 安装依赖

```bash
# Ubuntu/Debian系统
sudo apt-get update
sudo apt-get install gcc libpcap-dev qemu-user

# 验证安装
gcc --version
qemu-i386 --version
```

## 第一步：TCP流重组

### 1.1 编译程序

```bash
# 进入项目目录
cd /path/to/TCPFlowReconstruction-MalwareDetection/src

# 编译TCP流重组程序
make

# 验证编译结果
ls -la pcap
```

### 1.2 运行TCP流重组

```bash
# 使用提供的pcap文件进行测试
./pcap sample1.pcapng

# 或者使用其他pcap文件
./pcap pkt593960.pcapng
```

### 1.3 程序输出说明

程序运行后会显示：
- 解析的网络包数量
- FTP会话信息（客户端IP、服务器IP、用户名、密码）
- 传输的文件名
- 数据连接模式（PORT或PASV）
- 重组完成的文件

## 第二步：验证重组结果

### 2.1 检查重组文件

```bash
# 查看重组出的文件
ls -la cs-test.2

# 检查文件类型
file cs-test.2

# 查看文件大小
du -h cs-test.2
```

### 2.2 验证文件完整性

```bash
# 计算MD5哈希值
md5sum cs-test.2

# 如果有原始文件，进行比较
md5sum cs-test2.orig

# 或者使用diff命令比较
diff cs-test.2 cs-test2.orig
```

### 2.3 预期结果

- 重组文件应该与原始文件的MD5值相同
- 如果MD5不匹配，检查TCP流重组算法是否正确处理了包的顺序

## 第三步：手动逆向分析

### 3.1 初步分析

```bash
# 查看文件基本信息
file cs-test.2
strings cs-test.2 | head -20

# 检查是否为可执行文件
chmod +x cs-test.2
```

### 3.2 静态分析要点

进行手动逆向分析时，重点关注：

1. **程序入口点**：main函数的实现
2. **网络功能**：socket、bind、listen等网络相关函数
3. **文件操作**：文件读写、删除等操作
4. **系统调用**：system、exec等可能的恶意调用
5. **字符串分析**：查找可疑的命令、路径、IP地址等

### 3.3 分析工具推荐

- **objdump**：反汇编分析
- **readelf**：ELF文件结构分析
- **strings**：提取字符串
- **strace**：系统调用跟踪

## 第四步：IDA Pro恶意代码检测

### 4.1 准备工作

```bash
# 确保plugin.py和malware_list.py在同一目录
ls -la plugin.py malware_list.py

# 检查Python依赖
python3 -c "import idautils, idc, idaapi"
```

### 4.2 在IDA Pro中加载文件

1. 启动IDA Pro
2. 打开cs-test.2文件
3. 等待IDA完成自动分析
4. 确认所有函数都已识别

### 4.3 运行检测插件

**方法一：通过菜单加载**
```
File -> Script file -> 选择plugin.py
```

**方法二：通过命令行**
```
Alt+F7 打开脚本窗口
exec(open('plugin.py').read())
```

### 4.4 插件检测功能

插件会自动检测以下内容：

**软件漏洞检测：**
- 栈溢出漏洞
- 堆溢出漏洞
- Use After Free漏洞
- Double Free漏洞

**恶意代码检测：**
- 系统文件删除与修改
- 后门程序
- 僵尸进程创建
- 禁用系统保护
- 权限提升
- 恶意代码执行

### 4.5 分析检测结果

插件输出格式：
```
发现恶意代码 - 函数名：[函数名], 类型：[漏洞类型], 地址：0x[地址], 证据：[触发函数/特征]
```

## 第五步：动态验证（QEMU环境）

### 5.1 准备QEMU环境

```bash
# 创建测试目录
mkdir -p /home/cs-test/Test
cd /home/cs-test/Test

# 复制目标文件
cp /path/to/cs-test.2 .
cp /path/to/exploit.py .

# 设置执行权限
chmod +x cs-test.2
```

### 5.2 启动目标程序

```bash
# 在QEMU中运行，启用跟踪
qemu-i386 -strace -d in_asm -D trace.log cs-test.2

# 程序应该监听在端口12345
# 检查端口是否开启
netstat -tlnp | grep 12345
```

### 5.3 使用exploit.py进行漏洞利用

```bash
# 在另一个终端运行exploit脚本
python3 ./exploit.py
```

**exploit.py功能菜单：**
- 选项1：Mal_func1 - 删除系统日志
- 选项2：Mal_func2 - 代码执行（运行hustlogo.png）
- 选项3：Mal_func3 - 后门（nc > hustlogo.png）
- 选项4：Mal_func4 - 僵尸进程
- 选项5：Mal_func5 - 禁用SELinux

### 5.4 验证恶意行为

**验证后门功能：**
```bash
# 连接到后门端口
nc 127.0.0.1 54321
echo "NEVER GONNA GIVE YOU UP"
```

**检查系统变化：**
```bash
# 检查进程状态
ps aux | grep cs-test

# 检查网络连接
netstat -tlnp

# 检查文件变化
ls -la hustlogo.png
```

### 5.5 分析trace.log

```bash
# 查看系统调用跟踪
tail -f trace.log

# 分析关键系统调用
grep -E "(socket|bind|listen|fork|exec)" trace.log
```

## 故障排除

### 常见问题

**编译错误：**
```bash
# 如果缺少libpcap
sudo apt-get install libpcap-dev

# 如果编译失败，清理后重新编译
make clean
make
```

**IDA Pro插件错误：**
- 确保IDA Pro版本 >= 7.5
- 检查malware_list.py是否在同一目录
- 验证Python环境是否正确

**QEMU运行问题：**
```bash
# 如果qemu-i386不存在
sudo apt-get install qemu-user

# 如果权限问题
chmod +x cs-test.2
```

### 预期输出示例

**TCP流重组成功输出：**
```
Total 1234 packets are analyzed.
FTP Session Information:
Client IP: 192.168.1.100
Server IP: 192.168.1.1
Username: testuser
Password: testpass
File name: cs-test.2
Data Mode: PASV
文件[cs-test.2]重组完成并写入
```

## 项目文件说明

| 文件名 | 功能描述 |
|--------|----------|
| `pcap-sample.c` | 主程序，解析pcap文件和FTP协议 |
| `TCPFlowReconstruction.c` | TCP流重组核心算法 |
| `TCPFlowReconstruction.h` | TCP流重组头文件 |
| `plugin.py` | IDA Pro恶意代码检测插件 |
| `malware_list.py` | 恶意代码特征库（黑白名单） |
| `exploit.py` | 漏洞利用脚本 |
| `packet_header.h` | 网络包头结构定义 |
| `se_dbg.h` | 调试宏定义 |
| `sample1.pcapng` | 测试用pcap文件 |
| `Makefile` | 编译配置文件 |

## 学习要点

1. **TCP流重组**：理解TCP序列号、分片重组算法
2. **协议分析**：掌握FTP协议的控制连接和数据连接
3. **静态分析**：学会使用IDA Pro进行逆向工程
4. **动态分析**：掌握QEMU模拟器的使用
5. **漏洞检测**：了解常见的软件漏洞类型
6. **恶意代码识别**：学习恶意行为的特征和检测方法

---
**注意：本项目仅用于教学和研究目的，请勿用于非法用途。**