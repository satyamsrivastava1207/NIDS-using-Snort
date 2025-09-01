# NIDS-using-Snort
# Infotact Solutions  

## Month-1 Deliverable Report  

---

### 📌 Week 1: Introduction to NIDS and Snort – Installation and Setup  

#### What is NIDS (Network Intrusion Detection System)?  
A **Network Intrusion Detection System (NIDS)** is a cybersecurity tool that monitors network traffic for suspicious activity or known threats and alerts the user/admin.  
- Works passively (does not block traffic, only detects & reports).  

#### What is Snort?  
Snort is an open-source NIDS tool developed by Cisco. It captures and analyzes packets in real-time to detect malicious activity using rules and signatures.  

**Key features of Snort:**  
- Packet sniffing  
- Real-time traffic analysis  
- Protocol analysis  
- Content matching with rule-based detection  

#### ✅ Tasks Performed:  
1. **Linux Installation (Ubuntu/Kali)**  
   - Installed using a virtual machine.  
   - Base OS for installing Snort.  
   - *Screenshot 1: Linux UI after installation.*  

2. **Snort Installation**  
   ```bash
   sudo apt install snort
   snort --version
   ```
### Week 2: Configuring Snort and Monitoring Live Network Traffic
#### Identifying Active Network Interface
```bash
ifconfig
# or
ip a
```

#### Configuring Snort for IP Range

```bash
Edited HOME_NET in /etc/snort/snort.conf:

var HOME_NET 10.0.2.0/24
```

#### Running Snort in Detection Mode
```bash
sudo snort -c /etc/snort/snort.lua -i eth0 -A alert_fast
```

#### Parameters explained:
```bash
-c /etc/snort/snort.lua → configuration file

-i eth0 → interface to monitor

-A alert_fast → fast alert output
```

#### Monitoring Live Traffic
```bash
ping -c 4 <gateway_ip>
```

Alerts stored in /var/log/snort/alert


### Week 3: Simulating Network Attacks and Analyzing Snort Alerts
#### Purpose of Simulated Attacks

Used in controlled environments to test IDS effectiveness.

Example: ICMP flood attacks for stress testing.

#### Generating Suspicious Traffic (Ping Flood)
```bash
ping -f <target_ip>
```

Sends ICMP packets rapidly (DoS simulation).


#### Capturing & Viewing Snort Alerts

Logs stored at:
```bash
/var/log/snort/alert
```

#### View alerts:
```bash
cat /var/log/snort/alert
```

#### Interpreting Alerts

Each alert contains:

Alert message & priority

Classification (e.g., ICMP flood attack)

Source & destination IPs

Protocol & port numbers


### Week 4: Writing and Testing Custom Snort Rules
#### Understanding Rule Syntax

Format:
```bash
action protocol src_ip src_port -> dst_ip dst_port (options)
```

Example:
```bash
alert icmp any any -> any any (msg:"ICMP Packet Detected"; sid:1000001;)
```

Explanation:

alert → action

icmp → protocol

any any -> any any → source/destination IP & port

msg → alert message

sid → unique Snort ID

#### Writing a Custom Rule

Added this rule in /etc/snort/rules/local.rules:
```bash
alert icmp any any -> any any (msg:"Custom ICMP Alert"; sid:1000002;)
```

Included it in Snort config:
```bash
include $RULE_PATH/local.rules
```

#### Testing the Custom Rule

Generate ICMP traffic:
```bash
ping <target_ip>
```

#### Run Snort:
```bash
sudo snort -c /etc/snort/snort.lua -i eth0 -A alert_fast -l /var/log/snort
```

#### Verifying Logs

Check alerts for custom rule message (Custom ICMP Alert):
```bash 
cat /var/log/snort/alert
# or
nano /var/log/snort/alert
```
