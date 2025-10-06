import random
from datetime import datetime, timedelta

def generate_sample_logs():
    """Generate sample UNIX system logs for demonstration"""
    
    # Sample log templates
    normal_logs = [
        "Jan 15 10:30:15 server1 sshd[1234]: Accepted publickey for user1 from 192.168.1.100 port 22 ssh2",
        "Jan 15 10:31:20 server1 kernel: [12345.678] USB disconnect, address 1",
        "Jan 15 10:32:25 server1 systemd[1]: Started User Manager for UID 1000",
        "Jan 15 10:33:30 server1 cron[5678]: (user1) CMD (/usr/bin/backup.sh)",
        "Jan 15 10:34:35 server1 apache2[9012]: 192.168.1.50 - - [15/Jan/2024:10:34:35 +0000] \"GET /index.html HTTP/1.1\" 200 1234",
        "Jan 15 10:35:40 server1 postfix/smtpd[1111]: connect from mail.example.com[192.168.1.200]",
        "Jan 15 10:36:45 server1 dhcpd: DHCPDISCOVER from 00:11:22:33:44:55 via eth0",
        "Jan 15 10:37:50 server1 NetworkManager[2222]: <info> device (eth0): state change: activated -> disconnected"
    ]
    
    suspicious_logs = [
        "Jan 15 10:38:55 server1 sshd[3456]: Failed password for root from 10.0.0.1 port 22 ssh2",
        "Jan 15 10:39:00 server1 sshd[3457]: Failed password for admin from 10.0.0.1 port 22 ssh2",
        "Jan 15 10:40:05 server1 sudo: user1 : TTY=pts/0 ; PWD=/home/user1 ; USER=root ; COMMAND=/bin/bash",
        "Jan 15 10:41:10 server1 kernel: [12346.789] possible SYN flooding on port 80. Sending cookies",
        "Jan 15 10:42:15 server1 apache2[9013]: 192.168.1.200 - - [15/Jan/2024:10:42:15 +0000] \"GET /admin/config.php HTTP/1.1\" 404 0",
        "Jan 15 10:43:20 server1 sshd[3458]: Invalid user hacker from 203.0.113.1",
        "Jan 15 10:44:25 server1 auth: pam_unix(login:auth): authentication failure; logname= uid=0 euid=0 tty=tty1 ruser= rhost= user=root",
        "Jan 15 10:45:30 server1 apache2[9014]: 192.168.1.201 - - [15/Jan/2024:10:45:30 +0000] \"POST /wp-admin/admin-ajax.php HTTP/1.1\" 200 0"
    ]
    
    # Generate a mix of normal and suspicious logs
    sample_logs = []
    
    # Add normal logs (70%)
    for _ in range(14):
        log = random.choice(normal_logs)
        sample_logs.append(log)
    
    # Add suspicious logs (30%)
    for _ in range(6):
        log = random.choice(suspicious_logs)
        sample_logs.append(log)
    
    # Shuffle the logs
    random.shuffle(sample_logs)
    
    return '\n'.join(sample_logs)