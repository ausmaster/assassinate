@echo off
REM Quick HFS starter - run this from the shared folder
REM Access shared folder in Windows via: \\VBOXSVR\shared or D:\ or E:\

echo [*] Starting Rejetto HFS 2.3 on port 8080...

REM Disable firewall for port 8080
netsh advfirewall firewall add rule name="HFS HTTP Server" dir=in action=allow protocol=tcp localport=8080 2>nul

REM Run HFS directly from current location
start "" hfs.exe -p 8080

echo [+] HFS should now be running on port 8080
echo [+] Vulnerable to: exploit/windows/http/rejetto_hfs_exec
pause
