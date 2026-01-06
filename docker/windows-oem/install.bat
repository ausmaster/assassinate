@echo off
REM =============================================================================
REM Assassinate Windows Target - Vulnerable Service Setup
REM =============================================================================
REM This script installs Rejetto HTTP File Server 2.3 (CVE-2014-6287)
REM which is vulnerable to remote code execution.
REM
REM Exploit: exploit/windows/http/rejetto_hfs_exec
REM Port: 80 (HFS default - no config needed)
REM =============================================================================

echo [*] Assassinate Windows Target Setup
echo [*] Installing vulnerable services...

REM Create directory for vulnerable apps
mkdir C:\vuln 2>nul

REM Copy HFS from OEM folder (pre-downloaded binary)
echo [*] Copying Rejetto HFS 2.3 from OEM folder...
copy /Y "C:\OEM\hfs.exe" "C:\vuln\hfs.exe" 2>nul
copy /Y "C:\OEM\hfs.ini" "C:\vuln\hfs.ini" 2>nul

REM If copy failed, check shared folder
if not exist C:\vuln\hfs.exe (
    echo [!] OEM copy failed, checking shared folder...
    REM Try common share drive letters
    copy /Y "D:\hfs.exe" "C:\vuln\hfs.exe" 2>nul
    copy /Y "D:\hfs.ini" "C:\vuln\hfs.ini" 2>nul
    if not exist C:\vuln\hfs.exe copy /Y "E:\hfs.exe" "C:\vuln\hfs.exe" 2>nul
    if not exist C:\vuln\hfs.exe copy /Y "\\VBOXSVR\shared\hfs.exe" "C:\vuln\hfs.exe" 2>nul
)

REM Verify copy
if exist C:\vuln\hfs.exe (
    echo [+] HFS installed successfully
) else (
    echo [!] Failed to install HFS - binary not found
    echo [!] Please copy hfs.exe to C:\vuln manually
    exit /b 1
)

REM Create startup script to run HFS on boot (uses default port 80)
echo [*] Creating startup script...
echo @echo off > C:\vuln\start_hfs.bat
echo cd /d C:\vuln >> C:\vuln\start_hfs.bat
echo start "" hfs.exe >> C:\vuln\start_hfs.bat

REM Add to startup via registry
echo [*] Adding HFS to startup...
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "HFS" /t REG_SZ /d "C:\vuln\start_hfs.bat" /f

REM Create Windows Firewall rules to allow HFS (port 80 and program)
echo [*] Creating firewall rules for HFS...
netsh advfirewall firewall add rule name="HFS HTTP Server" dir=in action=allow protocol=tcp localport=80
netsh advfirewall firewall add rule name="HFS Program" dir=in action=allow program="C:\vuln\hfs.exe"

REM Start HFS now (uses default port 80)
echo [*] Starting HFS...
cd /d C:\vuln
start "" hfs.exe

echo [+] Setup complete!
echo [+] Rejetto HFS 2.3 running on port 80
echo [+] Vulnerable to: exploit/windows/http/rejetto_hfs_exec

REM Wait a moment to ensure service starts
timeout /t 5 /nobreak >nul

exit /b 0
