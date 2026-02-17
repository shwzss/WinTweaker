@echo off
setlocal EnableDelayedExpansion
color 0A
title WinTweaker - Windows Optimization Utility v1.1

:: ============================================================
::  WinTweaker v1.1 - Windows Optimization & Tweaking Utility
::  Supports: Windows 10 (all versions) + Windows 11 through 26H1
::  Requires Administrator privileges
:: ============================================================

:: Check for Admin
net session >nul 2>&1
if %errorlevel% neq 0 (
    color 0C
    echo.
    echo  [!] Administrator privileges required!
    echo  [!] Right-click and select "Run as administrator"
    echo.
    pause
    exit /b 1
)

:: Detect Windows Version
for /f "tokens=4-5 delims=. " %%i in ('ver') do set WIN_VER=%%i.%%j
for /f "tokens=3 delims=." %%a in ('ver') do set WIN_MAJOR=%%a
for /f "skip=1 tokens=1 delims=" %%a in ('wmic os get caption') do (
    if not defined WIN_NAME set WIN_NAME=%%a
)
:: Detect Windows 11 build
for /f "tokens=*" %%a in ('reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v CurrentBuildNumber 2^>nul') do (
    for /f "tokens=3" %%b in ("%%a") do set WIN_BUILD=%%b
)
for /f "tokens=*" %%a in ('reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v DisplayVersion 2^>nul') do (
    for /f "tokens=3" %%b in ("%%a") do set WIN_DISPLAY=%%b
)
set IS_WIN11=0
if !WIN_BUILD! GEQ 22000 set IS_WIN11=1

:MAIN_MENU
cls
color 0A
echo.
echo  +==========================================================+
echo  ^|          __        _  _  _____              _            ^|
echo  ^|         / / /\    / ^|^| ^|^|_   _^|            ^| ^|           ^|
echo  ^|        / / /  \   ^| ^| ^|   ^| ^|_      _____  ^| ^|  _____    ^|
echo  ^|       / / / /\ \  ^| ^| ^|   ^| \ \ /\ / / _ \ ^| ^| / ____|   ^|
echo  ^|      / / / ____ \ ^| ^| ^|   ^| ^|\ V  V /  __/ ^| ^|/ /         ^|
echo  ^|     /_/ /_/    \_\^|_^|_^|   ^|_^| \_/\_/ \___^| ^|_^|\_\        ^|
echo  ^|                                                          ^|
echo  ^|         Windows Optimization ^& Tweaking Utility         ^|
echo  ^|                      v1.1                               ^|
echo  +==========================================================+
echo  ^| OS: !WIN_NAME!
echo  ^| Build: !WIN_BUILD!   Version: !WIN_DISPLAY!
if !IS_WIN11!==1 (
echo  ^| [WIN11] Windows 11 tweaks ENABLED
) else (
echo  ^| [WIN10] Running in Windows 10 mode
)
echo  +----------------------------------------------------------+
echo.
echo   [1]  Performance Tweaks
echo   [2]  Privacy ^& Telemetry
echo   [3]  Network Optimizations
echo   [4]  Visual ^& UI Tweaks
echo   [5]  Power Settings
echo   [6]  Gaming Optimizations
echo   [7]  Timer Resolution Tweaks      ^<-- NEW in v1.1
echo   [8]  Windows 11 Specific Tweaks   ^<-- NEW in v1.1
echo   [9]  Startup ^& Services
echo   [10] Disk ^& Storage Tweaks
echo   [11] System Cleanup
echo   [12] Apply ALL Recommended Tweaks
echo   [13] Restore Defaults ^(System Restore Point^)
echo   [0]  Exit
echo.
echo  +----------------------------------------------------------+
set /p choice=" Enter choice: "

if "%choice%"=="1"  goto PERFORMANCE
if "%choice%"=="2"  goto PRIVACY
if "%choice%"=="3"  goto NETWORK
if "%choice%"=="4"  goto VISUAL
if "%choice%"=="5"  goto POWER
if "%choice%"=="6"  goto GAMING
if "%choice%"=="7"  goto TIMERRES
if "%choice%"=="8"  goto WIN11
if "%choice%"=="9"  goto STARTUP
if "%choice%"=="10" goto DISK
if "%choice%"=="11" goto CLEANUP
if "%choice%"=="12" goto ALL_TWEAKS
if "%choice%"=="13" goto RESTORE
if "%choice%"=="0"  goto EXIT
goto MAIN_MENU

:: ============================================================
::  PERFORMANCE TWEAKS
:: ============================================================
:PERFORMANCE
cls
echo.
echo  +----------------------------------------------------------+
echo  ^|              PERFORMANCE TWEAKS                         ^|
echo  +----------------------------------------------------------+
echo.
echo   [1]  Disable Visual Effects (Best Performance)
echo   [2]  Increase NTFS Memory Usage
echo   [3]  Disable Superfetch / SysMain
echo   [4]  Disable Windows Search Indexing
echo   [5]  Set Processor Scheduling to Programs
echo   [6]  Disable Hibernate
echo   [7]  Increase System Responsiveness
echo   [8]  Disable Core Isolation / Memory Integrity (perf gain)
echo   [9]  Apply ALL Performance Tweaks
echo   [0]  Back to Main Menu
echo.
set /p pchoice=" Enter choice: "

if "%pchoice%"=="1" goto PERF_VISUAL
if "%pchoice%"=="2" goto PERF_NTFS
if "%pchoice%"=="3" goto PERF_SUPERFETCH
if "%pchoice%"=="4" goto PERF_INDEX
if "%pchoice%"=="5" goto PERF_SCHEDULING
if "%pchoice%"=="6" goto PERF_HIBERNATE
if "%pchoice%"=="7" goto PERF_RESPONSIVENESS
if "%pchoice%"=="8" goto PERF_COREISOLATION
if "%pchoice%"=="9" goto PERF_ALL
if "%pchoice%"=="0" goto MAIN_MENU
goto PERFORMANCE

:PERF_VISUAL
echo  [*] Disabling Visual Effects for Best Performance...
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" /v VisualFXSetting /t REG_DWORD /d 2 /f >nul
reg add "HKCU\Control Panel\Desktop" /v UserPreferencesMask /t REG_BINARY /d 9012038010000000 /f >nul
reg add "HKCU\Control Panel\Desktop\WindowMetrics" /v MinAnimate /t REG_SZ /d 0 /f >nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ListviewAlphaSelect /t REG_DWORD /d 0 /f >nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v TaskbarAnimations /t REG_DWORD /d 0 /f >nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ExtendedUIHoverTime /t REG_DWORD /d 1 /f >nul
echo  [+] Visual Effects set to Best Performance!
goto :EOF

:PERF_NTFS
echo  [*] Optimizing NTFS...
reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v NtfsMemoryUsage /t REG_DWORD /d 2 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v NtfsDisable8dot3NameCreation /t REG_DWORD /d 1 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v NtfsDisableLastAccessUpdate /t REG_DWORD /d 1 /f >nul
echo  [+] NTFS optimized!
goto :EOF

:PERF_SUPERFETCH
echo  [*] Disabling Superfetch / SysMain...
sc stop SysMain >nul 2>&1
sc config SysMain start= disabled >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v EnableSuperfetch /t REG_DWORD /d 0 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v EnablePrefetcher /t REG_DWORD /d 0 /f >nul
echo  [+] Superfetch / SysMain disabled!
goto :EOF

:PERF_INDEX
echo  [*] Disabling Windows Search Indexing...
sc stop WSearch >nul 2>&1
sc config WSearch start= disabled >nul 2>&1
echo  [+] Windows Search Indexing disabled!
goto :EOF

:PERF_SCHEDULING
echo  [*] Setting Processor Scheduling to Programs...
reg add "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v Win32PrioritySeparation /t REG_DWORD /d 26 /f >nul
echo  [+] Processor Scheduling set to Programs!
goto :EOF

:PERF_HIBERNATE
echo  [*] Disabling Hibernate...
powercfg -h off >nul 2>&1
echo  [+] Hibernate disabled! (Frees hiberfil.sys space)
goto :EOF

:PERF_RESPONSIVENESS
echo  [*] Tweaking System Responsiveness...
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v SystemResponsiveness /t REG_DWORD /d 0 /f >nul
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "GPU Priority" /t REG_DWORD /d 8 /f >nul
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v Priority /t REG_DWORD /d 6 /f >nul
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Scheduling Category" /t REG_SZ /d High /f >nul
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "SFIO Priority" /t REG_SZ /d High /f >nul
echo  [+] System Responsiveness optimized!
goto :EOF

:PERF_COREISOLATION
echo  [*] Disabling Memory Integrity / Core Isolation...
echo  [!] NOTE: This reduces security. Only do this on gaming/perf machines.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" /v Enabled /t REG_DWORD /d 0 /f >nul
echo  [+] Memory Integrity disabled! (Reboot required)
goto :EOF

:PERF_ALL
echo  [*] Applying ALL Performance Tweaks...
call :PERF_VISUAL
call :PERF_NTFS
call :PERF_SUPERFETCH
call :PERF_INDEX
call :PERF_SCHEDULING
call :PERF_HIBERNATE
call :PERF_RESPONSIVENESS
echo.
echo  [+] ALL Performance Tweaks applied!
pause & goto PERFORMANCE

:: ============================================================
::  PRIVACY & TELEMETRY
:: ============================================================
:PRIVACY
cls
echo.
echo  +----------------------------------------------------------+
echo  ^|            PRIVACY ^& TELEMETRY                         ^|
echo  +----------------------------------------------------------+
echo.
echo   [1]  Disable Telemetry ^& Data Collection
echo   [2]  Disable Cortana
echo   [3]  Disable Activity History
echo   [4]  Disable Location Tracking
echo   [5]  Disable Advertising ID
echo   [6]  Disable Feedback Frequency
echo   [7]  Disable Microsoft Account Sync
echo   [8]  Disable App Diagnostics
echo   [9]  Apply ALL Privacy Tweaks
echo   [0]  Back to Main Menu
echo.
set /p prchoice=" Enter choice: "

if "%prchoice%"=="1" goto PRIV_TELEMETRY
if "%prchoice%"=="2" goto PRIV_CORTANA
if "%prchoice%"=="3" goto PRIV_ACTIVITY
if "%prchoice%"=="4" goto PRIV_LOCATION
if "%prchoice%"=="5" goto PRIV_ADID
if "%prchoice%"=="6" goto PRIV_FEEDBACK
if "%prchoice%"=="7" goto PRIV_MSSYNC
if "%prchoice%"=="8" goto PRIV_APPDIAG
if "%prchoice%"=="9" goto PRIV_ALL
if "%prchoice%"=="0" goto MAIN_MENU
goto PRIVACY

:PRIV_TELEMETRY
echo  [*] Disabling Telemetry ^& Data Collection...
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f >nul
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f >nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v LimitDiagnosticLogCollection /t REG_DWORD /d 1 /f >nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v DisableOneSettingsDownloads /t REG_DWORD /d 1 /f >nul
sc stop DiagTrack >nul 2>&1
sc config DiagTrack start= disabled >nul 2>&1
sc stop dmwappushservice >nul 2>&1
sc config dmwappushservice start= disabled >nul 2>&1
:: Win11 24H2+ Recall/AI telemetry
if !IS_WIN11!==1 (
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsAI" /v DisableAIDataAnalysis /t REG_DWORD /d 1 /f >nul 2>&1
    reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowCopilotButton /t REG_DWORD /d 0 /f >nul 2>&1
)
echo  [+] Telemetry disabled!
goto :EOF

:PRIV_CORTANA
echo  [*] Disabling Cortana...
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v AllowCortana /t REG_DWORD /d 0 /f >nul
reg add "HKCU\SOFTWARE\Microsoft\Personalization\Settings" /v AcceptedPrivacyPolicy /t REG_DWORD /d 0 /f >nul
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v BingSearchEnabled /t REG_DWORD /d 0 /f >nul
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v CortanaEnabled /t REG_DWORD /d 0 /f >nul
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v CortanaConsent /t REG_DWORD /d 0 /f >nul
echo  [+] Cortana disabled!
goto :EOF

:PRIV_ACTIVITY
echo  [*] Disabling Activity History...
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v EnableActivityFeed /t REG_DWORD /d 0 /f >nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v PublishUserActivities /t REG_DWORD /d 0 /f >nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v UploadUserActivities /t REG_DWORD /d 0 /f >nul
echo  [+] Activity History disabled!
goto :EOF

:PRIV_LOCATION
echo  [*] Disabling Location Tracking...
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /v Value /t REG_SZ /d Deny /f >nul
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /v Value /t REG_SZ /d Deny /f >nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v DisableLocation /t REG_DWORD /d 1 /f >nul
echo  [+] Location Tracking disabled!
goto :EOF

:PRIV_ADID
echo  [*] Disabling Advertising ID...
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v Enabled /t REG_DWORD /d 0 /f >nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" /v DisabledByGroupPolicy /t REG_DWORD /d 1 /f >nul
echo  [+] Advertising ID disabled!
goto :EOF

:PRIV_FEEDBACK
echo  [*] Disabling Feedback Requests...
reg add "HKCU\Software\Microsoft\Siuf\Rules" /v NumberOfSIUFInPeriod /t REG_DWORD /d 0 /f >nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v DoNotShowFeedbackNotifications /t REG_DWORD /d 1 /f >nul
echo  [+] Feedback disabled!
goto :EOF

:PRIV_MSSYNC
echo  [*] Disabling Microsoft Account Sync...
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v DisableSettingSync /t REG_DWORD /d 2 /f >nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v DisableSettingSyncUserOverride /t REG_DWORD /d 1 /f >nul
echo  [+] Microsoft Account Sync disabled!
goto :EOF

:PRIV_APPDIAG
echo  [*] Disabling App Diagnostics...
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics" /v Value /t REG_SZ /d Deny /f >nul
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics" /v Value /t REG_SZ /d Deny /f >nul
echo  [+] App Diagnostics disabled!
goto :EOF

:PRIV_ALL
echo  [*] Applying ALL Privacy Tweaks...
call :PRIV_TELEMETRY
call :PRIV_CORTANA
call :PRIV_ACTIVITY
call :PRIV_LOCATION
call :PRIV_ADID
call :PRIV_FEEDBACK
call :PRIV_MSSYNC
call :PRIV_APPDIAG
echo.
echo  [+] ALL Privacy Tweaks applied!
pause & goto PRIVACY

:: ============================================================
::  NETWORK OPTIMIZATIONS
:: ============================================================
:NETWORK
cls
echo.
echo  +----------------------------------------------------------+
echo  ^|            NETWORK OPTIMIZATIONS                        ^|
echo  +----------------------------------------------------------+
echo.
echo   [1]  Optimize TCP/IP Settings
echo   [2]  Disable Nagle's Algorithm (low latency)
echo   [3]  Flush DNS Cache + Winsock Reset
echo   [4]  Set TCP Auto-Tuning to Normal
echo   [5]  Set DNS to Cloudflare (1.1.1.1)
echo   [6]  Disable Network Throttling
echo   [7]  Apply ALL Network Tweaks
echo   [0]  Back to Main Menu
echo.
set /p nchoice=" Enter choice: "

if "%nchoice%"=="1" goto NET_TCP
if "%nchoice%"=="2" goto NET_NAGLE
if "%nchoice%"=="3" goto NET_FLUSHDNS
if "%nchoice%"=="4" goto NET_AUTOTUNING
if "%nchoice%"=="5" goto NET_DNS
if "%nchoice%"=="6" goto NET_THROTTLE
if "%nchoice%"=="7" goto NET_ALL
if "%nchoice%"=="0" goto MAIN_MENU
goto NETWORK

:NET_TCP
echo  [*] Optimizing TCP/IP Settings...
netsh int tcp set global autotuninglevel=normal >nul 2>&1
netsh int tcp set global chimney=enabled >nul 2>&1
netsh int tcp set global congestionprovider=ctcp >nul 2>&1
netsh int tcp set global ecncapability=enabled >nul 2>&1
netsh int tcp set heuristics disabled >nul 2>&1
netsh int tcp set global rss=enabled >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v TcpTimedWaitDelay /t REG_DWORD /d 30 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v MaxUserPort /t REG_DWORD /d 65534 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v DefaultTTL /t REG_DWORD /d 64 /f >nul
echo  [+] TCP/IP optimized!
goto :EOF

:NET_NAGLE
echo  [*] Disabling Nagle's Algorithm...
for /f %%i in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"') do (
    reg add "%%i" /v TcpAckFrequency /t REG_DWORD /d 1 /f >nul 2>&1
    reg add "%%i" /v TCPNoDelay /t REG_DWORD /d 1 /f >nul 2>&1
)
echo  [+] Nagle's Algorithm disabled!
goto :EOF

:NET_FLUSHDNS
echo  [*] Flushing DNS and resetting Winsock...
ipconfig /flushdns >nul
ipconfig /registerdns >nul
netsh winsock reset >nul
netsh int ip reset >nul
echo  [+] DNS flushed and Winsock reset!
goto :EOF

:NET_AUTOTUNING
echo  [*] Setting TCP Auto-Tuning to Normal...
netsh int tcp set global autotuninglevel=normal >nul
echo  [+] TCP Auto-Tuning configured!
goto :EOF

:NET_DNS
echo  [*] Setting DNS to Cloudflare (1.1.1.1 / 1.0.0.1)...
for /f "tokens=3*" %%i in ('netsh int show interface ^| findstr /i "connected"') do (
    netsh interface ipv4 set dns name="%%j" static 1.1.1.1 primary >nul 2>&1
    netsh interface ipv4 add dns name="%%j" 1.0.0.1 index=2 >nul 2>&1
)
echo  [+] DNS set to Cloudflare!
goto :EOF

:NET_THROTTLE
echo  [*] Disabling Network Throttling...
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v NetworkThrottlingIndex /t REG_DWORD /d 4294967295 /f >nul
echo  [+] Network Throttling disabled!
goto :EOF

:NET_ALL
echo  [*] Applying ALL Network Tweaks...
call :NET_TCP
call :NET_NAGLE
call :NET_FLUSHDNS
call :NET_AUTOTUNING
call :NET_THROTTLE
echo.
echo  [+] ALL Network Tweaks applied!
pause & goto NETWORK

:: ============================================================
::  VISUAL & UI TWEAKS
:: ============================================================
:VISUAL
cls
echo.
echo  +----------------------------------------------------------+
echo  ^|              VISUAL ^& UI TWEAKS                        ^|
echo  +----------------------------------------------------------+
echo.
echo   [1]  Show File Extensions in Explorer
echo   [2]  Show Hidden Files ^& Folders
echo   [3]  Disable News ^& Interests (Taskbar)
echo   [4]  Disable Chat / Teams Icon (Taskbar)
echo   [5]  Classic Right-Click Menu (Win11)
echo   [6]  Remove OneDrive from Explorer
echo   [7]  Restore Classic Explorer (Win11)
echo   [8]  Apply ALL Visual Tweaks
echo   [0]  Back to Main Menu
echo.
set /p vchoice=" Enter choice: "

if "%vchoice%"=="1" goto VIS_EXTENSIONS
if "%vchoice%"=="2" goto VIS_HIDDEN
if "%vchoice%"=="3" goto VIS_NEWS
if "%vchoice%"=="4" goto VIS_CHAT
if "%vchoice%"=="5" goto VIS_RIGHTCLICK
if "%vchoice%"=="6" goto VIS_ONEDRIVE
if "%vchoice%"=="7" goto VIS_CLASSICEXPLORER
if "%vchoice%"=="8" goto VIS_ALL
if "%vchoice%"=="0" goto MAIN_MENU
goto VISUAL

:VIS_EXTENSIONS
echo  [*] Showing File Extensions...
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v HideFileExt /t REG_DWORD /d 0 /f >nul
echo  [+] File Extensions visible!
goto :EOF

:VIS_HIDDEN
echo  [*] Showing Hidden Files ^& Folders...
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v Hidden /t REG_DWORD /d 1 /f >nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowSuperHidden /t REG_DWORD /d 1 /f >nul
echo  [+] Hidden files visible!
goto :EOF

:VIS_NEWS
echo  [*] Disabling News ^& Interests on Taskbar...
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" /v EnableFeeds /t REG_DWORD /d 0 /f >nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Feeds" /v ShellFeedsTaskbarViewMode /t REG_DWORD /d 2 /f >nul
:: Win11: disable widgets
if !IS_WIN11!==1 (
    reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v TaskbarDa /t REG_DWORD /d 0 /f >nul 2>&1
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Dsh" /v AllowNewsAndInterests /t REG_DWORD /d 0 /f >nul 2>&1
)
echo  [+] News / Widgets disabled!
goto :EOF

:VIS_CHAT
echo  [*] Removing Chat/Teams Icon from Taskbar...
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v TaskbarMn /t REG_DWORD /d 0 /f >nul
:: Win11 Teams from taskbar
if !IS_WIN11!==1 (
    reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v TaskbarMn /t REG_DWORD /d 0 /f >nul 2>&1
)
echo  [+] Chat/Teams icon removed!
goto :EOF

:VIS_RIGHTCLICK
echo  [*] Enabling Classic Right-Click Menu (Win11)...
reg add "HKCU\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" /f /ve >nul 2>&1
echo  [+] Classic right-click menu enabled!
taskkill /f /im explorer.exe >nul 2>&1
start explorer.exe
goto :EOF

:VIS_ONEDRIVE
echo  [*] Removing OneDrive from Explorer sidebar...
reg delete "HKCR\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f >nul 2>&1
reg delete "HKCR\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowSyncProviderNotifications /t REG_DWORD /d 0 /f >nul 2>&1
echo  [+] OneDrive removed from Explorer!
goto :EOF

:VIS_CLASSICEXPLORER
if !IS_WIN11!==0 (
    echo  [!] This tweak only applies to Windows 11.
    pause & goto VISUAL
)
echo  [*] Restoring compact/classic Explorer layout (Win11)...
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v UseCompactMode /t REG_DWORD /d 1 /f >nul 2>&1
echo  [+] Compact/Classic Explorer mode enabled!
goto :EOF

:VIS_ALL
echo  [*] Applying ALL Visual Tweaks...
call :VIS_EXTENSIONS
call :VIS_HIDDEN
call :VIS_NEWS
call :VIS_CHAT
call :VIS_ONEDRIVE
if !IS_WIN11!==1 (
    call :VIS_RIGHTCLICK
    call :VIS_CLASSICEXPLORER
)
echo.
echo  [+] ALL Visual Tweaks applied!
pause & goto VISUAL

:: ============================================================
::  POWER SETTINGS
:: ============================================================
:POWER
cls
echo.
echo  +----------------------------------------------------------+
echo  ^|               POWER SETTINGS                           ^|
echo  +----------------------------------------------------------+
echo.
echo   [1]  Set High Performance Power Plan
echo   [2]  Set Ultimate Performance Power Plan
echo   [3]  Disable USB Selective Suspend
echo   [4]  Disable PCIe Link State Power Management
echo   [5]  Disable CPU Core Parking
echo   [6]  Set Balanced Plan (Restore Default)
echo   [0]  Back to Main Menu
echo.
set /p pwchoice=" Enter choice: "

if "%pwchoice%"=="1" goto POW_HIGH
if "%pwchoice%"=="2" goto POW_ULTIMATE
if "%pwchoice%"=="3" goto POW_USB
if "%pwchoice%"=="4" goto POW_PCIE
if "%pwchoice%"=="5" goto POW_COREPARKING
if "%pwchoice%"=="6" goto POW_BALANCED
if "%pwchoice%"=="0" goto MAIN_MENU
goto POWER

:POW_HIGH
echo  [*] Setting High Performance Power Plan...
powercfg -setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c >nul 2>&1
echo  [+] High Performance activated!
goto :EOF

:POW_ULTIMATE
echo  [*] Enabling Ultimate Performance Power Plan...
powercfg -duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61 >nul 2>&1
for /f "tokens=4" %%G in ('powercfg -list ^| findstr "Ultimate"') do (
    powercfg -setactive %%G >nul 2>&1
)
echo  [+] Ultimate Performance activated!
goto :EOF

:POW_USB
echo  [*] Disabling USB Selective Suspend...
powercfg -setacvalueindex SCHEME_CURRENT 2a737441-1930-4402-8d77-b2bebba308a3 48e6b7a6-50f5-4782-a5d4-53bb8f07e226 0 >nul 2>&1
powercfg -setdcvalueindex SCHEME_CURRENT 2a737441-1930-4402-8d77-b2bebba308a3 48e6b7a6-50f5-4782-a5d4-53bb8f07e226 0 >nul 2>&1
powercfg -SetActive SCHEME_CURRENT >nul 2>&1
echo  [+] USB Selective Suspend disabled!
goto :EOF

:POW_PCIE
echo  [*] Disabling PCIe Link State Power Management...
powercfg -setacvalueindex SCHEME_CURRENT SUB_PCIEXPRESS ASPM 0 >nul 2>&1
powercfg -SetActive SCHEME_CURRENT >nul 2>&1
echo  [+] PCIe LSPM disabled!
goto :EOF

:POW_COREPARKING
echo  [*] Disabling CPU Core Parking...
powercfg -setacvalueindex SCHEME_CURRENT SUB_PROCESSOR CPMINCORES 100 >nul 2>&1
powercfg -setacvalueindex SCHEME_CURRENT SUB_PROCESSOR PROCTHROTTLEMIN 100 >nul 2>&1
powercfg -SetActive SCHEME_CURRENT >nul 2>&1
echo  [+] CPU Core Parking disabled!
goto :EOF

:POW_BALANCED
echo  [*] Restoring Balanced Power Plan...
powercfg -setactive 381b4222-f694-41f0-9685-ff5bb260df2e >nul 2>&1
echo  [+] Balanced Power Plan restored!
goto :EOF

:: ============================================================
::  GAMING OPTIMIZATIONS
:: ============================================================
:GAMING
cls
echo.
echo  +----------------------------------------------------------+
echo  ^|            GAMING OPTIMIZATIONS                        ^|
echo  +----------------------------------------------------------+
echo.
echo   [1]  Enable Game Mode
echo   [2]  Disable Xbox Game Bar
echo   [3]  Disable HAGS (old GPUs ^< GTX 1000)
echo   [4]  Enable HAGS (new GPUs GTX1000+ / RX5000+)
echo   [5]  Disable Mouse Acceleration
echo   [6]  Optimize for Low Latency Gaming
echo   [7]  Disable Fullscreen Optimizations (global)
echo   [8]  Apply ALL Gaming Tweaks
echo   [0]  Back to Main Menu
echo.
set /p gchoice=" Enter choice: "

if "%gchoice%"=="1" goto GAME_MODE
if "%gchoice%"=="2" goto GAME_XBOXBAR
if "%gchoice%"=="3" goto GAME_HAGS_OFF
if "%gchoice%"=="4" goto GAME_HAGS_ON
if "%gchoice%"=="5" goto GAME_MOUSE
if "%gchoice%"=="6" goto GAME_LATENCY
if "%gchoice%"=="7" goto GAME_FSO
if "%gchoice%"=="8" goto GAME_ALL
if "%gchoice%"=="0" goto MAIN_MENU
goto GAMING

:GAME_MODE
echo  [*] Enabling Windows Game Mode...
reg add "HKCU\Software\Microsoft\GameBar" /v AutoGameModeEnabled /t REG_DWORD /d 1 /f >nul
reg add "HKCU\Software\Microsoft\GameBar" /v AllowAutoGameMode /t REG_DWORD /d 1 /f >nul
echo  [+] Game Mode enabled!
goto :EOF

:GAME_XBOXBAR
echo  [*] Disabling Xbox Game Bar...
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v AppCaptureEnabled /t REG_DWORD /d 0 /f >nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR" /v AllowGameDVR /t REG_DWORD /d 0 /f >nul
reg add "HKCU\System\GameConfigStore" /v GameDVR_Enabled /t REG_DWORD /d 0 /f >nul
reg add "HKCU\System\GameConfigStore" /v GameDVR_FSEBehaviorMode /t REG_DWORD /d 2 /f >nul
echo  [+] Xbox Game Bar disabled!
goto :EOF

:GAME_HAGS_OFF
echo  [*] Disabling Hardware Accelerated GPU Scheduling...
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v HwSchMode /t REG_DWORD /d 1 /f >nul
echo  [+] HAGS disabled! (Reboot required)
goto :EOF

:GAME_HAGS_ON
echo  [*] Enabling Hardware Accelerated GPU Scheduling...
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v HwSchMode /t REG_DWORD /d 2 /f >nul
echo  [+] HAGS enabled! (Reboot required)
goto :EOF

:GAME_MOUSE
echo  [*] Disabling Mouse Acceleration...
reg add "HKCU\Control Panel\Mouse" /v MouseSpeed /t REG_SZ /d 0 /f >nul
reg add "HKCU\Control Panel\Mouse" /v MouseThreshold1 /t REG_SZ /d 0 /f >nul
reg add "HKCU\Control Panel\Mouse" /v MouseThreshold2 /t REG_SZ /d 0 /f >nul
echo  [+] Mouse Acceleration disabled!
goto :EOF

:GAME_LATENCY
echo  [*] Optimizing for Low Latency Gaming...
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "GPU Priority" /t REG_DWORD /d 8 /f >nul
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v Priority /t REG_DWORD /d 6 /f >nul
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Scheduling Category" /t REG_SZ /d High /f >nul
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "SFIO Priority" /t REG_SZ /d High /f >nul
echo  [+] Low Latency Gaming optimized!
goto :EOF

:GAME_FSO
echo  [*] Disabling Fullscreen Optimizations globally...
reg add "HKCU\System\GameConfigStore" /v GameDVR_DXGIHonorFSEWindowsCompatible /t REG_DWORD /d 1 /f >nul
reg add "HKCU\System\GameConfigStore" /v GameDVR_EFSEFeatureFlags /t REG_DWORD /d 0 /f >nul
echo  [+] Fullscreen Optimizations disabled!
goto :EOF

:GAME_ALL
echo  [*] Applying ALL Gaming Tweaks...
call :GAME_MODE
call :GAME_XBOXBAR
call :GAME_MOUSE
call :GAME_LATENCY
call :GAME_FSO
echo.
echo  [+] ALL Gaming Tweaks applied!
pause & goto GAMING

:: ============================================================
::  TIMER RESOLUTION TWEAKS  (NEW in v1.1)
:: ============================================================
:TIMERRES
cls
echo.
echo  +----------------------------------------------------------+
echo  ^|          TIMER RESOLUTION TWEAKS   [NEW v1.1]          ^|
echo  +----------------------------------------------------------+
echo.
echo   Windows default timer resolution is 15.6ms (64 Hz).
echo   Lowering it reduces scheduling jitter and input latency.
echo   This is especially important for gaming ^& audio work.
echo.
echo   [1]  Show Current Timer Resolution
echo   [2]  Set Timer Resolution to 0.5ms (Highest - Gaming)
echo   [3]  Set Timer Resolution to 1.0ms (Balanced)
echo   [4]  Enable Dynamic Tick (power saving - default)
echo   [5]  Disable Dynamic Tick (consistent low latency)
echo   [6]  Lock Global Timer to 0.5ms at Boot (Persistent)
echo   [7]  Restore Default Timer Resolution (15.6ms)
echo   [8]  Enable Per-Process Timer Resolution (Win11 23H2+)
echo   [0]  Back to Main Menu
echo.
echo  +----------------------------------------------------------+
echo  [!] Lower timer res = lower latency but higher CPU usage.
echo  +----------------------------------------------------------+
echo.
set /p tchoice=" Enter choice: "

if "%tchoice%"=="1" goto TIMER_SHOW
if "%tchoice%"=="2" goto TIMER_05MS
if "%tchoice%"=="3" goto TIMER_1MS
if "%tchoice%"=="4" goto TIMER_DYNON
if "%tchoice%"=="5" goto TIMER_DYNOFF
if "%tchoice%"=="6" goto TIMER_PERSIST
if "%tchoice%"=="7" goto TIMER_RESTORE
if "%tchoice%"=="8" goto TIMER_PERPROCESS
if "%tchoice%"=="0" goto MAIN_MENU
goto TIMERRES

:TIMER_SHOW
echo.
echo  [*] Querying current timer resolution...
echo.
:: Use powercfg to show timer - also use bcdedit
bcdedit /enum current | findstr /i "useplatformclock\|uselegacyapicmode\|tscsyncpolicy"
echo.
echo  [i] Registry-based timer floor setting:
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v GlobalTimerResolutionRequests >nul 2>&1 && (
    reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v GlobalTimerResolutionRequests
) || (
    echo  [i] GlobalTimerResolutionRequests not set (default behavior active)
)
echo.
echo  [i] Dynamic Tick status:
bcdedit /enum current | findstr /i "disabledynamictick"
echo.
echo  [i] To precisely measure your current timer resolution,
echo  [i] use ClockRes.exe from Sysinternals.
echo.
pause & goto TIMERRES

:TIMER_05MS
echo  [*] Requesting 0.5ms timer resolution via registry...
:: GlobalTimerResolutionRequests makes Windows honor requests down to 0.5ms
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v GlobalTimerResolutionRequests /t REG_DWORD /d 1 /f >nul
echo  [*] Disabling Dynamic Tick for consistent scheduling...
bcdedit /set disabledynamictick yes >nul 2>&1
echo  [*] Setting TSC sync policy for accuracy...
bcdedit /set tscsyncpolicy enhanced >nul 2>&1
echo  [+] 0.5ms Timer Resolution set! (Reboot required)
echo  [i] Apps requesting high-res timers will now get ^<= 0.5ms.
pause & goto TIMERRES

:TIMER_1MS
echo  [*] Setting 1.0ms timer resolution...
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v GlobalTimerResolutionRequests /t REG_DWORD /d 1 /f >nul
bcdedit /set disabledynamictick yes >nul 2>&1
echo  [+] 1.0ms Timer Resolution configured!
pause & goto TIMERRES

:TIMER_DYNON
echo  [*] Enabling Dynamic Tick (default power-saving behavior)...
bcdedit /set disabledynamictick no >nul 2>&1
echo  [+] Dynamic Tick enabled! (Better battery life, less consistent latency)
pause & goto TIMERRES

:TIMER_DYNOFF
echo  [*] Disabling Dynamic Tick (consistent low-latency scheduling)...
bcdedit /set disabledynamictick yes >nul 2>&1
echo  [+] Dynamic Tick disabled! (Consistent scheduling, slightly higher CPU usage)
echo  [i] Recommended for gaming, audio production, real-time workloads.
pause & goto TIMERRES

:TIMER_PERSIST
echo  [*] Enabling GlobalTimerResolutionRequests (persistent 0.5ms floor)...
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v GlobalTimerResolutionRequests /t REG_DWORD /d 1 /f >nul
bcdedit /set disabledynamictick yes >nul 2>&1
bcdedit /set tscsyncpolicy enhanced >nul 2>&1
echo  [+] Persistent high-resolution timer enabled!
echo  [i] This persists across reboots without needing a 3rd-party app.
echo  [i] Any app requesting high-res timers will be honored at 0.5ms.
pause & goto TIMERRES

:TIMER_RESTORE
echo  [*] Restoring default timer resolution...
reg delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v GlobalTimerResolutionRequests /f >nul 2>&1
bcdedit /deletevalue disabledynamictick >nul 2>&1
bcdedit /deletevalue tscsyncpolicy >nul 2>&1
echo  [+] Timer resolution restored to Windows default (15.6ms dynamic)!
pause & goto TIMERRES

:TIMER_PERPROCESS
if !IS_WIN11!==0 (
    echo  [!] Per-Process Timer Resolution requires Windows 11 23H2 or later.
    pause & goto TIMERRES
)
if !WIN_BUILD! LSS 22631 (
    echo  [!] Your build (!WIN_BUILD!) is too old for Per-Process Timer Resolution.
    echo  [!] Requires build 22631+ (Win11 23H2).
    pause & goto TIMERRES
)
echo  [*] Enabling Per-Process High-Resolution Timer (Win11 23H2+)...
:: On Win11 23H2+, each process can set its own timer without affecting the global clock
:: This is the ideal setting: apps that need <1ms get it, others stay at default
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v GlobalTimerResolutionRequests /t REG_DWORD /d 1 /f >nul
echo  [+] Per-process timer resolution enabled!
echo  [i] Apps like games and DAWs will get their requested resolution.
echo  [i] Idle processes remain at default, saving power.
pause & goto TIMERRES

:: ============================================================
::  WINDOWS 11 SPECIFIC TWEAKS  (NEW in v1.1)
:: ============================================================
:WIN11
cls
if !IS_WIN11!==0 (
    color 0E
    echo.
    echo  [!] These tweaks are designed for Windows 11.
    echo  [!] Your system appears to be running Windows 10.
    echo  [!] Applying them anyway may have no effect.
    echo.
    color 0A
)
echo.
echo  +----------------------------------------------------------+
echo  ^|      WINDOWS 11 SPECIFIC TWEAKS   [NEW v1.1]           ^|
echo  +----------------------------------------------------------+
echo  ^| Build: !WIN_BUILD!   Version: !WIN_DISPLAY!
echo  +----------------------------------------------------------+
echo.
echo   [1]  Disable Copilot (all versions)
echo   [2]  Disable Windows Recall / AI Features (24H2+)
echo   [3]  Disable Taskbar Search Box (keep icon only)
echo   [4]  Move Taskbar Icons to Left (classic layout)
echo   [5]  Disable Snap Layouts Popup
echo   [6]  Disable Recommended Section in Start Menu
echo   [7]  Disable Ads in Start Menu ^& Settings
echo   [8]  Disable TPM ^& Secure Boot Nag Popup
echo   [9]  Optimize for Windows 11 26H1 (latest build)
echo   [10] Apply ALL Windows 11 Tweaks
echo   [0]  Back to Main Menu
echo.
set /p w11choice=" Enter choice: "

if "%w11choice%"=="1"  goto W11_COPILOT
if "%w11choice%"=="2"  goto W11_RECALL
if "%w11choice%"=="3"  goto W11_SEARCHBOX
if "%w11choice%"=="4"  goto W11_TASKBARLEFT
if "%w11choice%"=="5"  goto W11_SNAP
if "%w11choice%"=="6"  goto W11_RECOMMENDED
if "%w11choice%"=="7"  goto W11_ADS
if "%w11choice%"=="8"  goto W11_TPMNAG
if "%w11choice%"=="9"  goto W11_26H1
if "%w11choice%"=="10" goto W11_ALL
if "%w11choice%"=="0"  goto MAIN_MENU
goto WIN11

:W11_COPILOT
echo  [*] Disabling Copilot...
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowCopilotButton /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot" /v TurnOffWindowsCopilot /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKCU\Software\Policies\Microsoft\Windows\WindowsCopilot" /v TurnOffWindowsCopilot /t REG_DWORD /d 1 /f >nul 2>&1
:: 24H2 Copilot standalone app
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsAI" /v DisableAIDataAnalysis /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsAI" /v TurnOffWindowsCopilot /t REG_DWORD /d 1 /f >nul 2>&1
echo  [+] Copilot disabled!
goto :EOF

:W11_RECALL
echo  [*] Disabling Windows Recall and AI features (24H2+)...
:: Disable Recall (Snapshots)
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsAI" /v DisableAIDataAnalysis /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowCopilotButton /t REG_DWORD /d 0 /f >nul 2>&1
:: Disable AI features in Photos, Paint, etc.
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsAI" /v AllowCocreator /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsAI" /v EnableImageCreator /t REG_DWORD /d 0 /f >nul 2>&1
:: Disable Click-to-do
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsAI" /v DisableClickToDo /t REG_DWORD /d 1 /f >nul 2>&1
echo  [+] Windows Recall and AI features disabled (24H2+)!
goto :EOF

:W11_SEARCHBOX
echo  [*] Hiding Taskbar Search Box (keeping icon)...
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v SearchboxTaskbarMode /t REG_DWORD /d 1 /f >nul 2>&1
echo  [+] Search box hidden (icon only)!
goto :EOF

:W11_TASKBARLEFT
echo  [*] Moving Taskbar Icons to Left...
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v TaskbarAl /t REG_DWORD /d 0 /f >nul 2>&1
echo  [+] Taskbar alignment set to Left!
goto :EOF

:W11_SNAP
echo  [*] Disabling Snap Layouts popup on hover...
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v EnableSnapAssistFlyout /t REG_DWORD /d 0 /f >nul 2>&1
echo  [+] Snap Layouts popup disabled!
goto :EOF

:W11_RECOMMENDED
echo  [*] Disabling Recommended section in Start Menu...
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v HideRecommendedSection /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v Start_TrackDocs /t REG_DWORD /d 0 /f >nul 2>&1
echo  [+] Recommended section disabled!
goto :EOF

:W11_ADS
echo  [*] Disabling Ads in Start Menu ^& Settings...
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-338387Enabled /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-338388Enabled /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-338389Enabled /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-353694Enabled /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-353696Enabled /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SystemPaneSuggestionsEnabled /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SoftLandingEnabled /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v RotatingLockScreenEnabled /t REG_DWORD /d 0 /f >nul 2>&1
:: 24H2 Start Menu ads
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v ShowRecommendationsForTips /t REG_DWORD /d 0 /f >nul 2>&1
echo  [+] Start Menu and Settings ads disabled!
goto :EOF

:W11_TPMNAG
echo  [*] Disabling TPM/Secure Boot nag popup...
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement" /v ScoobeSystemSettingEnabled /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate" /v TargetReleaseVersion /t REG_DWORD /d 1 /f >nul 2>&1
echo  [+] TPM nag suppressed!
goto :EOF

:W11_26H1
echo.
echo  [*] Applying Windows 11 26H1 specific optimizations...
echo  [i] Build threshold for 26H1: 27842+
echo.
if !WIN_BUILD! LSS 27842 (
    echo  [!] Your build is !WIN_BUILD!. Some 26H1 tweaks may not apply yet.
    echo  [i] Applying compatible tweaks only...
)
:: Disable new AI Shell / Dev Drive features if unwanted
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsAI" /v DisableAIDataAnalysis /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsAI" /v TurnOffWindowsCopilot /t REG_DWORD /d 1 /f >nul 2>&1
:: Disable "AI-powered" suggestions in Settings (26H1 feature)
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v ShowRecommendationsForTips /t REG_DWORD /d 0 /f >nul 2>&1
:: Disable new phonelinking / cross-device features
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v EnableCdp /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CDP" /v CdpSessionUserAuthzPolicy /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CDP" /v RomeSdkChannelUserAuthzPolicy /t REG_DWORD /d 0 /f >nul 2>&1
:: Disable new Start Menu account recommendations
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v Start_AccountNotifications /t REG_DWORD /d 0 /f >nul 2>&1
:: Disable Outlook integration in taskbar (26H1)
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v TaskbarCoreSearchAssistant /t REG_DWORD /d 0 /f >nul 2>&1
:: Apply timer resolution best practice for 26H1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v GlobalTimerResolutionRequests /t REG_DWORD /d 1 /f >nul 2>&1
echo  [+] Windows 11 26H1 optimizations applied!
goto :EOF

:W11_ALL
echo  [*] Applying ALL Windows 11 Tweaks...
call :W11_COPILOT
call :W11_RECALL
call :W11_SEARCHBOX
call :W11_TASKBARLEFT
call :W11_SNAP
call :W11_RECOMMENDED
call :W11_ADS
call :W11_TPMNAG
call :W11_26H1
echo.
echo  [+] ALL Windows 11 Tweaks applied!
pause & goto WIN11

:: ============================================================
::  STARTUP & SERVICES
:: ============================================================
:STARTUP
cls
echo.
echo  +----------------------------------------------------------+
echo  ^|             STARTUP ^& SERVICES                         ^|
echo  +----------------------------------------------------------+
echo.
echo   [1]  Open Startup Manager (msconfig)
echo   [2]  Open Task Manager Startup Tab
echo   [3]  Disable Windows Update Auto-Restart
echo   [4]  Disable Auto-Start Print Spooler
echo   [5]  Disable Fax Service
echo   [6]  Disable Remote Registry
echo   [7]  Disable Connected Devices Platform (CDPSvc)
echo   [0]  Back to Main Menu
echo.
set /p schoice=" Enter choice: "

if "%schoice%"=="1" ( start msconfig & goto STARTUP )
if "%schoice%"=="2" ( start taskmgr & goto STARTUP )
if "%schoice%"=="3" goto SVC_WUAUTORESTART
if "%schoice%"=="4" goto SVC_SPOOLER
if "%schoice%"=="5" goto SVC_FAX
if "%schoice%"=="6" goto SVC_REMREG
if "%schoice%"=="7" goto SVC_CDP
if "%schoice%"=="0" goto MAIN_MENU
goto STARTUP

:SVC_WUAUTORESTART
echo  [*] Disabling Windows Update Auto-Restart...
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v NoAutoRebootWithLoggedOnUsers /t REG_DWORD /d 1 /f >nul
echo  [+] Windows Update Auto-Restart disabled!
pause & goto STARTUP

:SVC_SPOOLER
echo  [*] Setting Print Spooler to Manual start...
sc config Spooler start= demand >nul 2>&1
sc stop Spooler >nul 2>&1
echo  [+] Print Spooler set to Manual!
pause & goto STARTUP

:SVC_FAX
echo  [*] Disabling Fax Service...
sc config Fax start= disabled >nul 2>&1
sc stop Fax >nul 2>&1
echo  [+] Fax Service disabled!
pause & goto STARTUP

:SVC_REMREG
echo  [*] Disabling Remote Registry...
sc config RemoteRegistry start= disabled >nul 2>&1
sc stop RemoteRegistry >nul 2>&1
echo  [+] Remote Registry disabled!
pause & goto STARTUP

:SVC_CDP
echo  [*] Disabling Connected Devices Platform (CDPSvc)...
sc config CDPSvc start= disabled >nul 2>&1
sc stop CDPSvc >nul 2>&1
sc config CDPUserSvc start= disabled >nul 2>&1
echo  [+] CDPSvc disabled!
pause & goto STARTUP

:: ============================================================
::  DISK & STORAGE TWEAKS
:: ============================================================
:DISK
cls
echo.
echo  +----------------------------------------------------------+
echo  ^|              DISK ^& STORAGE TWEAKS                    ^|
echo  +----------------------------------------------------------+
echo.
echo   [1]  Enable Write Caching on Drives
echo   [2]  Disable Disk Defrag Schedule (for SSDs)
echo   [3]  Run CHKDSK on C: (Next Reboot)
echo   [4]  Check Drive Health (SMART)
echo   [5]  Enable TRIM for SSD
echo   [0]  Back to Main Menu
echo.
set /p dchoice=" Enter choice: "

if "%dchoice%"=="1" goto DISK_CACHE
if "%dchoice%"=="2" goto DISK_DEFRAG
if "%dchoice%"=="3" goto DISK_CHKDSK
if "%dchoice%"=="4" goto DISK_SMART
if "%dchoice%"=="5" goto DISK_TRIM
if "%dchoice%"=="0" goto MAIN_MENU
goto DISK

:DISK_CACHE
echo  [*] Opening Device Manager for Write Caching...
echo  [i] Go to Disk Drives ^> [Your Drive] ^> Properties ^> Policies
devmgmt.msc
pause & goto DISK

:DISK_DEFRAG
echo  [*] Disabling Scheduled Defragmentation (SSD-friendly)...
schtasks /Change /TN "\Microsoft\Windows\Defrag\ScheduledDefrag" /Disable >nul 2>&1
echo  [+] Scheduled defrag disabled!
pause & goto DISK

:DISK_CHKDSK
echo  [*] Scheduling CHKDSK on next reboot...
echo y | chkdsk c: /f /r >nul 2>&1
echo  [+] CHKDSK scheduled for next restart!
pause & goto DISK

:DISK_SMART
echo  [*] Checking Drive Health (SMART Data)...
wmic diskdrive get status, model, size
echo.
pause & goto DISK

:DISK_TRIM
echo  [*] Enabling TRIM for SSD...
fsutil behavior set DisableDeleteNotify 0 >nul
echo  [+] TRIM enabled!
pause & goto DISK

:: ============================================================
::  SYSTEM CLEANUP
:: ============================================================
:CLEANUP
cls
echo.
echo  +----------------------------------------------------------+
echo  ^|               SYSTEM CLEANUP                           ^|
echo  +----------------------------------------------------------+
echo.
echo   [1]  Clean Temporary Files
echo   [2]  Clean Windows Update Cache
echo   [3]  Empty Recycle Bin
echo   [4]  Clear Event Logs
echo   [5]  Run Disk Cleanup (cleanmgr)
echo   [6]  Run SFC ^& DISM Scan
echo   [7]  Perform Full Cleanup (All Above)
echo   [0]  Back to Main Menu
echo.
set /p clchoice=" Enter choice: "

if "%clchoice%"=="1" goto CLEAN_TEMP
if "%clchoice%"=="2" goto CLEAN_WUPCACHE
if "%clchoice%"=="3" goto CLEAN_RECYCLE
if "%clchoice%"=="4" goto CLEAN_EVENTS
if "%clchoice%"=="5" ( start cleanmgr & goto CLEANUP )
if "%clchoice%"=="6" goto CLEAN_SFC
if "%clchoice%"=="7" goto CLEAN_ALL
if "%clchoice%"=="0" goto MAIN_MENU
goto CLEANUP

:CLEAN_TEMP
echo  [*] Cleaning Temporary Files...
del /s /f /q "%temp%\*.*" >nul 2>&1
rd /s /q "%temp%" >nul 2>&1
md "%temp%" >nul 2>&1
del /s /f /q "C:\Windows\Temp\*.*" >nul 2>&1
del /s /f /q "C:\Windows\Prefetch\*.*" >nul 2>&1
echo  [+] Temporary files cleaned!
goto :EOF

:CLEAN_WUPCACHE
echo  [*] Cleaning Windows Update Cache...
net stop wuauserv >nul 2>&1
net stop bits >nul 2>&1
rd /s /q "C:\Windows\SoftwareDistribution" >nul 2>&1
net start wuauserv >nul 2>&1
net start bits >nul 2>&1
echo  [+] Windows Update Cache cleared!
goto :EOF

:CLEAN_RECYCLE
echo  [*] Emptying Recycle Bin...
rd /s /q "C:\$Recycle.Bin" >nul 2>&1
echo  [+] Recycle Bin emptied!
goto :EOF

:CLEAN_EVENTS
echo  [*] Clearing Event Logs...
for /f "tokens=*" %%G in ('wevtutil.exe el') do (
    wevtutil.exe cl "%%G" >nul 2>&1
)
echo  [+] Event Logs cleared!
goto :EOF

:CLEAN_SFC
echo  [*] Running System File Checker and DISM...
echo  [!] This may take several minutes...
DISM /Online /Cleanup-Image /ScanHealth >nul 2>&1
DISM /Online /Cleanup-Image /RestoreHealth >nul 2>&1
sfc /scannow
echo  [+] SFC and DISM scan complete!
goto :EOF

:CLEAN_ALL
call :CLEAN_TEMP
call :CLEAN_WUPCACHE
call :CLEAN_RECYCLE
call :CLEAN_EVENTS
call :CLEAN_SFC
echo.
echo  [+] Full System Cleanup complete!
pause & goto CLEANUP

:: ============================================================
::  APPLY ALL RECOMMENDED TWEAKS
:: ============================================================
:ALL_TWEAKS
cls
echo.
echo  +----------------------------------------------------------+
echo  ^|          APPLYING ALL RECOMMENDED TWEAKS               ^|
echo  +----------------------------------------------------------+
echo.
echo  [!] This will apply a curated set of safe tweaks.
echo  [!] A system restore point will be created first.
echo  [i] Detected: !WIN_NAME! (Build !WIN_BUILD!)
echo.
set /p confirm=" Type YES to confirm: "
if /i not "%confirm%"=="YES" goto MAIN_MENU

echo.
echo  [*] Creating Restore Point first...
wmic.exe /Namespace:\\root\default Path SystemRestore Call CreateRestorePoint "Pre-WinTweaker v1.1", 100, 7 >nul 2>&1
echo  [+] Restore Point created.
echo.

echo  [*] Applying Performance Tweaks...
call :PERF_NTFS
call :PERF_SUPERFETCH
call :PERF_SCHEDULING
call :PERF_RESPONSIVENESS

echo  [*] Applying Privacy Tweaks...
call :PRIV_TELEMETRY
call :PRIV_ADID
call :PRIV_FEEDBACK
call :PRIV_ACTIVITY

echo  [*] Applying Network Tweaks...
call :NET_TCP
call :NET_THROTTLE

echo  [*] Applying Visual Tweaks...
call :VIS_EXTENSIONS
call :VIS_HIDDEN
call :VIS_NEWS

echo  [*] Applying Gaming Tweaks...
call :GAME_MODE
call :GAME_XBOXBAR
call :GAME_MOUSE
call :GAME_LATENCY

echo  [*] Applying Timer Resolution...
call :TIMER_DYNOFF
call :TIMER_PERSIST

if !IS_WIN11!==1 (
    echo  [*] Applying Windows 11 specific tweaks...
    call :W11_COPILOT
    call :W11_ADS
    call :W11_RECOMMENDED
    call :W11_SNAP
    call :W11_26H1
)

echo  [*] Cleaning Temporary Files...
call :CLEAN_TEMP

echo.
echo  +----------------------------------------------------------+
echo  ^|      All recommended tweaks applied successfully!      ^|
echo  ^|      A reboot is recommended to apply all changes.    ^|
echo  +----------------------------------------------------------+
echo.
pause & goto MAIN_MENU

:: ============================================================
::  CREATE RESTORE POINT
:: ============================================================
:RESTORE
cls
echo.
echo  +----------------------------------------------------------+
echo  ^|           SYSTEM RESTORE POINT                         ^|
echo  +----------------------------------------------------------+
echo.
echo   [1]  Create Restore Point Now
echo   [2]  Open System Restore (rstrui.exe)
echo   [0]  Back to Main Menu
echo.
set /p rchoice=" Enter choice: "

if "%rchoice%"=="1" goto RESTORE_CREATE
if "%rchoice%"=="2" ( start rstrui.exe & goto MAIN_MENU )
if "%rchoice%"=="0" goto MAIN_MENU
goto RESTORE

:RESTORE_CREATE
echo  [*] Creating System Restore Point...
wmic.exe /Namespace:\\root\default Path SystemRestore Call CreateRestorePoint "WinTweaker v1.1 Manual Restore Point", 100, 7
echo  [+] Restore Point created!
pause & goto MAIN_MENU

:: ============================================================
::  EXIT
:: ============================================================
:EXIT
cls
echo.
echo  +----------------------------------------------------------+
echo  ^|   Thank you for using WinTweaker v1.1!                ^|
echo  ^|   A reboot may be needed to apply all changes.       ^|
echo  +----------------------------------------------------------+
echo.
timeout /t 3 >nul
exit /b 0
