@echo off
rem Build ps4ufs_gui.exe (and the ps4ufs.exe CLI) with MSVC x64.
setlocal
if not defined VCINSTALLDIR call "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat" >nul || exit /b 1
cd /d "%~dp0"
rc /nologo ps4ufs_gui.rc || exit /b 1
cl /nologo /O2 /W3 ps4ufs_gui.c ps4ufs_gui.res /Fe:ps4ufs_gui.exe /link /SUBSYSTEM:WINDOWS /MANIFEST:NO || exit /b 1
if "%1"=="cli" cl /nologo /O2 /W3 ps4ufs.c /Fe:ps4ufs.exe || exit /b 1
del /q *.obj *.res 2>nul
