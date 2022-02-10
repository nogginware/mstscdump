@SETLOCAL

@if "%VCINSTALLDIR%" == "" set VCINSTALLDIR=C:\Program Files (x86)\Microsoft Visual Studio\2017\Professional\VC

@set USE_DETOURS=1

@if not exist bin mkdir bin
@if not exist bin\x86 mkdir bin\x86
@if not exist bin\x64 mkdir bin\x64

@del /q bin\x86\*.*
@del /q bin\x64\*.*

@echo !== Building MSTSCDUMP.EXE and MSTSCHOOK.DLL (32-bit)...
@call "%VCINSTALLDIR%\Auxiliary\Build\vcvarsall.bat" x86
@set
@nmake /nologo clean all -f Makefile CFG="Release32" USE_DETOURS=%USE_DETOURS% || goto ERROR_EXIT
@copy mstscdump.exe bin\x86 || goto ERROR_EXIT
@copy mstschook.dll bin\x86 || goto ERROR_EXIT
@copy test.exe bin\x86 || goto ERROR_EXIT
@nmake /nologo clean -f Makefile CFG="Release32" USE_DETOURS=%USE_DETOURS% || goto ERROR_EXIT

@SETLOCAL

@echo !== Building MSTSCDUMP.EXE and MSTSCHOOK.DLL (64-bit)...
@call "%VCINSTALLDIR%\Auxiliary\Build\vcvarsall.bat" x64
@nmake /nologo clean all -f Makefile CFG="Release64" USE_DETOURS=%USE_DETOURS% || goto ERROR_EXIT
@copy mstscdump.exe bin\x64 || goto ERROR_EXIT
@copy mstschook.dll bin\x64 || goto ERROR_EXIT
@copy test.exe bin\x64 || goto ERROR_EXIT
@nmake /nologo clean -f Makefile CFG="Release64" USE_DETOURS=%USE_DETOURS% || goto ERROR_EXIT

@ENDLOCAL

:ERROR_EXIT
@ENDLOCAL
exit /b %ERRORLEVEL%