@echo off
REM Build script for PE Packer
REM Requires Visual Studio or MinGW

echo Building PE Packer...
echo.

REM Check for Visual Studio
where cl >nul 2>&1
if %ERRORLEVEL% == 0 (
    echo Using MSVC compiler...
    goto :build_msvc
)

REM Check for MinGW
where gcc >nul 2>&1
if %ERRORLEVEL% == 0 (
    echo Using MinGW GCC compiler...
    goto :build_mingw
)

echo Error: No C compiler found. Please install Visual Studio or MinGW.
exit /b 1

:build_msvc
REM Build with MSVC
if not exist build mkdir build
cd build

REM Build validator DLL
cl /c /LD ..\src\validator\validator.c /Fovalidator.obj
cl /c /LD ..\src\validator\dllmain.c /Fodllmain.obj
link /DLL validator.obj dllmain.obj user32.lib /OUT:validator.dll

REM Build packer
cl /c ..\src\packer\main.c /Fomain.obj
cl /c ..\src\packer\pe_parser.c /Fope_parser.obj
cl /c ..\src\packer\overlay.c /Fooverlay.obj
link main.obj pe_parser.obj overlay.obj /OUT:packer.exe

cd ..
echo.
echo Build complete!
echo Output files:
echo   build\validator.dll
echo   build\packer.exe
goto :end

:build_mingw
REM Build with MinGW
if not exist build mkdir build
cd build

REM Build validator DLL
gcc -c -shared ../src/validator/validator.c -o validator.o
gcc -c -shared ../src/validator/dllmain.c -o dllmain.o
gcc -shared validator.o dllmain.o -o validator.dll -luser32

REM Build packer
gcc -c ../src/packer/main.c -o main.o
gcc -c ../src/packer/pe_parser.c -o pe_parser.o
gcc -c ../src/packer/overlay.c -o overlay.o
gcc main.o pe_parser.o overlay.o -o packer.exe

cd ..
echo.
echo Build complete!
echo Output files:
echo   build\validator.dll
echo   build\packer.exe
goto :end

:end
echo.
echo Usage: packer.exe -in app.exe -out packed.exe -appid 450
