@echo off
title CyberKB — Build EXE
cd /d "%~dp0"

echo.
echo  ================================================
echo   CyberKB v3 -- Compilando ejecutable...
echo  ================================================
echo.

REM Install PyInstaller if needed
pip show pyinstaller >nul 2>&1
if errorlevel 1 (
    echo [*] Instalando PyInstaller...
    pip install pyinstaller
)

REM Clean previous build
if exist "build" rmdir /s /q "build"
if exist "dist\CyberKB.exe" del /f "dist\CyberKB.exe"

echo [*] Compilando con PyInstaller...
pyinstaller cyberkb.spec --noconfirm

if errorlevel 1 (
    echo.
    echo [ERROR] La compilacion fallo. Revisa los mensajes arriba.
    pause
    exit /b 1
)

echo.
echo  ================================================
echo   BUILD COMPLETADO
echo   Ejecutable: dist\CyberKB.exe
echo.
echo   Para distribuir, copia junto al exe:
echo     - .env  (con tu ANTHROPIC_API_KEY)
echo   El exe crea data\ y uploads\ automaticamente.
echo  ================================================
echo.
pause
