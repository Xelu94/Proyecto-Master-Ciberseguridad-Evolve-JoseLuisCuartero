@echo off
title CyberKB v3
cd /d "%~dp0"

echo.
echo  ================================================
echo   CyberKB v3 -- Iniciando servidor...
echo  ================================================
echo.

REM Verificar que .env existe
if not exist ".env" (
    echo [!] No se encontro .env — copiando desde .env.example
    copy .env.example .env
    echo [!] Edita .env y agrega tu ANTHROPIC_API_KEY antes de usar la IA
    echo.
)

REM Abrir navegador tras 2 segundos
start "" cmd /c "timeout /t 2 /nobreak >nul && start http://localhost:8000"

REM Lanzar servidor
python main.py

echo.
echo  Servidor detenido. Presiona cualquier tecla para cerrar.
pause >nul
