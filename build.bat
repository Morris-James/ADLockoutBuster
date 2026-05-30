@echo off
echo ===================================================
echo  ADLockoutBuster - Portable EXE Builder
echo  Techify
echo ===================================================
echo.

REM Check Python is available
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python not found. Install Python 3.10+ and try again.
    pause
    exit /b 1
)

REM Install dependencies
echo Installing dependencies...
pip install PyQt6 pyinstaller --quiet

echo.
echo Building portable executable...
echo.

pyinstaller ^
    --onefile ^
    --windowed ^
    --name "ADLockoutBuster" ^
    --icon "ADLockoutBuster.ico" ^
    --add-data "ADLockoutBuster.ico;." ^
    --hidden-import PyQt6 ^
    --hidden-import PyQt6.QtWidgets ^
    --hidden-import PyQt6.QtCore ^
    --hidden-import PyQt6.QtGui ^
    lockout_finder.py

echo.
if exist "dist\ADLockoutBuster.exe" (
    echo ===================================================
    echo  BUILD SUCCESSFUL!
    echo  Output: dist\ADLockoutBuster.exe
    echo  Copy this single file anywhere - no install needed.
    echo ===================================================
) else (
    echo BUILD FAILED. Check the output above for errors.
)

pause
