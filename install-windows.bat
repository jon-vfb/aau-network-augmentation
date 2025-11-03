@echo off
echo Installing AAU Network Augmentation Tool dependencies for Windows...
echo.

echo Checking Python installation...
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python is not installed or not in PATH
    echo Please install Python 3.7+ from https://python.org
    pause
    exit /b 1
)

echo Python found. Installing dependencies...
python -m pip install --upgrade pip
python -m pip install -r requirements-windows.txt

if errorlevel 1 (
    echo.
    echo ERROR: Failed to install dependencies
    echo Please check your internet connection and try again
    pause
    exit /b 1
)

echo.
echo ✓ Installation completed successfully!
echo.
echo You can now run the application with:
echo   python main.py
echo.
echo Press any key to exit...
pause >nul