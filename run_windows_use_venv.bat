@echo off
echo Activating virtual environment and running the application...

REM Change to the directory where this script is located
cd /d "%~dp0"

REM Activate the virtual environment
call .\.venv\Scripts\activate.bat

REM Run the Python script 
echo Starting the Python application with 'run' command and arguments: %*
python -m gemini_cli_openaiapi_proxy run %*
echo Application has finished.
pause
