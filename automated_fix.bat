@echo off
setlocal

REM Check if _resources folder exists in current directory
if exist "_resources" (
    echo Found _resources folder in current directory
    echo Running Python scripts...
    echo.
    
    REM Get the directory where this batch script is located
    set "SCRIPT_DIR=%~dp0"
    
    REM Run the first Python script
    echo Running fix_joplin_toc.py...
    python "%SCRIPT_DIR%fix_joplin_toc.py"
    if errorlevel 1 (
        echo Error: fix_joplin_toc.py failed with error code %errorlevel%
        exit /b %errorlevel%
    )
    echo.
    
    REM Run the second Python script
    echo Running fix_paths.py...
    python "%SCRIPT_DIR%fix_paths.py"
    if errorlevel 1 (
        echo Error: fix_paths.py failed with error code %errorlevel%
        exit /b %errorlevel%
    )
    echo.
    
    echo Both scripts completed successfully!
) else (
    echo _resources folder not found in current directory
    echo Current directory: %CD%
    exit /b 1
)

endlocal