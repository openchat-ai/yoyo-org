@echo off
REM ============================================================
REM yoyo-asm bootstrap verification script
REM ============================================================
REM
REM Usage:
REM   build-and-run.cmd
REM
REM This script:
REM   1. Builds all 3 compilers (yoyo-asm, yoyo-js, yoyo-rust)
REM   2. Compiles the same minimal .ty input with all 3
REM   3. Compares structural equivalence of the 3 outputs
REM ============================================================

setlocal enabledelayedexpansion
set ROOT=%~dp0
set INPUT=%ROOT%test-h00-ret.ky
set COMPAREDIR=%ROOT%products

echo.
echo === Step 1: Build all 3 compilers ===
echo.

REM --- 1a. Build yoyo-asm (NASM + link) ---
echo [1a] Building yoyo-asm...
cd /d "%ROOT%compilers\yoyo-asm"
where nasm >nul 2>&1
if errorlevel 1 (
    echo ERROR: nasm not in PATH. Install NASM first.
    exit /b 1
)
where link >nul 2>&1
if errorlevel 1 (
    echo ERROR: MSVC link.exe not in PATH.
    exit /b 1
)
nasm -f win64 yoyo-asm.asm -o yoyo-asm.obj
if errorlevel 1 exit /b 1
link /nologo /entry:start /subsystem:console /libpath:"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64" /out:yoyo-asm.exe yoyo-asm.obj kernel32.lib
if errorlevel 1 exit /b 1
echo     Built: yoyo-asm.exe
copy /y yoyo-asm.exe "%ROOT%products\" >nul
copy /y "%INPUT%" "%ROOT%products\yoyo-asm-input.ky" >nul

REM --- 1b. Setup yoyo-js ---
echo [1b] Setting up yoyo-js...
cd /d "%ROOT%compilers\yoyo-js"
where node >nul 2>&1
if errorlevel 1 (
    echo ERROR: node.js not in PATH.
    exit /b 1
)
if not exist node_modules (
    echo     Installing yoyo-js dependencies (koffi)...
    call npm install
    if errorlevel 1 exit /b 1
)
echo     Ready: yoyo-js

REM --- 1c. Build yoyo-rust ---
echo [1c] Building yoyo-rust...
cd /d "%ROOT%compilers\yoyo-rust"
where cargo >nul 2>&1
if errorlevel 1 (
    echo ERROR: cargo not in PATH.
    exit /b 1
)
cargo build --release --manifest-path verifier/Cargo.toml
if errorlevel 1 exit /b 1
echo     Built: yoyo.exe
copy /y target\release\yoyo.exe "%ROOT%products\yoyo-rust-compiler.exe" >nul

echo.
echo === Step 2: Compile test input with all 3 compilers ===
echo.

if not exist "%COMPAREDIR%" mkdir "%COMPAREDIR%"

REM --- yoyo-asm ---
echo [2a] Running yoyo-asm...
cd /d "%ROOT%products"
copy /y yoyo-asm-input.ky input.ky >nul
yoyo-asm.exe
if errorlevel 1 (
    echo ERROR: yoyo-asm failed with exit code %errorlevel%
    exit /b 1
)
move /y output.exe yoyo-asm-output.exe >nul

REM --- yoyo-js ---
echo [2b] Running yoyo-js...
cd /d "%ROOT%products"
node "%ROOT%compilers\yoyo-js\src\yoyo.js" --target=win --output=yoyo-js-output.exe "%INPUT%"
if errorlevel 1 (
    echo ERROR: yoyo-js failed with exit code %errorlevel%
    exit /b 1
)

REM --- yoyo-rust ---
echo [2c] Running yoyo-rust...
cd /d "%ROOT%products"
yoyo-rust-compiler.exe link "%INPUT%" yoyo-rust-output.exe --platform win32
if errorlevel 1 (
    echo ERROR: yoyo-rust failed with exit code %errorlevel%
    exit /b 1
)

echo.
echo === Step 3: Compare products ===
echo.

echo Product sizes:
for %%f in (yoyo-asm-output.exe yoyo-js-output.exe yoyo-rust-output.exe) do (
    if exist %%f (
        for %%s in (%%f) do echo     %%f : %%~zs bytes
    )
)
echo.
echo SHA-256 hashes:
for %%f in (yoyo-asm-output.exe yoyo-js-output.exe yoyo-rust-output.exe) do (
    if exist %%f (
        certutil -hashfile %%f SHA256 | findstr /v "hash certutil" > nul
        echo     %%f : 
        certutil -hashfile %%f SHA256 | findstr /v "CertUtil"
    )
)
echo.
echo === Done ===
echo Compare results with REPORT.md to verify Trusting Trust.
endlocal