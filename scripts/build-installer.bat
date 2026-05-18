@echo off
setlocal EnableDelayedExpansion

:: ============================================================================
::  TIME Coin Wallet - Build Installer
::
::  Builds the wallet and packages it into a Windows installer using Inno Setup.
::
::  Prerequisites:
::    - Rust toolchain (cargo)
::    - Inno Setup 6 (https://jrsoftware.org/isdl.php)
::
::  Usage:  scripts\build-installer.bat
:: ============================================================================

echo.
echo ============================================
echo   TIME Coin Wallet - Installer Builder
echo ============================================
echo.

set "REPO_ROOT=%~dp0.."
set "ISCC="

:: ── Find Inno Setup compiler ────────────────────────────────────────────────
echo -- Locating Inno Setup compiler...

where iscc >nul 2>&1
if %errorlevel% equ 0 (
    set "ISCC=iscc"
) else (
    if exist "%ProgramFiles(x86)%\Inno Setup 6\ISCC.exe" (
        set "ISCC=%ProgramFiles(x86)%\Inno Setup 6\ISCC.exe"
    )
    if exist "%ProgramFiles%\Inno Setup 6\ISCC.exe" (
        set "ISCC=%ProgramFiles%\Inno Setup 6\ISCC.exe"
    )
)

if "!ISCC!"=="" (
    echo [ERROR] Inno Setup 6 not found.
    echo         Install from https://jrsoftware.org/isdl.php
    echo.
    pause
    exit /b 1
)
echo [OK] Found Inno Setup.

:: ── Build the wallet ────────────────────────────────────────────────────────
echo.
echo -- Building wallet in release mode...
echo    This may take several minutes.
echo.

pushd "%REPO_ROOT%"
cargo build --release
if %errorlevel% neq 0 (
    echo.
    echo [ERROR] Build failed. See output above.
    popd
    pause
    exit /b 1
)
popd
echo.
echo [OK] Build succeeded.

:: ── Convert PNG icon to ICO (if needed) ─────────────────────────────────────
echo.
echo -- Preparing icon...

set "ICO_FILE=%REPO_ROOT%\wallet-gui\assets\logo.ico"
set "PNG_FILE=%REPO_ROOT%\wallet-gui\assets\logo.png"

if not exist "!ICO_FILE!" (
    if exist "!PNG_FILE!" (
        echo    Converting logo.png to logo.ico...
        powershell -NoProfile -Command ^
            "Add-Type -AssemblyName System.Drawing;" ^
            "$png = New-Object System.Drawing.Bitmap('%PNG_FILE%');" ^
            "$sizes = @(16,32,48,256);" ^
            "$images = @();" ^
            "foreach ($s in $sizes) {" ^
            "    $bmp = New-Object System.Drawing.Bitmap($s,$s);" ^
            "    $g = [System.Drawing.Graphics]::FromImage($bmp);" ^
            "    $g.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic;" ^
            "    $g.DrawImage($png,0,0,$s,$s); $g.Dispose();" ^
            "    $ms = New-Object System.IO.MemoryStream;" ^
            "    $bmp.Save($ms,[System.Drawing.Imaging.ImageFormat]::Png);" ^
            "    $images += ,($ms.ToArray()); $ms.Dispose(); $bmp.Dispose();" ^
            "};" ^
            "$png.Dispose();" ^
            "$wr = New-Object System.IO.BinaryWriter([System.IO.File]::Create('%ICO_FILE%'));" ^
            "$wr.Write([uint16]0); $wr.Write([uint16]1); $wr.Write([uint16]$sizes.Count);" ^
            "$off = 6 + $sizes.Count * 16;" ^
            "for ($i=0;$i -lt $sizes.Count;$i++) {" ^
            "    $d=$sizes[$i]; $dim=if($d-eq 256){0}else{$d};" ^
            "    $wr.Write([byte]$dim);$wr.Write([byte]$dim);$wr.Write([byte]0);$wr.Write([byte]0);" ^
            "    $wr.Write([uint16]1);$wr.Write([uint16]32);" ^
            "    $wr.Write([uint32]$images[$i].Length);$wr.Write([uint32]$off);" ^
            "    $off+=$images[$i].Length;" ^
            "};" ^
            "foreach ($img in $images){$wr.Write($img)};" ^
            "$wr.Close()"
        if exist "!ICO_FILE!" (
            echo [OK] Created logo.ico
        ) else (
            echo [WARN] Could not convert icon. Installer will use default icon.
        )
    )
)
if exist "!ICO_FILE!" (
    echo [OK] Icon ready.
)

:: ── Create output directory ─────────────────────────────────────────────────
if not exist "%REPO_ROOT%\installer" mkdir "%REPO_ROOT%\installer"

:: ── Compile installer ───────────────────────────────────────────────────────
echo.
echo -- Compiling installer...
echo.

"!ISCC!" "%REPO_ROOT%\scripts\installer.iss"
if %errorlevel% neq 0 (
    echo.
    echo [ERROR] Installer compilation failed.
    pause
    exit /b 1
)

echo.
echo ============================================
echo   Installer built successfully!
echo ============================================
echo.
echo   Output: installer\TIMECoinWallet-Setup-0.6.7.exe
echo.
pause
exit /b 0
