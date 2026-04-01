#Requires -Version 5.1
<#
.SYNOPSIS
    Install fbd (Fistbump full node) on Windows.

.DESCRIPTION
    Downloads Swift, installs Visual Studio Build Tools if needed,
    builds fbd in release mode, and installs the binaries.

.PARAMETER Prefix
    Installation directory for binaries (default: C:\Program Files\fbd).

.PARAMETER SwiftVersion
    Swift version to install (default: 6.2.3).

.PARAMETER DepsOnly
    Install dependencies and Swift only, skip build.

.PARAMETER SkipSwift
    Skip Swift installation (already installed).

.EXAMPLE
    .\Install\windows.ps1
    .\Install\windows.ps1 -Prefix "$env:USERPROFILE\bin"
    .\Install\windows.ps1 -DepsOnly
#>

param(
    [string]$Prefix = "$env:ProgramFiles\fbd",
    [string]$SwiftVersion = "6.2.3",
    [switch]$DepsOnly,
    [switch]$SkipSwift,
    [switch]$Help
)

$ErrorActionPreference = "Stop"

# -- Helpers ----------------------------------------------------------

function Info($msg)  { Write-Host "==> $msg" -ForegroundColor Cyan }
function Ok($msg)    { Write-Host " ok $msg" -ForegroundColor Green }
function Err($msg)   { Write-Host "error: $msg" -ForegroundColor Red }
function Die($msg)   { Err $msg; exit 1 }

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($id)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-Command($cmd) {
    $null = Get-Command $cmd -ErrorAction SilentlyContinue
    return $?
}

# -- Help -------------------------------------------------------------

if ($Help) {
    Write-Host ""
    Write-Host "Usage: .\Install\windows.ps1 [options]"
    Write-Host ""
    Write-Host "Options:"
    Write-Host "  -Prefix DIR        Install binaries to DIR (default: C:\Program Files\fbd)"
    Write-Host "  -SwiftVersion VER  Swift version to install (default: $SwiftVersion)"
    Write-Host "  -DepsOnly          Install dependencies and Swift only, skip build"
    Write-Host "  -SkipSwift         Skip Swift installation (already installed)"
    Write-Host "  -Help              Show this help"
    Write-Host ""
    exit 0
}

# -- Pre-flight -------------------------------------------------------

Write-Host ""
Write-Host "fbd installer (Windows)" -ForegroundColor White
Write-Host ""

$script:Arch = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture
if ($script:Arch -ne "X64" -and $script:Arch -ne "Arm64") {
    Die "unsupported architecture: $script:Arch (need x64 or arm64)"
}

# -- Visual Studio Build Tools ----------------------------------------

function Install-VSBuildTools {
    # Check if VS Build Tools or full VS is already installed with C++ workload
    $vsWhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    if (Test-Path $vsWhere) {
        $inst = & $vsWhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
        if ($inst) {
            Ok "Visual Studio C++ tools found: $inst"
            return
        }
    }

    Info "Installing Visual Studio Build Tools (C++ workload)..."
    Write-Host "  This may take several minutes on first install."

    # Try winget first
    if (Test-Command winget) {
        Info "Installing via winget..."
        winget install --id Microsoft.VisualStudio.2022.BuildTools `
            --override "--quiet --wait --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended" `
            --accept-source-agreements --accept-package-agreements
        if ($LASTEXITCODE -eq 0) {
            Ok "Visual Studio Build Tools installed"
            return
        }
        Write-Host "  winget install returned code $LASTEXITCODE, trying direct download..." -ForegroundColor Yellow
    }

    # Direct download fallback
    $vsUrl = "https://aka.ms/vs/17/release/vs_buildtools.exe"
    $vsInstaller = "$env:TEMP\vs_buildtools.exe"
    Info "Downloading Visual Studio Build Tools..."
    Invoke-WebRequest -Uri $vsUrl -OutFile $vsInstaller -UseBasicParsing

    Start-Process -FilePath $vsInstaller -ArgumentList `
        "--quiet", "--wait", "--norestart",
        "--add", "Microsoft.VisualStudio.Workload.VCTools",
        "--includeRecommended" `
        -Wait -NoNewWindow

    Remove-Item $vsInstaller -ErrorAction SilentlyContinue
    Ok "Visual Studio Build Tools installed"
}

# -- Swift ------------------------------------------------------------

function Install-Swift {
    # Check if Swift is already installed and correct version
    if (Test-Command swift) {
        $currentOutput = & swift --version 2>&1 | Select-Object -First 1
        if ($currentOutput -match "(\d+\.\d+(\.\d+)?)") {
            $current = $Matches[1]
            if ($current -eq $SwiftVersion) {
                Ok "Swift $SwiftVersion already installed"
                return
            }
            Info "Found Swift $current, installing $SwiftVersion..."
        }
    }

    # Try winget first
    if (Test-Command winget) {
        Info "Installing Swift $SwiftVersion via winget..."
        winget install --id Swift.Toolchain --version $SwiftVersion `
            --accept-source-agreements --accept-package-agreements
        if ($LASTEXITCODE -eq 0) {
            # Refresh PATH for this session
            Refresh-Path
            Ok "Swift $SwiftVersion installed via winget"
            return
        }
        Write-Host "  winget install returned code $LASTEXITCODE, trying direct download..." -ForegroundColor Yellow
    }

    # Direct download from swift.org
    $swiftTag = "swift-${SwiftVersion}-RELEASE"
    if ($script:Arch -eq "Arm64") {
        $filename = "${swiftTag}-windows10-arm64.exe"
        $platform = "windows10-arm64"
    } else {
        $filename = "${swiftTag}-windows10.exe"
        $platform = "windows10"
    }
    $url = "https://download.swift.org/swift-${SwiftVersion}-release/${platform}/${swiftTag}/${filename}"

    Info "Downloading Swift $SwiftVersion..."
    Write-Host "  $url"

    $installer = "$env:TEMP\$filename"
    Invoke-WebRequest -Uri $url -OutFile $installer -UseBasicParsing

    Info "Running Swift installer..."
    Start-Process -FilePath $installer -ArgumentList "/quiet" -Wait -NoNewWindow
    Remove-Item $installer -ErrorAction SilentlyContinue

    # Refresh PATH for this session
    Refresh-Path

    if (-not (Test-Command swift)) {
        Die "Swift installation completed but 'swift' not found in PATH. You may need to restart your terminal."
    }

    Ok "Swift $(& swift --version 2>&1 | Select-Object -First 1)"
}

function Refresh-Path {
    # Reload PATH from registry so newly installed tools are visible
    $machinePath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    $env:Path = "$machinePath;$userPath"
}

# -- PATH helper ------------------------------------------------------

function Add-ToUserPath($dir) {
    $current = [Environment]::GetEnvironmentVariable('Path', 'User')
    if ($current -like ('*' + $dir + '*')) { return }
    $updated = $current + ';' + $dir
    [Environment]::SetEnvironmentVariable('Path', $updated, 'User')
    $env:Path = $env:Path + ';' + $dir
    Info ('Added ' + $dir + ' to user PATH')
}

# -- Build ------------------------------------------------------------

function Build-Shd {
    # Find repo root (use $PSScriptRoot captured at top level)
    $scriptDir = $script:ScriptDir
    $repoDir = Split-Path -Parent $scriptDir
    if (-not $scriptDir) {
        $repoDir = (Get-Location).Path
    }

    if (-not (Test-Path "$repoDir\Package.swift")) {
        Die "Cannot find Package.swift - run this script from the fbd repository"
    }

    # Generate BuildInfo.swift with git hash
    $buildInfoPath = "$repoDir\Sources\Base\BuildInfo.swift"
    $hash = "unknown"
    if (Test-Command git) {
        try {
            $h = & git -C $repoDir rev-parse --short=7 HEAD 2>$null
            if ($LASTEXITCODE -eq 0 -and $h) {
                $hash = $h.Trim()
                $dirty = & git -C $repoDir diff --quiet HEAD -- 2>$null
                if ($LASTEXITCODE -ne 0) { $hash = "$hash-dirty" }
            }
        } catch {}
    }
    Set-Content -Path $buildInfoPath -Value "/// Auto-generated at build time - do not edit.`nlet _buildHash: String = `"$hash`"" -Encoding UTF8

    Info "Building fbd (release)..."
    Push-Location $repoDir

    try {
        # Set up VS developer environment if not already set
        Setup-VsDevEnv

        $buildLog = "$repoDir\.build\build.log"
        New-Item -ItemType Directory -Path "$repoDir\.build" -Force | Out-Null

        $process = Start-Process -FilePath "swift" -ArgumentList "build", "-c", "release" `
            -NoNewWindow -Wait -PassThru `
            -RedirectStandardOutput $buildLog `
            -RedirectStandardError "$repoDir\.build\build.err.log"

        # Merge stderr into log
        if (Test-Path "$repoDir\.build\build.err.log") {
            Get-Content "$repoDir\.build\build.err.log" | Add-Content $buildLog
            Remove-Item "$repoDir\.build\build.err.log" -ErrorAction SilentlyContinue
        }

        # Show last few progress lines
        if (Test-Path $buildLog) {
            Get-Content $buildLog | Select-String -Pattern "^(Build |\[|Linking )" | Select-Object -Last 5 | ForEach-Object { Write-Host $_.Line }
        }

        if ($process.ExitCode -ne 0) {
            Write-Host ""
            Err "Build failed. Last 40 lines:"
            Write-Host ""
            if (Test-Path $buildLog) {
                Get-Content $buildLog | Select-Object -Last 40 | ForEach-Object { Write-Host $_ }
            }
            Write-Host ""
            Die "Full log: $buildLog"
        }

        # Find the build output directory (varies by platform triple)
        $buildDir = "$repoDir\.build\release"
        if (-not (Test-Path "$buildDir\fbd.exe")) {
            # Try platform-specific path (e.g. .build\x86_64-unknown-windows-msvc\release)
            $tripleDir = Get-ChildItem "$repoDir\.build" -Directory | Where-Object {
                $_.Name -match "windows" -and (Test-Path "$($_.FullName)\release\fbd.exe")
            } | Select-Object -First 1
            if ($tripleDir) {
                $buildDir = "$($tripleDir.FullName)\release"
            }
        }
        if (-not (Test-Path "$buildDir\fbd.exe") -or -not (Test-Path "$buildDir\fbdctl.exe")) {
            Die "Build succeeded but fbd.exe or fbdctl.exe not found in $buildDir"
        }

        Ok "Build complete"

        # Install binaries
        Info "Installing to $Prefix..."
        New-Item -ItemType Directory -Path $Prefix -Force | Out-Null

        Copy-Item "$buildDir\fbd.exe" "$Prefix\fbd.exe" -Force
        Copy-Item "$buildDir\fbdctl.exe" "$Prefix\fbdctl.exe" -Force

        Ok "fbd.exe    -> $Prefix\fbd.exe"
        Ok "fbdctl.exe -> $Prefix\fbdctl.exe"

        # Add to user PATH if not already there
        Add-ToUserPath $Prefix
    } finally {
        Pop-Location
    }
}

function Setup-VsDevEnv {
    # If cl.exe is already in PATH, dev env is set up
    if (Test-Command cl) { return }

    $vsWhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    if (-not (Test-Path $vsWhere)) { return }

    $installPath = & $vsWhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    if (-not $installPath) { return }

    $vcvarsall = "$installPath\VC\Auxiliary\Build\vcvarsall.bat"
    if (-not (Test-Path $vcvarsall)) { return }

    # Pick the right target architecture
    $vsArch = 'x64'
    if ($script:Arch -eq 'Arm64') { $vsArch = 'arm64' }

    Info "Setting up Visual Studio developer environment ($vsArch)..."

    # Run vcvarsall.bat and capture the resulting environment
    $batFile = [System.IO.Path]::GetTempFileName() + ".bat"
    Set-Content -Path $batFile -Value "@call `"$vcvarsall`" $vsArch >nul 2>&1`r`nset" -Encoding ASCII
    $output = cmd /c $batFile
    Remove-Item $batFile -ErrorAction SilentlyContinue
    $regex = '^(.+?)=(.*)$'
    foreach ($line in $output) {
        if ($line -match $regex) {
            [Environment]::SetEnvironmentVariable($Matches[1], $Matches[2], 'Process')
        }
    }
    Ok "Developer environment configured"
}

# -- Main -------------------------------------------------------------

# Capture script directory at top level (not available inside functions)
$script:ScriptDir = $PSScriptRoot
if (-not $script:ScriptDir) {
    $script:ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
}

# Check for admin (needed for VS Build Tools and Program Files install)
$isAdmin = Test-Admin
if (-not $isAdmin) {
    $defaultPrefix = "$env:ProgramFiles\fbd"
    if ($Prefix -eq $defaultPrefix) {
        Write-Host "  Note: Run as Administrator to install to Program Files," -ForegroundColor Yellow
        Write-Host "  or use: -Prefix `"$env:USERPROFILE\bin`"" -ForegroundColor Yellow
        Write-Host ""
    }
}

Install-VSBuildTools

if (-not $SkipSwift) {
    Install-Swift
} else {
    if (-not (Test-Command swift)) {
        Die "swift not found in PATH (-SkipSwift was set)"
    }
    Ok "Using existing Swift: $(& swift --version 2>&1 | Select-Object -First 1)"
}

if ($DepsOnly) {
    Write-Host ""
    Ok "Dependencies installed. Run 'swift build -c release' to build."
    exit 0
}

Build-Shd

Write-Host ""
Write-Host "Installation complete!" -ForegroundColor Green
Write-Host ""
Write-Host "  fbd.exe    - Fistbump full node"
Write-Host "  fbdctl.exe - JSON-RPC client"
Write-Host ""
Write-Host "  Start:  fbd --network main"
Write-Host "  Help:   fbd --help"
Write-Host ""
Write-Host "  To use in this terminal:" -ForegroundColor Yellow
Write-Host "    set PATH=%PATH%;$Prefix" -ForegroundColor Yellow
Write-Host ""
