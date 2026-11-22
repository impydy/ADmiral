# Build ADmiral on Windows: tests, the self-contained folder build and the installer.
#   powershell -ExecutionPolicy Bypass -File packaging\build.ps1 [-SkipTests]
# Needs the .NET 10 SDK (https://dot.net) and, for the installer, Inno Setup 6 (https://jrsoftware.org/isinfo.php).
# Output:
#   dist\ADmiral\                    the published program folder (ADmiral.exe + runtime + wwwroot)
#   dist\ADmiral-Setup-<ver>.exe     the installer
# No self-extracting single-file exe: antivirus machine-learning engines flag those as false positives.
param([switch]$SkipTests)
$ErrorActionPreference = 'Stop'
Set-Location (Split-Path $PSScriptRoot -Parent)
$env:DOTNET_CLI_TELEMETRY_OPTOUT = '1'
$env:DOTNET_NOLOGO = '1'

if (-not $SkipTests) {
    dotnet test tests\ADmiral.Tests -c Release
    if ($LASTEXITCODE -ne 0) { throw "tests failed" }
}

$out = Join-Path (Get-Location) 'dist\ADmiral'
if (Test-Path $out) { Remove-Item $out -Recurse -Force }
dotnet publish src\ADmiral.Desktop -c Release -r win-x64 --self-contained -o $out
if ($LASTEXITCODE -ne 0) { throw "dotnet publish failed" }
if (-not (Test-Path "$out\ADmiral.exe")) { throw "ADmiral.exe missing from $out" }
if (-not (Test-Path "$out\wwwroot\index.html")) { throw "the UI (wwwroot) is missing from $out" }

# the version of the build = <Version> in Directory.Build.props
$version = ([xml](Get-Content Directory.Build.props)).Project.PropertyGroup.Version | Where-Object { $_ } | Select-Object -First 1
if (-not $version) { throw "Version not found in Directory.Build.props" }

# ADmiral.exe is a windowed program: wait for it and read its exit code through a process object
$p = Start-Process "$out\ADmiral.exe" -ArgumentList '--self-test' -Wait -PassThru -WindowStyle Hidden
if ($p.ExitCode -ne 0) { throw "ADmiral.exe --self-test failed (exit $($p.ExitCode))" }

$iscc = "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe"
if (Test-Path $iscc) {
    $wv2 = 'packaging\MicrosoftEdgeWebview2Setup.exe'
    if (-not (Test-Path $wv2)) {
        Invoke-WebRequest "https://go.microsoft.com/fwlink/p/?LinkId=2124703" -OutFile $wv2
    }
    # the bootstrapper is bundled into the installer and runs elevated: it must carry a valid Microsoft signature
    # (checked every build, also for a copy that was already there)
    $sig = Get-AuthenticodeSignature -FilePath $wv2
    if ($sig.Status -ne 'Valid' -or -not $sig.SignerCertificate -or
        $sig.SignerCertificate.Subject -notmatch '(^|,\s*)O=Microsoft Corporation(,|$)') {
        Remove-Item $wv2 -Force -ErrorAction SilentlyContinue
        throw "MicrosoftEdgeWebview2Setup.exe is not validly signed by Microsoft (status: $($sig.Status), signer: $($sig.SignerCertificate.Subject)); removed"
    }
    & $iscc /Qp "/DAppVersion=$version" "/DSourceDir=$out" packaging\installer.iss
    if ($LASTEXITCODE -ne 0) { throw "Inno Setup failed" }
} else {
    Write-Warning "Inno Setup 6 not found; skipping the installer."
}
Get-ChildItem dist\*.exe -ErrorAction SilentlyContinue | ForEach-Object { "{0} ({1:N1} MB)" -f $_.FullName, ($_.Length / 1MB) }
