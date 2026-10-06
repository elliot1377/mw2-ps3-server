<#
Builds the Windows release: a standalone "MW2 Server.exe" (PyInstaller, no Python needed to run it) + the RPCS3
online fix, zipped:  build\mw2-ps3-server-<version>-windows.zip

    powershell -ExecutionPolicy Bypass -File build.ps1 [-Version 1.0.0]

Needs Python 3 with:  pip install -r requirements.txt pyinstaller
#>
param([string]$Version = '1.0.0')

$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$out = Join-Path $root 'build'
$name = 'MW2 PS3 Online (RPCS3)'
$stage = Join-Path $out "release\$name"

python -m unittest discover -s (Join-Path $root 'tests')
if ($LASTEXITCODE) { throw 'tests failed' }

python -m PyInstaller --noconfirm --onefile --console --name 'MW2 Server' `
    --distpath (Join-Path $out 'dist') --workpath (Join-Path $out 'work') --specpath $out `
    (Join-Path $root 'server\dwserver.py')
if ($LASTEXITCODE) { throw 'PyInstaller failed' }

if (Test-Path $stage) { Remove-Item $stage -Recurse -Force }
New-Item -ItemType Directory -Force "$stage\server" | Out-Null
Copy-Item (Join-Path $out 'dist\MW2 Server.exe') "$stage\server\"
Copy-Item (Join-Path $root 'server\tiger_sboxes.bin') "$stage\server\"
Copy-Item (Join-Path $root 'server\files') "$stage\server\files" -Recurse
Copy-Item (Join-Path $root 'windows\Start Server.bat') $stage
Copy-Item (Join-Path $root 'rpcs3\Install Online Fix.bat'), (Join-Path $root 'rpcs3\Install Online Fix.ps1') $stage
Copy-Item (Join-Path $root 'docs\RELEASE_README.txt') "$stage\README.txt"
Copy-Item (Join-Path $root 'LICENSE') "$stage\LICENSE.txt"

$zip = Join-Path $out "mw2-ps3-server-$Version-windows.zip"
if (Test-Path $zip) { Remove-Item $zip -Force }
Compress-Archive -Path $stage -DestinationPath $zip
Write-Host "Built $zip" -ForegroundColor Green
