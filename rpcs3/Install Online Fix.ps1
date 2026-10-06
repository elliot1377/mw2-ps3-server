<#
MW2 PS3 online fix for RPCS3: points MW2's old DemonWare / IWNet servers at a community server.

    Install Online Fix.bat                -> the server on this PC (127.0.0.1, Start Server.bat)
    Install Online Fix.bat 203.0.113.7    -> a server somewhere else

Changes only MW2's per-game RPCS3 settings (Network tab: Network Connected, PSN RPCN, IP swap list) and keeps a
backup of every file it changes (config_<ID>.yml.bak_online).
#>
param([string]$ServerIP = '127.0.0.1', [string]$RPCS3 = '')

$ErrorActionPreference = 'Stop'
if (-not ($ServerIP -as [ipaddress])) { Write-Host "Not an IP address: $ServerIP" -ForegroundColor Red; exit 1 }

# MW2 PS3 title IDs: US, EU (several languages), JP
$TitleIDs = 'BLUS30377', 'BLES00683', 'BLES00684', 'BLES00685', 'BLES00686', 'BLES00687', 'BLJM60191', 'BLJM55011'

$Hosts = 'mw2-ps3-auth.mmp3.demonware.net', 'mw2-ps3-lsg.live.mmp3.demonware.net', 'mw2-ps3-lsg.cert.mmp3.demonware.net',
         'mw2-stun.us.demonware.net', 'mw2-stun.eu.demonware.net', 'auth1.ps3.iw4.iwnet.infinityward.com',
         'match1.ps3.iw4.iwnet.infinityward.com', 'blob1.ps3.iw4.iwnet.infinityward.com',
         'team1.ps3.iw4.iwnet.infinityward.com', 'ip1.ps3.iw4.iwnet.infinityward.com',
         'log1.ps3.iw4.iwnet.infinityward.com', 'web1.ps3.iw4.iwnet.infinityward.com'
$SwapList = ($Hosts | ForEach-Object { "$_=$ServerIP" }) -join '&&'
$Utf8 = New-Object System.Text.UTF8Encoding $false

function Find-RPCS3 {
    if ($RPCS3) { return $RPCS3 }
    foreach ($candidate in @($PSScriptRoot, (Split-Path $PSScriptRoot -Parent))) {
        if ($candidate -and (Test-Path (Join-Path $candidate 'rpcs3.exe'))) { return $candidate }
    }
    Add-Type -AssemblyName System.Windows.Forms
    $dialog = New-Object System.Windows.Forms.FolderBrowserDialog
    $dialog.Description = 'Select your RPCS3 folder (the one with rpcs3.exe)'
    if ($dialog.ShowDialog() -ne 'OK') { return $null }
    return $dialog.SelectedPath
}

# set the Net section of one config file (UTF-8 without BOM, as RPCS3 writes it)
function Set-NetSettings([string]$path) {
    $lines = [System.Collections.Generic.List[string]]([System.IO.File]::ReadAllLines($path, [System.Text.Encoding]::UTF8))
    $want = [ordered]@{
        'Internet enabled' = 'Connected'
        'IP swap list'     = '"' + $SwapList + '"'
        'PSN status'       = 'RPCN'
    }
    $net = $lines.IndexOf('Net:')
    if ($net -lt 0) { $lines.Add('Net:'); $net = $lines.Count - 1 }
    $end = $net + 1
    while ($end -lt $lines.Count -and $lines[$end] -match '^\s') { $end++ }
    foreach ($key in $want.Keys) {
        $found = $false
        for ($i = $net + 1; $i -lt $end; $i++) {
            if ($lines[$i] -match "^\s+$([regex]::Escape($key)):") { $lines[$i] = "  ${key}: $($want[$key])"; $found = $true }
        }
        if (-not $found) { $lines.Insert($end, "  ${key}: $($want[$key])"); $end++ }
    }
    [System.IO.File]::WriteAllLines($path, $lines, $Utf8)
}

$root = Find-RPCS3
if (-not $root -or -not (Test-Path (Join-Path $root 'rpcs3.exe'))) {
    Write-Host 'RPCS3 folder not found (it must contain rpcs3.exe).' -ForegroundColor Red
    exit 1
}

$customDir = Join-Path $root 'config\custom_configs'
$globalConfig = Join-Path $root 'config\config.yml'
if (-not (Test-Path $globalConfig)) { $globalConfig = Join-Path $root 'config.yml' }
New-Item -ItemType Directory -Force $customDir | Out-Null

foreach ($id in $TitleIDs) {
    $custom = Join-Path $customDir "config_$id.yml"
    if (Test-Path $custom) {
        Copy-Item -LiteralPath $custom "$custom.bak_online" -Force
    } elseif (Test-Path $globalConfig) {
        Copy-Item -LiteralPath $globalConfig $custom        # start from the global settings: nothing else changes
    } else {
        [System.IO.File]::WriteAllLines($custom, [string[]]@('Net:'), $Utf8)
    }
    Set-NetSettings $custom
}

Write-Host ''
Write-Host "MW2 online fix set in $root" -ForegroundColor Green
Write-Host "Server: $ServerIP$(if ($ServerIP -eq '127.0.0.1') { ' (this PC - run Start Server.bat before playing)' })"
Write-Host 'Next: RPCS3 > Configuration > RPCN > create a free account (once), then MW2 > Multiplayer > Play Online.'
