
param(
  [string]$OutDir = ".",
  [int]$SinceHours = 24
)

$ErrorActionPreference = "Stop"


function Save-Out {
  param($obj, [string]$name)
  $p = Join-Path $base $name
  $ext = [IO.Path]::GetExtension($p).ToLower()
  if($ext -eq ".json"){
    $obj | ConvertTo-Json -Depth 5 | Out-File -Encoding UTF8 $p
  }
  elseif($ext -eq ".csv"){
    $obj | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $p
  }
  else{
    $obj | Out-File -Encoding UTF8 $p
  }
}

function Invoke-SafeCommand {
    param(
        [Parameter(Mandatory)][string]$ExeName,
        [Parameter(Mandatory)][string]$OutPath
    )
    $pathsToTry = @(
        (Join-Path $env:SystemRoot ("System32\" + $ExeName)),
        (Join-Path $env:SystemRoot ("Sysnative\" + $ExeName)),
        $ExeName
    )
    foreach($p in $pathsToTry){
        try{
            if((Split-Path $p -Leaf) -eq $p){
                $cmd = Get-Command $p -ErrorAction SilentlyContinue
                if($cmd){
                    & $cmd.Source 2>&1 | Out-File -Encoding UTF8 $OutPath
                    return $true
                }
            } elseif(Test-Path $p){
                & $p 2>&1 | Out-File -Encoding UTF8 $OutPath
                return $true
            }
        } catch {}
    }
    return $false
}

function Resolve-ExePath {
    param([Parameter(Mandatory)][string]$ExeName)
    $candidates = @(
        (Join-Path $env:SystemRoot ("System32\" + $ExeName)),
        (Join-Path $env:SystemRoot ("Sysnative\" + $ExeName)),
        $ExeName
    )
    foreach($c in $candidates){
        if((Split-Path $c -Leaf) -eq $c){
            $cmd = Get-Command $c -ErrorAction SilentlyContinue
            if($cmd){ return $cmd.Source }
        } elseif (Test-Path $c) {
            return $c
        }
    }
    return $null
}

function Convert-ToDateTimeSafe {
    param([Parameter(ValueFromPipeline=$true)]$Value)
    if ($null -eq $Value) { return $null }
    try {
        if ($Value -is [DateTime]) { return $Value }
        if ($Value -is [string]) {
            # DMTF 시도
            try {
                return [Management.ManagementDateTimeConverter]::ToDateTime($Value)
            } catch {
                try {
                    return [datetime]::Parse($Value, [Globalization.CultureInfo]::InvariantCulture)
                } catch {
                    return [datetime]::Parse($Value)
                }
            }
        }
        $s = $Value.ToString()
        if ([string]::IsNullOrWhiteSpace($s)) { return $null }
        try { return [Management.ManagementDateTimeConverter]::ToDateTime($s) } catch {}
        try { return [datetime]::Parse($s, [Globalization.CultureInfo]::InvariantCulture) } catch {}
        return [datetime]::Parse($s)
    } catch {
        return $null
    }
}


$stamp    = (Get-Date).ToString("yyyyMMdd_HHmmss")
$hostName = $env:COMPUTERNAME
$base     = Join-Path $OutDir ("IR_{0}_{1}" -f $hostName,$stamp)
New-Item -ItemType Directory -Path $base -Force | Out-Null

# 01: Transcript
$transcriptPath = Join-Path $base "01_transcript.txt"
Start-Transcript -Path $transcriptPath | Out-Null

try {
    Save-Out (Get-Date) "02_now.txt"

    $os = Get-CimInstance Win32_OperatingSystem
    $lbu = Convert-ToDateTimeSafe $os.LastBootUpTime
    $bootLine = if ($lbu) { "LastBootUpTime: $lbu" } else { "LastBootUpTime: <unavailable>" }
    Save-Out $bootLine "03_boot.txt"

    # ---------------------------------------------------------------------------------
	
    Save-Out (Get-ComputerInfo) "04_systeminfo.txt"
    try { Save-Out (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion') "05_winver.txt" } catch {}

    try { Get-Volume | Select-Object DriveLetter,FileSystemLabel,FileSystem,Size,SizeRemaining | Export-Csv -NoTypeInformation -Encoding UTF8 (Join-Path $base "06_volumes.csv") } catch {}
    try { Get-Service | Sort-Object Status,Name | Export-Csv -NoTypeInformation -Encoding UTF8 (Join-Path $base "07_services.csv") } catch {}
    try { Get-Process | Sort-Object StartTime -ErrorAction SilentlyContinue | Select-Object Name,Id,SessionId,StartTime,Path | Export-Csv -NoTypeInformation -Encoding UTF8 (Join-Path $base "08_processes.csv") } catch {}
    try { Get-ScheduledTask | Select-Object TaskName,State,Author,URI,Description | Export-Csv -NoTypeInformation -Encoding UTF8 (Join-Path $base "09_tasks.csv") } catch {}

    # ---------------------------------------------------------------------------------

    try { Get-NetIPConfiguration | Format-List | Out-File -Encoding UTF8 (Join-Path $base "10_net_ipconfig.txt") } catch {}
    try { Get-NetTCPConnection | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess | Export-Csv -NoTypeInformation -Encoding UTF8 (Join-Path $base "11_net_tcp.csv") } catch {}

    $arpPath = Resolve-ExePath 'arp.exe'
    if($arpPath){
        try { & $arpPath -a | Out-File -Encoding UTF8 (Join-Path $base "12_net_arp.txt") } catch {}
    } else { "arp.exe not found" | Out-File -Encoding UTF8 (Join-Path $base "12_net_arp.txt") }

    $routePath = Resolve-ExePath 'route.exe'
    if($routePath){
        try { & $routePath print | Out-File -Encoding UTF8 (Join-Path $base "13_net_route.txt") } catch {}
    } else { "route.exe not found" | Out-File -Encoding UTF8 (Join-Path $base "13_net_route.txt") }

    $ipconfigPath = Resolve-ExePath 'ipconfig.exe'
    if($ipconfigPath){
        try { & $ipconfigPath /displaydns | Out-File -Encoding UTF8 (Join-Path $base "14_net_dnscache.txt") } catch {}
    } else { "ipconfig.exe not found" | Out-File -Encoding UTF8 (Join-Path $base "14_net_dnscache.txt") }

    # ---------------------------------------------------------------------------------

    $quserOut = Join-Path $base "15_sessions_quser.txt"
    if(-not (Invoke-SafeCommand -ExeName "quser.exe" -OutPath $quserOut)){
        try{
            $logons = Get-CimInstance Win32_LogonSession | Where-Object { $_.LogonType -in 2,10,11 }
            $rows = foreach($ls in $logons){
                $users = Get-CimAssociatedInstance -InputObject $ls -Association Win32_LoggedOnUser
                foreach($u in $users){
                    [pscustomobject]@{
                        User        = ("{0}\{1}" -f $u.Domain,$u.Name)
                        LogonType   = $ls.LogonType
                        AuthPackage = $ls.AuthenticationPackage
                        StartTime   = Convert-ToDateTimeSafe $ls.StartTime
                        LogonId     = $ls.LogonId
                    }
                }
            }
            if($rows){
                $rows | Sort-Object StartTime | Export-Csv -NoTypeInformation -Encoding UTF8 (Join-Path $base "16_sessions_cim.csv")
                "quser.exe unavailable → collected via CIM (Win32_LogonSession)" | Out-File -Append -Encoding UTF8 $quserOut
            } else {
                "no interactive logons found via CIM" | Out-File -Append -Encoding UTF8 $quserOut
            }
        } catch {
            "CIM fallback error: $($_.Exception.Message)" | Out-File -Append -Encoding UTF8 $quserOut
        }
    }

    $qwOut = Join-Path $base "17_sessions_qwinsta.txt"
    if(-not (Invoke-SafeCommand -ExeName "qwinsta.exe" -OutPath $qwOut)){
        try{
            $procs = Get-Process | ForEach-Object {
                try{ $_ | Select-Object Name,Id,SessionId } catch { $null }
            }
            $procs | Sort-Object SessionId,Name | Export-Csv -NoTypeInformation -Encoding UTF8 (Join-Path $base "18_sessions_process.csv")
            "qwinsta.exe unavailable → approximated via process SessionId" | Out-File -Append -Encoding UTF8 $qwOut
        } catch {
            "process-based fallback error: $($_.Exception.Message)" | Out-File -Append -Encoding UTF8 $qwOut
        }
    }

    # ---------------------------------------------------------------------------------
	
    $netPath = Resolve-ExePath 'net.exe'
    if($netPath){
        try { & $netPath user                     | Out-File -Encoding UTF8 (Join-Path $base "19_users_netuser.txt") } catch {}
        try { & $netPath localgroup administrators | Out-File -Encoding UTF8 (Join-Path $base "20_users_admins.txt") } catch {}
    } else {
        "net.exe not found" | Out-File -Encoding UTF8 (Join-Path $base "19_users_netuser.txt")
        "net.exe not found" | Out-File -Encoding UTF8 (Join-Path $base "20_users_admins.txt")
    }

    try { Get-LocalUser | Select-Object Name,Enabled,LastLogon | Export-Csv -NoTypeInformation -Encoding UTF8 (Join-Path $base "21_users_local.csv") } catch {}
    try { Get-SmbShare  | Select-Object Name,Path,Description,CurrentUsers | Export-Csv -NoTypeInformation -Encoding UTF8 (Join-Path $base "22_shares.csv") } catch {}

    # ---------------------------------------------------------------------------------
	
    try { Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' | Out-String | Out-File -Encoding UTF8 (Join-Path $base "23_run_hklm.txt") } catch {}
    try { Get-ItemProperty 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' | Out-String | Out-File -Encoding UTF8 (Join-Path $base "24_run_hkcu.txt") } catch {}
    try { reg export "HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall" (Join-Path $base "25_uninstall_hklm.reg") /y | Out-Null } catch {}
    try { reg export "HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall" (Join-Path $base "26_uninstall_hkcu.reg") /y | Out-Null } catch {}

    # ---------------------------------------------------------------------------------
	
    try { Stop-Transcript | Out-Null } catch {}

    $hashFile = Join-Path $base "27_hashes.txt"

    $hashLines = @("## File Hashes (SHA256)")
    $items = Get-ChildItem $base -File -Recurse | Where-Object { $_.FullName -ne $hashFile }
    foreach($f in $items){
        try{
            $h = Get-FileHash $f.FullName -Algorithm SHA256
            $rel = $f.FullName.Replace($base,".")
            $hashLines += ("{0}  {1}" -f $h.Hash, $rel)
        } catch {
            $rel = $f.FullName.Replace($base,".")
            $hashLines += ("<ERROR>  {0}" -f $rel)
        }
    }

    Set-Content -Path $hashFile -Encoding UTF8 -Value $hashLines

    try {
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $zipPath = Join-Path $base "28_package.zip"
        if(Test-Path $zipPath){ Remove-Item $zipPath -Force }
        [IO.Compression.ZipFile]::CreateFromDirectory($base, $zipPath)
    } catch {}

}
finally {
    try { Stop-Transcript | Out-Null } catch {}
}
