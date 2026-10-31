# Run in Windows PowerShell 5.1 as the dedicated lab account after its RDP logon.
# Requires permission to create a task. Does not create users or change firewall/audit settings.
[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$ReceiverIP, [ValidateRange(1,65535)][int]$Port=8080)
$ErrorActionPreference = 'Stop'
$ip = [System.Net.IPAddress]::Parse($ReceiverIP)
$b = $ip.GetAddressBytes()
$private = ($b.Length -eq 4) -and (($b[0] -eq 10) -or ($b[0] -eq 172 -and $b[1] -ge 16 -and $b[1] -le 31) -or ($b[0] -eq 192 -and $b[1] -eq 168))
if (-not $private) { throw 'ReceiverIP must be a lab RFC1918 IPv4 address.' }
$taskName = 'Lab_Emulation_Test'
if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) { throw 'Lab task already exists. Review and clean up the previous run first.' }
$curl = (Get-Command curl.exe -ErrorAction Stop).Source
$root = Join-Path $env:LOCALAPPDATA 'Week8-Lab'
New-Item -ItemType Directory -Path $root -Force | Out-Null
$runId = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ') + '-' + [guid]::NewGuid().ToString('N').Substring(0,8)
$run = Join-Path $root $runId
New-Item -ItemType Directory -Path $run | Out-Null
$started = (Get-Date).ToUniversalTime().ToString('o')
$user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
$marker = Join-Path $run 'task-marker.txt'
# The scheduled action only writes its timestamp to a local file.
$escapedMarker = $marker.Replace("'", "''")
$line = "[System.IO.File]::AppendAllText('$escapedMarker', [DateTime]::UtcNow.ToString('o') + [Environment]::NewLine)"
$exe = Join-Path $PSHOME 'powershell.exe'
$action = New-ScheduledTaskAction -Execute $exe -Argument ('-NoProfile -NonInteractive -Command "' + $line + '"')
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $user
$principal = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Limited
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Minutes 1)
Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description 'Week8 lab timestamp marker only' | Out-Null
Export-ScheduledTask -TaskName $taskName | Set-Content -Path (Join-Path $run 'task.xml') -Encoding UTF8
Start-ScheduledTask -TaskName $taskName
Start-Sleep -Seconds 5
$info = Get-ScheduledTaskInfo -TaskName $taskName
$info | Format-List * | Out-File (Join-Path $run 'task-result.txt')
if (-not (Test-Path $marker)) { throw "Task did not write marker. Check task history, execution policy and $run. Task remains for inspection." }
# Exact ASCII bytes, matching receiver.py. No existing user files are read.
$file = Join-Path $run 'dummy-data.txt'
[System.IO.File]::WriteAllBytes($file, [System.Text.Encoding]::ASCII.GetBytes("WEEK8-LAB-DUMMY-DATA`nNo real credentials or personal data.`n"))
$hash = (Get-FileHash -Path $file -Algorithm SHA256).Hash.ToLowerInvariant()
$url = 'http://' + $ReceiverIP + ':' + $Port + '/upload'
$response = & $curl --fail --silent --show-error --noproxy '*' --connect-timeout 5 --max-time 15 --header 'Content-Type: application/octet-stream' --data-binary ('@' + $file) $url
if ($LASTEXITCODE -ne 0) { throw "Upload failed. Review receiver and firewall. Evidence directory: $run" }
$received = ($response -join "`n") | ConvertFrom-Json
if ($received.sha256 -ne $hash) { throw 'Receiver hash mismatch.' }
$response | Set-Content (Join-Path $run 'receiver-response.json') -Encoding UTF8
[ordered]@{run_id=$runId; start_utc=$started; end_utc=(Get-Date).ToUniversalTime().ToString('o'); computer=$env:COMPUTERNAME; user=$user; receiver=$url; sha256=$hash; bytes=(Get-Item $file).Length; task=$taskName; evidence=$run} | ConvertTo-Json | Set-Content (Join-Path $run 'run-metadata.json') -Encoding UTF8
Write-Host "Completed local task and dummy transfer. Evidence: $run"
Write-Host 'Now verify Wazuh alerts. Log off and log on again to verify the task logon trigger before cleanup.'
