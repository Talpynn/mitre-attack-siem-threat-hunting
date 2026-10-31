# Removes only this lab task; evidence and marker scripts are retained for the report.
[CmdletBinding(SupportsShouldProcess=$true)]
param()
$ErrorActionPreference='Stop'
$task = Get-ScheduledTask -TaskName 'Lab_Emulation_Test' -ErrorAction SilentlyContinue
if (-not $task) { Write-Host 'Lab task is already absent.'; return }
if ($task.Description -ne 'Week8 lab timestamp marker only') { throw 'Description differs. Review the task manually; nothing was removed.' }
if ($PSCmdlet.ShouldProcess('Lab_Emulation_Test','Stop and unregister lab task')) {
    Stop-ScheduledTask -TaskName 'Lab_Emulation_Test' -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName 'Lab_Emulation_Test' -Confirm:$false
    Write-Host 'Lab task removed. Evidence retained in LOCALAPPDATA\Week8-Lab.'
}
