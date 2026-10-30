# Windows: run the PowerShell agent every 6 hours

Run in an elevated PowerShell, after copying `CertHaloAgent.ps1` and `targets.txt` to `C:\CertHalo`.

```powershell
# Store the Agent key for the account the task runs as (here SYSTEM: machine-wide, readable by admins only).
[Environment]::SetEnvironmentVariable("CERTHALO_API_KEY", "chk_...", "Machine")

$action  = New-ScheduledTaskAction -Execute "powershell.exe" `
  -Argument '-NoProfile -ExecutionPolicy Bypass -File C:\CertHalo\CertHaloAgent.ps1 -Targets C:\CertHalo\targets.txt -Interval 21600'
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Hours 6)
Register-ScheduledTask -TaskName "CertHalo agent" -Action $action -Trigger $trigger -User "SYSTEM" -RunLevel Highest
```

Check it with `Start-ScheduledTask -TaskName "CertHalo agent"` and the task's history, or run the script by hand with `-DryRun` to see exactly what it would send.
