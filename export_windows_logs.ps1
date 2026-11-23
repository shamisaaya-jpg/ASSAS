# ASSAS - Export Windows Security events to CSV
# Run in PowerShell as Administrator:
#   powershell -ExecutionPolicy Bypass -File .\export_windows_logs.ps1

$ids = 4624, 4625, 4720, 4722, 4726, 4728, 4732, 4740
$out = "$env:USERPROFILE\Desktop\windows_security.csv"

Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = $ids; StartTime = (Get-Date).AddDays(-7) } -ErrorAction SilentlyContinue |
  ForEach-Object {
    $xml  = [xml]$_.ToXml()
    $data = @{}
    foreach ($d in $xml.Event.EventData.Data) { $data[$d.Name] = $d.'#text' }
    [PSCustomObject]@{
      TimeCreated = $_.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
      EventID     = $_.Id
      User        = $data['TargetUserName']
      IP          = $data['IpAddress']
      Computer    = $_.MachineName
      Message     = ($_.Message -split "`n")[0]
    }
  } | Export-Csv -Path $out -NoTypeInformation -Encoding UTF8

Write-Host "Saved to $out"
