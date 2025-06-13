
# ServerHealthReport.ps1

$reportPath = "$env:USERPROFILE\Desktop\ServerHealthReport.html"

# Collect system information
$serverName = $env:COMPUTERNAME
$domain = (Get-WmiObject Win32_ComputerSystem).Domain
$uptime = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
$lastRestart = $uptime
$uptimeSpan = (Get-Date) - $lastRestart

$cpuInfo = Get-CimInstance Win32_Processor
$cpuUsage = $cpuInfo | Select-Object Name, LoadPercentage
$socketCount = ($cpuInfo | Measure-Object).Count
$virtualProcessors = ($cpuInfo | Measure-Object -Property NumberOfLogicalProcessors -Sum).Sum

$memory = Get-CimInstance Win32_OperatingSystem | Select-Object TotalVisibleMemorySize, FreePhysicalMemory
$totalMemGB = [math]::Round($memory.TotalVisibleMemorySize / 1MB, 2)
$freeMemGB = [math]::Round($memory.FreePhysicalMemory / 1MB, 2)
$usedMemGB = [math]::Round($totalMemGB - $freeMemGB, 2)

$disk = Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" | Select-Object DeviceID, Size, FreeSpace
$ipConfig = Get-NetIPAddress | Where-Object {$_.AddressFamily -eq "IPv4" -and $_.IPAddress -notlike "169.*"} | Select-Object InterfaceAlias, IPAddress
$roles = Get-WindowsFeature | Where-Object {$_.Installed -eq $true} | Select-Object DisplayName

$startDate = (Get-Date).AddDays(-7)
$eventErrors = Get-WinEvent -FilterHashtable @{LogName='System'; Level=2; StartTime=$startDate} | Select-Object TimeCreated, Id, Message -First 50
$eventWarnings = Get-WinEvent -FilterHashtable @{LogName='System'; Level=3; StartTime=$startDate} | Select-Object TimeCreated, Id, Message -First 50
$serviceRestarts = Get-WinEvent -FilterHashtable @{LogName='System'; ID=7036; StartTime=$startDate} | Select-Object TimeCreated, Message -First 50

$updates = Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 10 Source, Description, HotFixID, InstalledOn

$recentApps = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*, HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* |
    Where-Object { $_.InstallDate -match '^\d{8}$' } |
    Select-Object DisplayName, InstallDate |
    Where-Object {
        $installDate = [datetime]::ParseExact($_.InstallDate, 'yyyyMMdd', $null)
        $installDate -gt (Get-Date).AddDays(-30)
    } |
    Sort-Object InstallDate -Descending

$html = @"
<html>
<head>
    <title>Server Health Report</title>
    <style>
        body { font-family: Arial; }
        table { border-collapse: collapse; width: 100%; margin-bottom: 20px; }
        th, td { border: 1px solid #ccc; padding: 8px; text-align: left; vertical-align: top; }
        th { background-color: #f2f2f2; }
        h2 { color: #2e6c80; }
        pre { white-space: pre-wrap; word-wrap: break-word; }
    </style>
</head>
<body>
    <h1>Windows Server Health Report</h1>
    <h2>Server Information</h2>
    <table>
        <tr><th>Server Name</th><td>$serverName</td></tr>
        <tr><th>Domain</th><td>$domain</td></tr>
        <tr><th>Last Restart</th><td>$lastRestart</td></tr>
        <tr><th>Uptime</th><td>$($uptimeSpan.Days) days, $($uptimeSpan.Hours) hours, $($uptimeSpan.Minutes) minutes</td></tr>
        <tr><th>CPU Socket Count</th><td>$socketCount</td></tr>
        <tr><th>Virtual Processors</th><td>$virtualProcessors</td></tr>
        <tr><th>Total RAM (GB)</th><td>$totalMemGB</td></tr>
    </table>
    <h2>Installed Roles</h2>
    <ul>
"@

foreach ($role in $roles) {
    $html += "<li>$($role.DisplayName)</li>"
}

$html += @"
    </ul>
    <h2>CPU Usage</h2>
    <table><tr><th>Name</th><th>Load %</th></tr>
"@

foreach ($cpu in $cpuUsage) {
    $html += "<tr><td>$($cpu.Name)</td><td>$($cpu.LoadPercentage)%</td></tr>"
}

$html += @"
    </table>
    <h2>Memory Usage</h2>
    <table>
        <tr><th>Total (GB)</th><th>Used (GB)</th><th>Free (GB)</th></tr>
        <tr><td>$totalMemGB</td><td>$usedMemGB</td><td>$freeMemGB</td></tr>
    </table>
    <h2>Disk Usage</h2>
    <table><tr><th>Drive</th><th>Total (GB)</th><th>Free (GB)</th></tr>
"@

foreach ($d in $disk) {
    $total = [math]::Round($d.Size / 1GB, 2)
    $free = [math]::Round($d.FreeSpace / 1GB, 2)
    $html += "<tr><td>$($d.DeviceID)</td><td>$total</td><td>$free</td></tr>"
}

$html += @"
    </table>
    <h2>IP Configuration</h2>
    <table><tr><th>Interface</th><th>IP Address</th></tr>
"@

foreach ($ip in $ipConfig) {
    $html += "<tr><td>$($ip.InterfaceAlias)</td><td>$($ip.IPAddress)</td></tr>"
}

$html += @"
    </table>
    <h2>Recent Windows Updates</h2>
    <table><tr><th>Source</th><th>Description</th><th>HotFix ID</th><th>Installed On</th></tr>
"@

foreach ($update in $updates) {
    $html += "<tr><td>$($update.Source)</td><td>$($update.Description)</td><td>$($update.HotFixID)</td><td>$($update.InstalledOn.ToShortDateString())</td></tr>"
}

$html += @"
    </table>
    <h2>Recently Installed Applications (Last 30 Days)</h2>
    <table><tr><th>Application</th><th>Install Date</th></tr>
"@

foreach ($app in $recentApps) {
    $installDate = [datetime]::ParseExact($app.InstallDate, 'yyyyMMdd', $null).ToShortDateString()
    $html += "<tr><td>$($app.DisplayName)</td><td>$installDate</td></tr>"
}

$html += @"
    </table>
    <h2>Event Viewer Errors (Last 7 Days)</h2>
    <table><tr><th>Time</th><th>Event ID</th><th>Message</th></tr>
"@

foreach ($event in $eventErrors) {
    $msg = ($event.Message -replace '[^ -~]', '')
    $html += "<tr><td>$($event.TimeCreated)</td><td>$($event.Id)</td><td><pre>$msg</pre></td></tr>"
}

$html += @"
    </table>
    <h2>Event Viewer Warnings (Last 7 Days)</h2>
    <table><tr><th>Time</th><th>Event ID</th><th>Message</th></tr>
"@

foreach ($event in $eventWarnings) {
    $msg = ($event.Message -replace '[^ -~]', '')
    $html += "<tr><td>$($event.TimeCreated)</td><td>$($event.Id)</td><td><pre>$msg</pre></td></tr>"
}

$html += @"
    </table>
    <h2>Service Restarts (Last 7 Days)</h2>
    <table><tr><th>Time</th><th>Message</th></tr>
"@

foreach ($event in $serviceRestarts) {
    $msg = ($event.Message -replace '[^ -~]', '')
    $html += "<tr><td>$($event.TimeCreated)</td><td><pre>$msg</pre></td></tr>"
}

$html += @"
    </table>
</body>
</html>
"@

$html | Out-File -FilePath $reportPath -Encoding UTF8
Write-Host "Report generated at: $reportPath"
