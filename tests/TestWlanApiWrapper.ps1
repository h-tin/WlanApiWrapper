[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

$psVersion = $PSVersionTable.PSVersion
if ($psVersion.Major -lt 7 -or ($psVersion.Major -eq 7 -and $psVersion.Minor -lt 5)) {
    Write-Error "This script requires PowerShell 7.5 (pwsh.exe) or higher. Current version: $psVersion"
    exit 1
}

try {
    Add-Type -Path .\WlanApiWrapper.dll
}
catch {
    $_.Exception.LoaderExceptions | ForEach-Object { $_.Message }
    exit 1
}

$client = New-Object WlanApiWrapper.Client

$ifaces = $client.EnumInterfaces()
$iface = [WlanApiWrapper.InterfaceInfo]$ifaces[0]

Write-Host "Scanning..."
$result = $client.Scan($iface.interfaceGuid)
Start-Sleep -Seconds 5

Write-Host "Getting available network list..."
$result = $client.GetAvailableNetworkList($iface.interfaceGuid, 0)
foreach ($net in $result) {
    Write-Host $net.dot11Ssid
}
Start-Sleep -Seconds 5

Write-Host "Getting network bss list..."
$result = $client.GetNetworkBssList($iface.interfaceGuid, "", 1, 0)
foreach ($bss in $result) {
    Write-Host $bss.dot11Bssid ":" $bss.dot11Ssid
}
Start-Sleep -Seconds 5

if ($Args.Count -ne 2) {
    exit 1
}

Write-Host "Trying to connect to network" $Args[0] "on" $Args[1]
$connParams = New-Object WlanApiWrapper.ConnectionParameters
$connParams.wlanConnectionMode = 0
$connParams.profile = $Args[0]
$connParams.dot11Ssid = $Args[0]
$connParams.desiredBssidList = @($Args[1])
$connParams.dot11BssType = 1
$connParams.flags = 0
$client.Connect($iface.interfaceGuid, $connParams)
Start-Sleep -Seconds 10

Write-Host "Disconnecting..."
$result = $client.Disconnect($iface.interfaceGuid)
Start-Sleep -Seconds 10
