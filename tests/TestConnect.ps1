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
$client.Connect($iface.interfaceGuid, $connParams) > $null
