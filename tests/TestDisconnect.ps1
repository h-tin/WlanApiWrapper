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

Write-Host "Disconnecting..."
$client.Disconnect($iface.interfaceGuid) > $null
