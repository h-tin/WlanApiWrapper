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

Write-Host "Trying to get connection information..."
$result = $client.QueryInterfaceCurrentConnection($iface.interfaceGuid)
Write-Host "State    :" $result.state
Write-Host "Mode     :" $result.wlanConnectionMode
Write-Host "Profile  :" $result.profileName
Write-Host "SSID     :" $result.wlanAssociationAttributes.dot11Ssid
Write-Host "BSSType  :" $result.wlanAssociationAttributes.dot11BssType
Write-Host "BSSID    :" $result.wlanAssociationAttributes.dot11Bssid
Write-Host "PhyType  :" $result.wlanAssociationAttributes.dot11PhyType
Write-Host "PhyIndex :" $result.wlanAssociationAttributes.dot11PhyIndex
Write-Host "Signal   :" $result.wlanAssociationAttributes.wlanSignalQuality
Write-Host "Rx Rate  :" $result.wlanAssociationAttributes.rxRate
Write-Host "Tx Rage  :" $result.wlanAssociationAttributes.txRate
Write-Host "Security :" $result.wlanSecurityAttributes.securityEnabled
Write-Host "OneX     :" $result.wlanSecurityAttributes.oneXEnabled
Write-Host "Auth     :" $result.wlanSecurityAttributes.dot11AuthAlgorithm
Write-Host "Cipher   :" $result.wlanSecurityAttributes.dot11CipherAlgorithm
