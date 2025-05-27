param(
    [Parameter(Mandatory)][string]$Ssid,
    [Parameter(Mandatory)][securestring]$PassPhrase
)
$plainPassPhrase = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
    [Runtime.InteropServices.Marshal]::SecureStringToBSTR($PassPhrase)
)
$xmlPath = ".\profile.temp"
Out-File -FilePath $xmlPath -Encoding UTF8 -InputObject @"
<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
    <name>$Ssid</name>
    <SSIDConfig>
        <SSID>
            <name>$Ssid</name>
        </SSID>
        <nonBroadcast>true</nonBroadcast>
    </SSIDConfig>
    <connectionType>ESS</connectionType>
    <connectionMode>manual</connectionMode>
    <MSM>
        <security>
            <authEncryption>
                <authentication>WPA2PSK</authentication>
                <encryption>AES</encryption>
                <useOneX>false</useOneX>
            </authEncryption>
            <sharedKey>
                <keyType>passPhrase</keyType>
                <protected>false</protected>
                <keyMaterial>$plainPassPhrase</keyMaterial>
            </sharedKey>
        </security>
        <MACRandomization xmlns="http://www.microsoft.com/networking/WLAN/profile/v3">
            <enableRandomization>false</enableRandomization>
        </MACRandomization>
    </MSM>
</WLANProfile>
"@
netsh wlan add profile filename="$xmlPath"
Remove-Item -Path $xmlPath
