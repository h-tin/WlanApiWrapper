using System;
using System.Runtime.InteropServices;

namespace WlanApiWrapper;

public static class API
{
    public const int BSSID_BYTES_LENGTH = 6;
    public const int DOT11_RATE_SET_MAX_LENGTH = 126;
    public const int MAX_SSID_BYTES_LENGTH = 32;
    public const int WLAN_MAX_NAME_LENGTH = 256;
    public const int WLAN_MAX_PHY_TYPE_NUMBER = 8;

    public enum DOT11_AUTH_ALGORITHM : uint
    {
        DOT11_AUTH_ALGO_80211_OPEN = 1,
        DOT11_AUTH_ALGO_80211_SHARED_KEY = 2,
        DOT11_AUTH_ALGO_WPA = 3,
        DOT11_AUTH_ALGO_WPA_PSK = 4,
        DOT11_AUTH_ALGO_WPA_NONE = 5,
        DOT11_AUTH_ALGO_RSNA = 6,
        DOT11_AUTH_ALGO_RSNA_PSK = 7,
        DOT11_AUTH_ALGO_WPA3 = 8,
        DOT11_AUTH_ALGO_WPA3_ENT_192 = DOT11_AUTH_ALGO_WPA3,
        DOT11_AUTH_ALGO_WPA3_SAE = 9,
        DOT11_AUTH_ALGO_OWE = 10,
        DOT11_AUTH_ALGO_WPA3_ENT = 11,
        DOT11_AUTH_ALGO_IHV_START = 0x80000000,
        DOT11_AUTH_ALGO_IHV_END = 0xffffffff,
    }

    public enum DOT11_BSS_TYPE : uint
    {
        dot11_BSS_type_infrastructure = 1,
        dot11_BSS_type_independent = 2,
        dot11_BSS_type_any = 3,
    }

    public enum DOT11_CIPHER_ALGORITHM : uint
    {
        DOT11_CIPHER_ALGO_NONE = 0x00,
        DOT11_CIPHER_ALGO_WEP40 = 0x01,
        DOT11_CIPHER_ALGO_TKIP = 0x02,
        DOT11_CIPHER_ALGO_CCMP = 0x04,
        DOT11_CIPHER_ALGO_WEP104 = 0x05,
        DOT11_CIPHER_ALGO_WPA_USE_GROUP = 0x100,
        DOT11_CIPHER_ALGO_RSN_USE_GROUP = 0x100,
        DOT11_CIPHER_ALGO_WEP = 0x101,
        DOT11_CIPHER_ALGO_IHV_START = 0x80000000,
        DOT11_CIPHER_ALGO_IHV_END = 0xffffffff,
    }

    public enum DOT11_PHY_TYPE : uint
    {
        dot11_phy_type_unknown = 0,
        dot11_phy_type_any = 0,
        dot11_phy_type_fhss = 1,
        dot11_phy_type_dsss = 2,
        dot11_phy_type_irbaseband = 3,
        dot11_phy_type_ofdm = 4,
        dot11_phy_type_hrdsss = 5,
        dot11_phy_type_erp = 6,
        dot11_phy_type_ht = 7,
        dot11_phy_type_vht = 8,
        dot11_phy_type_dmg = 9,
        dot11_phy_type_he = 10,
        dot11_phy_type_eht = 11,
        dot11_phy_type_IHV_start = 0x80000000,
        dot11_phy_type_IHV_end = 0xffffffff,
    }

    public enum WLAN_CONNECTION_MODE : uint
    {
        wlan_connection_mode_profile = 0,
        wlan_connection_mode_temporary_profile,
        wlan_connection_mode_discovery_secure,
        wlan_connection_mode_discovery_unsecure,
        wlan_connection_mode_auto,
        wlan_connection_mode_invalid,
    }

    public enum WLAN_INTF_OPCODE : uint
    {
        wlan_intf_opcode_autoconf_start = 0x000000000,
        wlan_intf_opcode_autoconf_enabled,
        wlan_intf_opcode_background_scan_enabled,
        wlan_intf_opcode_media_streaming_mode,
        wlan_intf_opcode_radio_state,
        wlan_intf_opcode_bss_type,
        wlan_intf_opcode_interface_state,
        wlan_intf_opcode_current_connection,
        wlan_intf_opcode_channel_number,
        wlan_intf_opcode_supported_infrastructure_auth_cipher_pairs,
        wlan_intf_opcode_supported_adhoc_auth_cipher_pairs,
        wlan_intf_opcode_supported_country_or_region_string_list,
        wlan_intf_opcode_current_operation_mode,
        wlan_intf_opcode_supported_safe_mode,
        wlan_intf_opcode_certified_safe_mode,
        wlan_intf_opcode_hosted_network_capable,
        wlan_intf_opcode_management_frame_protection_capable,
        wlan_intf_opcode_secondary_sta_interfaces,
        wlan_intf_opcode_secondary_sta_synchronized_connections,
        wlan_intf_opcode_realtime_connection_quality,
        wlan_intf_opcode_qos_info,
        wlan_intf_opcode_autoconf_end = 0x0fffffff,
        wlan_intf_opcode_msm_start = 0x10000100,
        wlan_intf_opcode_statistics,
        wlan_intf_opcode_rssi,
        wlan_intf_opcode_msm_end = 0x1fffffff,
        wlan_intf_opcode_security_start = 0x20010000,
        wlan_intf_opcode_security_end = 0x2fffffff,
        wlan_intf_opcode_ihv_start = 0x30000000,
        wlan_intf_opcode_ihv_end = 0x3fffffff,
    }

    public enum WLAN_INTERFACE_STATE : uint
    {
        wlan_interface_state_not_ready,
        wlan_interface_state_connected,
        wlan_interface_state_ad_hoc_network_formed,
        wlan_interface_state_disconnecting,
        wlan_interface_state_disconnected,
        wlan_interface_state_associating,
        wlan_interface_state_discovering,
        wlan_interface_state_authenticating,
    }

    public enum WLAN_OPCODE_VALUE_TYPE : uint
    {
        wlan_opcode_value_type_query_only = 0,
        wlan_opcode_value_type_set_by_group_policy,
        wlan_opcode_value_type_set_by_user,
        wlan_opcode_value_type_invalid,
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct DOT11_BSSID_LIST
    {
        public NDIS_OBJECT_HEADER Header;
        public uint uNumOfEntries;
        public uint uTotalNumOfEntries;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
        public DOT11_MAC_ADDRESS[] BSSIDs;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct DOT11_MAC_ADDRESS
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = BSSID_BYTES_LENGTH)]
        public byte[] ucDot11MacAddress;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct DOT11_SSID
    {
        public uint uSSIDLength;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = MAX_SSID_BYTES_LENGTH)]
        public byte[] ucSSID;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct NDIS_OBJECT_HEADER
    {
        public byte Type;
        public byte Revision;
        public ushort Size;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct WLAN_ASSOCIATION_ATTRIBUTES
    {
        public DOT11_SSID dot11Ssid;
        public DOT11_BSS_TYPE dot11BssType;
        public DOT11_MAC_ADDRESS dot11Bssid;
        public DOT11_PHY_TYPE dot11PhyType;
        public uint uDot11PhyIndex;
        public uint wlanSignalQuality;
        public uint ulRxRate;
        public uint ulTxRate;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct WLAN_AVAILABLE_NETWORK
    {
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = WLAN_MAX_NAME_LENGTH)]
        public string strProfileName;
        public DOT11_SSID dot11Ssid;
        public DOT11_BSS_TYPE dot11BssType;
        public uint uNumberOfBssids;
        [MarshalAs(UnmanagedType.Bool)]
        public bool bNetworkConnectable;
        public uint wlanNotConnectableReason;
        public uint uNumberOfPhyTypes;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = WLAN_MAX_PHY_TYPE_NUMBER)]
        public DOT11_PHY_TYPE[] dot11PhyTypes;
        [MarshalAs(UnmanagedType.Bool)]
        public bool bMorePhyTypes;
        public uint wlanSignalQuality;
        [MarshalAs(UnmanagedType.Bool)]
        public bool bSecurityEnabled;
        public DOT11_AUTH_ALGORITHM dot11DefaultAuthAlgorithm;
        public DOT11_CIPHER_ALGORITHM dot11DefaultCipherAlgorithm;
        public uint dwFlags;
        public uint dwReserved;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct WLAN_AVAILABLE_NETWORK_LIST
    {
        public uint dwNumberOfItems;
        public uint dwIndex;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
        public WLAN_AVAILABLE_NETWORK[] Network;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct WLAN_BSS_ENTRY
    {
        public DOT11_SSID dot11Ssid;
        public uint uPhyId;
        public DOT11_MAC_ADDRESS dot11Bssid;
        public DOT11_BSS_TYPE dot11BssType;
        public DOT11_PHY_TYPE dot11BssPhyType;
        public int lRssi;
        public uint uLinkQuality;
        public int bInRegDomain;
        public ushort usBeaconPeriod;
        public ulong ullTimestamp;
        public ulong ullHostTimestamp;
        public ushort usCapabilityInformation;
        public uint ulChCenterFrequency;
        public WLAN_RATE_SET wlanRateSet;
        public uint ulIeOffset;
        public uint ulIeSize;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct WLAN_BSS_LIST
    {
        public uint dwTotalSize;
        public uint dwNumberOfItems;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
        public WLAN_BSS_ENTRY[] wlanBssEntries;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct WLAN_CONNECTION_ATTRIBUTES
    {
        public WLAN_INTERFACE_STATE isState;
        public WLAN_CONNECTION_MODE wlanConnectionMode;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = WLAN_MAX_NAME_LENGTH)]
        public string strProfileName;
        public WLAN_ASSOCIATION_ATTRIBUTES wlanAssociationAttributes;
        public WLAN_SECURITY_ATTRIBUTES wlanSecurityAttributes;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct WLAN_CONNECTION_PARAMETERS
    {
        public WLAN_CONNECTION_MODE wlanConnectionMode;
        [MarshalAs(UnmanagedType.LPWStr, SizeConst = WLAN_MAX_NAME_LENGTH)]
        public string strProfile;
        public IntPtr pDot11Ssid;
        public IntPtr pDesiredBssidList;
        public DOT11_BSS_TYPE dot11BssType;
        public uint dwFlags;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct WLAN_INTERFACE_INFO
    {
        public Guid InterfaceGuid;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = WLAN_MAX_NAME_LENGTH)]
        public string strInterfaceDescription;
        public WLAN_INTERFACE_STATE isState;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct WLAN_INTERFACE_INFO_LIST
    {
        public uint dwNumberOfItems;
        public uint dwIndex;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
        public WLAN_INTERFACE_INFO[] InterfaceInfo;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct WLAN_RATE_SET
    {
        public uint uRateSetLength;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = DOT11_RATE_SET_MAX_LENGTH)]
        public ushort[] usRateSet;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct WLAN_SECURITY_ATTRIBUTES
    {
        [MarshalAs(UnmanagedType.Bool)]
        public bool bSecurityEnabled;
        [MarshalAs(UnmanagedType.Bool)]
        public bool bOneXEnabled;
        public DOT11_AUTH_ALGORITHM dot11AuthAlgorithm;
        public DOT11_CIPHER_ALGORITHM dot11CipherAlgorithm;
    }

    [DllImport("wlanapi.dll", SetLastError = true)]
    public static extern uint WlanCloseHandle(
        IntPtr hClientHandle,
        IntPtr pReserved);

    [DllImport("wlanapi.dll", SetLastError = true)]
    public static extern uint WlanConnect(
        IntPtr hClientHandle,
        ref Guid pInterfaceGuid,
        ref WLAN_CONNECTION_PARAMETERS pConnectionParameters,
        IntPtr pReserved);

    [DllImport("wlanapi.dll", SetLastError = true)]
    public static extern uint WlanDisconnect(
        IntPtr hClientHandle,
        ref Guid pInterfaceGuid,
        IntPtr pReserved);

    [DllImport("wlanapi.dll", SetLastError = true)]
    public static extern uint WlanEnumInterfaces(
        IntPtr hClientHandle,
        IntPtr pReserved,
        out IntPtr ppInterfaceList);

    [DllImport("wlanapi.dll", SetLastError = true)]
    public static extern void WlanFreeMemory(
        IntPtr pMemory);

    [DllImport("wlanapi.dll", SetLastError = true)]
    public static extern uint WlanGetAvailableNetworkList(
        IntPtr hClientHandle,
        ref Guid pInterfaceGuid,
        uint dwFlags,
        IntPtr pReserved,
        out IntPtr ppAvailableNetworkList);

    [DllImport("wlanapi.dll", SetLastError = true)]
    public static extern uint WlanGetNetworkBssList(
        IntPtr hClientHandle,
        ref Guid pInterfaceGuid,
        IntPtr pDot11Ssid,
        DOT11_BSS_TYPE dot11BssType,
        int bSecurityEnabled,
        IntPtr pReserved,
        out IntPtr ppWlanBssList);

    [DllImport("wlanapi.dll", SetLastError = true)]
    public static extern uint WlanOpenHandle(
        uint dwClientVersion,
        IntPtr pReserved,
        out uint pdwNegotiatedVersion,
        out IntPtr phClientHandle);

    [DllImport("wlanapi.dll", SetLastError = true)]
    public static extern uint WlanQueryInterface(
        IntPtr hClientHandle,
        ref Guid pInterfaceGuid,
        WLAN_INTF_OPCODE OpCode,
        IntPtr pReserved,
        out int pdwDataSize,
        out IntPtr ppData,
        out WLAN_OPCODE_VALUE_TYPE pWlanOpcodeValueType);

    [DllImport("wlanapi.dll", SetLastError = true)]
    public static extern uint WlanScan(
        IntPtr hClientHandle,
        ref Guid pInterfaceGuid,
        IntPtr pDot11Ssid,
        IntPtr pIeData,
        IntPtr pReserved);
}
