using System;
using System.Runtime.InteropServices;
using System.Text;

namespace WlanApiWrapper;

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

public class AvailableNetwork
{
    public string profileName = "";
    public string dot11Ssid = "";
    public DOT11_BSS_TYPE dot11BssType;
    public uint numberOfBssids;
    public int networkConnectable;
    public uint wlanNotConnectableReason;
    public uint numberOfPhyTypes;
    public DOT11_PHY_TYPE[] dot11PhyTypes = [];
    public bool morePhyTypes;
    public uint wlanSignalQuality;
    public bool securityEnabled;
    public DOT11_AUTH_ALGORITHM dot11DefaultAuthAlgorithm;
    public DOT11_CIPHER_ALGORITHM dot11DefaultCipherAlgorithm;
    public uint flags;
    public uint reserved;
}

public class BssEntry
{
    public string dot11Ssid = "";
    public uint phyId;
    public string dot11Bssid = "";
    public DOT11_BSS_TYPE dot11BssType;
    public DOT11_PHY_TYPE dot11BssPhyType;
    public int rssi;
    public uint linkQuality;
    public bool inRegDomain;
    public ushort beaconPeriod;
    public ulong timestamp;
    public ulong hostTimestamp;
    public ushort capabilityInformation;
    public uint chCenterFrequency;
    public ushort[] wlanRateSet = [];
    public uint ieOffset;
    public uint ieSize;
}

public class ConnectionParameters
{
    public WLAN_CONNECTION_MODE wlanConnectionMode;
    public string profile = "";
    public string dot11Ssid = "";
    public string[] desiredBssidList = [];
    public DOT11_BSS_TYPE dot11BssType;
    public uint flags;
}

public class InterfaceInfo
{
    public Guid interfaceGuid;
    public string interfaceDescription = "";
    public WLAN_INTERFACE_STATE state;
}

public class Client : IDisposable
{
    public const int BSSID_BYTES_LENGTH = 6;
    public const int BSSID_STRING_LENGTH = 12;
    public const int DOT11_RATE_SET_MAX_LENGTH = 126;
    public const int MAX_SSID_BYTES_LENGTH = 32;
    public const uint WLAN_CLIENT_VERSION = 2;
    public const int WLAN_MAX_NAME_LENGTH = 256;
    public const int WLAN_MAX_PHY_TYPE_NUMBER = 8;

    private IntPtr clientHandle = IntPtr.Zero;
    private uint negotiatedVersion = 0;
    public uint NegotiatedVersion { get { return negotiatedVersion; } }

    public Client()
    {
        var result = Raw.WlanOpenHandle(WLAN_CLIENT_VERSION, IntPtr.Zero, out negotiatedVersion, out clientHandle);
        if (result != 0)
        {
            string pStringBuffer = new string(' ', 256);
            Raw.WlanReasonCodeToString(result, 256, pStringBuffer, IntPtr.Zero);
            throw new Exception($"WlanOpenHandle failed with reason code {result} ({pStringBuffer})");
        }
    }

    public void Dispose()
    {
        if (clientHandle != IntPtr.Zero)
        {
            Raw.WlanCloseHandle(clientHandle, IntPtr.Zero);
            clientHandle = IntPtr.Zero;
        }
    }

    private static string ByteArrayToHexString(byte[] bytes)
    {
        return BitConverter.ToString(bytes).Replace("-", "").ToLowerInvariant();
    }

    private static byte[] HexStringToByteArray(string hex)
    {
        if (hex.Length % 2 != 0)
            throw new ArgumentException("Hex string must have an even length.");

        byte[] bytes = new byte[hex.Length / 2];
        for (int i = 0; i < bytes.Length; i++)
        {
            bytes[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
        }
        return bytes;
    }

    private static IntPtr CreateUnmanagedDot11BssidList(string[] bssidList)
    {
        int headerSize = Marshal.SizeOf<Raw.NDIS_OBJECT_HEADER>();
        int bssidCount = bssidList.Length;
        int totalSize = headerSize + (2 * sizeof(uint)) + (BSSID_BYTES_LENGTH * bssidCount);
        int offset = 0;
        IntPtr ptr = Marshal.AllocHGlobal(totalSize);
        var header = new Raw.NDIS_OBJECT_HEADER
        {
            Type = 0x80,
            Revision = 1,
            Size = (ushort)headerSize,
        };
        Marshal.StructureToPtr(header, ptr, false);
        offset += headerSize;
        Marshal.WriteInt32(ptr, offset, bssidCount);
        offset += sizeof(uint);
        Marshal.WriteInt32(ptr, offset, bssidCount);
        offset += sizeof(uint);
        for (int i = 0; i < bssidCount; i++)
        {
            if (bssidList[i].Length != BSSID_STRING_LENGTH)
                throw new ArgumentException($"BSSID must be {BSSID_STRING_LENGTH} hexadecimal characters (no separators)");
            var bssid = new Raw.DOT11_MAC_ADDRESS
            {
                ucDot11MacAddress = HexStringToByteArray(bssidList[i]),
            };
            Marshal.StructureToPtr(bssid, IntPtr.Add(ptr, offset), false);
            offset += BSSID_BYTES_LENGTH;
        }
        return ptr;
    }

    private static IntPtr CreateUnmanagedDot11Ssid(string ssidStr)
    {
        byte[] ssidBytes = Encoding.ASCII.GetBytes(ssidStr);
        if (ssidBytes.Length > MAX_SSID_BYTES_LENGTH)
            return IntPtr.Zero;
        Raw.DOT11_SSID dot11Ssid = new Raw.DOT11_SSID
        {
            uSSIDLength = (uint)ssidBytes.Length,
            ucSSID = new byte[MAX_SSID_BYTES_LENGTH]
        };
        Array.Copy(ssidBytes, dot11Ssid.ucSSID, ssidBytes.Length);
        IntPtr ptr = Marshal.AllocHGlobal(Marshal.SizeOf<Raw.DOT11_SSID>());
        Marshal.StructureToPtr(dot11Ssid, ptr, false);
        return ptr;
    }

    public uint Connect(Guid interfaceGuid, ConnectionParameters connParams)
    {
        IntPtr ssidPtr = IntPtr.Zero;
        IntPtr bssidListPtr = IntPtr.Zero;
        try
        {
            var connParamsStruct = new Raw.WLAN_CONNECTION_PARAMETERS
            {
                wlanConnectionMode = connParams.wlanConnectionMode,
                strProfile = connParams.profile,
                pDot11Ssid = ssidPtr = CreateUnmanagedDot11Ssid(connParams.dot11Ssid),
                pDesiredBssidList = bssidListPtr = CreateUnmanagedDot11BssidList(connParams.desiredBssidList),
                dot11BssType = connParams.dot11BssType,
                dwFlags = connParams.flags,
            };
            return Raw.WlanConnect(clientHandle, ref interfaceGuid, ref connParamsStruct, IntPtr.Zero);
        }
        finally
        {
            if (ssidPtr != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(ssidPtr);
            }
            if (bssidListPtr != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(bssidListPtr);
            }
        }
    }

    public uint Disconnect(Guid interfaceGuid)
    {
        return Raw.WlanDisconnect(clientHandle, ref interfaceGuid, IntPtr.Zero);
    }

    public InterfaceInfo[] EnumInterfaces()
    {
        IntPtr ppInterfaceList;
        InterfaceInfo[] interfaceInfoList = [];
        var result = Raw.WlanEnumInterfaces(clientHandle, IntPtr.Zero, out ppInterfaceList);
        if (result != 0)
        {
            return interfaceInfoList;
        }
        try
        {
            int offset = 0;
            var numberOfItems = (uint)Marshal.ReadInt32(ppInterfaceList, offset);
            offset += sizeof(uint);
            var index = (uint)Marshal.ReadInt32(ppInterfaceList, offset);
            offset += sizeof(uint);
            if (numberOfItems > 0)
            {
                interfaceInfoList = new InterfaceInfo[numberOfItems];
                int interfaceInfoSize = Marshal.SizeOf<Raw.WLAN_INTERFACE_INFO>();
                for (int i = 0; i < numberOfItems; i++)
                {
                    Raw.WLAN_INTERFACE_INFO interfaceInfo = Marshal.PtrToStructure<Raw.WLAN_INTERFACE_INFO>(IntPtr.Add(ppInterfaceList, offset));
                    interfaceInfoList[i] = new InterfaceInfo();
                    interfaceInfoList[i].interfaceGuid = interfaceInfo.InterfaceGuid;
                    interfaceInfoList[i].interfaceDescription = interfaceInfo.strInterfaceDescription;
                    interfaceInfoList[i].state = interfaceInfo.isState;
                    offset += interfaceInfoSize;
                }
            }
        }
        finally
        {
            Raw.WlanFreeMemory(ppInterfaceList);
        }
        return interfaceInfoList;
    }

    public AvailableNetwork[] GetAvailableNetworkList(Guid interfaceGuid, uint flags)
    {
        IntPtr ppAvailableNetworkList;
        AvailableNetwork[] availableNetworkList = [];
        var result = Raw.WlanGetAvailableNetworkList(clientHandle, ref interfaceGuid, flags, IntPtr.Zero, out ppAvailableNetworkList);
        if (result != 0)
        {
            return availableNetworkList;
        }
        try
        {
            int offset = 0;
            var numberOfItems = Marshal.ReadInt32(ppAvailableNetworkList, offset);
            offset += sizeof(uint);
            var index = Marshal.ReadInt32(ppAvailableNetworkList, offset);
            offset += sizeof(uint);
            if (numberOfItems > 0)
            {
                availableNetworkList = new AvailableNetwork[numberOfItems];
                int availableNetworkSize = Marshal.SizeOf<Raw.WLAN_AVAILABLE_NETWORK>();
                for (int i = 0; i < numberOfItems; i++)
                {
                    Raw.WLAN_AVAILABLE_NETWORK availableNetwork = Marshal.PtrToStructure<Raw.WLAN_AVAILABLE_NETWORK>(IntPtr.Add(ppAvailableNetworkList, offset));
                    availableNetworkList[i] = new AvailableNetwork();
                    availableNetworkList[i].profileName = availableNetwork.strProfileName;
                    availableNetworkList[i].dot11Ssid = Encoding.ASCII.GetString(availableNetwork.dot11Ssid.ucSSID, 0, (int)availableNetwork.dot11Ssid.uSSIDLength);
                    availableNetworkList[i].dot11BssType = availableNetwork.dot11BssType;
                    availableNetworkList[i].numberOfBssids = availableNetwork.uNumberOfBssids;
                    availableNetworkList[i].networkConnectable = availableNetwork.bNetworkConnectable;
                    availableNetworkList[i].wlanNotConnectableReason = availableNetwork.wlanNotConnectableReason;
                    availableNetworkList[i].numberOfPhyTypes = availableNetwork.uNumberOfPhyTypes;
                    availableNetworkList[i].dot11PhyTypes = availableNetwork.dot11PhyTypes;
                    availableNetworkList[i].morePhyTypes = availableNetwork.bMorePhyTypes != 0;
                    availableNetworkList[i].wlanSignalQuality = availableNetwork.wlanSignalQuality;
                    availableNetworkList[i].securityEnabled = availableNetwork.bSecurityEnabled != 0;
                    availableNetworkList[i].dot11DefaultAuthAlgorithm = availableNetwork.dot11DefaultAuthAlgorithm;
                    availableNetworkList[i].dot11DefaultCipherAlgorithm = availableNetwork.dot11DefaultCipherAlgorithm;
                    availableNetworkList[i].flags = availableNetwork.dwFlags;
                    availableNetworkList[i].reserved = availableNetwork.dwReserved;
                    offset += availableNetworkSize;
                }
            }
        }
        finally
        {
            Raw.WlanFreeMemory(ppAvailableNetworkList);
        }
        return availableNetworkList;
    }

    public BssEntry[] GetNetworkBssList(Guid interfaceGuid, string dot11Ssid, DOT11_BSS_TYPE dot11BssType, bool securityEnabled)
    {
        IntPtr ppWlanBssList = IntPtr.Zero;
        BssEntry[] bssEntryList = [];
        IntPtr pDot11Ssid = IntPtr.Zero;
        try
        {
            if (dot11Ssid != "")
            {
                pDot11Ssid = CreateUnmanagedDot11Ssid(dot11Ssid);
            }
            var result = Raw.WlanGetNetworkBssList(clientHandle, ref interfaceGuid, pDot11Ssid, dot11BssType, securityEnabled ? 1 : 0, IntPtr.Zero, out ppWlanBssList);
            if (result != 0)
            {
                return bssEntryList;
            }
            int offset = 0;
            var totalSize = Marshal.ReadInt32(ppWlanBssList, offset);
            offset += sizeof(uint);
            var numberOfItems = Marshal.ReadInt32(ppWlanBssList, offset);
            offset += sizeof(uint);
            if (numberOfItems > 0)
            {
                bssEntryList = new BssEntry[numberOfItems];
                int bssEntrySize = Marshal.SizeOf<Raw.WLAN_BSS_ENTRY>();
                for (int i = 0; i < numberOfItems; i++)
                {
                    Raw.WLAN_BSS_ENTRY bssEntry = Marshal.PtrToStructure<Raw.WLAN_BSS_ENTRY>(IntPtr.Add(ppWlanBssList, offset));
                    bssEntryList[i] = new BssEntry();
                    bssEntryList[i].dot11Ssid = Encoding.ASCII.GetString(bssEntry.dot11Ssid.ucSSID, 0, (int)bssEntry.dot11Ssid.uSSIDLength);
                    bssEntryList[i].phyId = bssEntry.uPhyId;
                    bssEntryList[i].dot11Bssid = ByteArrayToHexString(bssEntry.dot11Bssid.ucDot11MacAddress);
                    bssEntryList[i].dot11BssType = bssEntry.dot11BssType;
                    bssEntryList[i].dot11BssPhyType = bssEntry.dot11BssPhyType;
                    bssEntryList[i].rssi = bssEntry.lRssi;
                    bssEntryList[i].linkQuality = bssEntry.uLinkQuality;
                    bssEntryList[i].inRegDomain = bssEntry.bInRegDomain != 0;
                    bssEntryList[i].beaconPeriod = bssEntry.usBeaconPeriod;
                    bssEntryList[i].timestamp = bssEntry.ullTimestamp;
                    bssEntryList[i].hostTimestamp = bssEntry.ullHostTimestamp;
                    bssEntryList[i].capabilityInformation = bssEntry.usCapabilityInformation;
                    bssEntryList[i].chCenterFrequency = bssEntry.ulChCenterFrequency;
                    bssEntryList[i].wlanRateSet = bssEntry.wlanRateSet.usRateSet;
                    bssEntryList[i].ieOffset = bssEntry.ulIeOffset;
                    bssEntryList[i].ieSize = bssEntry.ulIeSize;
                    offset += bssEntrySize;
                }
            }
        }
        finally
        {
            if (pDot11Ssid != IntPtr.Zero)
            {
                Raw.WlanFreeMemory(pDot11Ssid);
            }
            Raw.WlanFreeMemory(ppWlanBssList);
        }
        return bssEntryList;
    }

    public uint Scan(Guid interfaceGuid)
    {
        // This function returns immidiately.
        // Actual scan will be completed within 4 seconds.
        return Raw.WlanScan(clientHandle, ref interfaceGuid, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
    }

    public class Raw
    {
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

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct WLAN_AVAILABLE_NETWORK
        {
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = WLAN_MAX_NAME_LENGTH)]
            public string strProfileName;
            public DOT11_SSID dot11Ssid;
            public DOT11_BSS_TYPE dot11BssType;
            public uint uNumberOfBssids;
            public int bNetworkConnectable;
            public uint wlanNotConnectableReason;
            public uint uNumberOfPhyTypes;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = WLAN_MAX_PHY_TYPE_NUMBER)]
            public DOT11_PHY_TYPE[] dot11PhyTypes;
            public int bMorePhyTypes;
            public uint wlanSignalQuality;
            public int bSecurityEnabled;
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
        public static extern void WlanFreeMemory(IntPtr pMemory);

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

        [DllImport("Wlanapi.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern uint WlanReasonCodeToString(
            uint dwReasonCode,
            uint dwBufferSize,
            string pStringBuffer,
            IntPtr pReserved);

        [DllImport("Wlanapi.dll", SetLastError = true)]
        public static extern uint WlanScan(
            IntPtr hClientHandle,
            ref Guid pInterfaceGuid,
            IntPtr pDot11Ssid,
            IntPtr pIeData,
            IntPtr pReserved);
    }
}
