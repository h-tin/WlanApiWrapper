using System;
using System.Runtime.InteropServices;
using System.Text;

namespace WlanApiWrapper;

public class AssociationAttributes
{
    public string dot11Ssid = "";
    public API.DOT11_BSS_TYPE dot11BssType;
    public string dot11Bssid = "";
    public API.DOT11_PHY_TYPE dot11PhyType;
    public uint dot11PhyIndex;
    public uint wlanSignalQuality;
    public uint rxRate;
    public uint txRate;
}

public class AvailableNetwork
{
    public string profileName = "";
    public string dot11Ssid = "";
    public API.DOT11_BSS_TYPE dot11BssType;
    public uint numberOfBssids;
    public bool networkConnectable;
    public uint wlanNotConnectableReason;
    public uint numberOfPhyTypes;
    public API.DOT11_PHY_TYPE[] dot11PhyTypes = [];
    public bool morePhyTypes;
    public uint wlanSignalQuality;
    public bool securityEnabled;
    public API.DOT11_AUTH_ALGORITHM dot11DefaultAuthAlgorithm;
    public API.DOT11_CIPHER_ALGORITHM dot11DefaultCipherAlgorithm;
    public uint flags;
    public uint reserved;

    public static AvailableNetwork FromStructPtr(IntPtr ptr)
    {
        var c = new AvailableNetwork();
        var s = Marshal.PtrToStructure<API.WLAN_AVAILABLE_NETWORK>(ptr);
        c.profileName = s.strProfileName;
        c.dot11Ssid = Ssid.StructToString(s.dot11Ssid);
        c.dot11BssType = s.dot11BssType;
        c.numberOfBssids = s.uNumberOfBssids;
        c.networkConnectable = s.bNetworkConnectable;
        c.wlanNotConnectableReason = s.wlanNotConnectableReason;
        c.numberOfPhyTypes = s.uNumberOfPhyTypes;
        c.dot11PhyTypes = s.dot11PhyTypes;
        c.morePhyTypes = s.bMorePhyTypes;
        c.wlanSignalQuality = s.wlanSignalQuality;
        c.securityEnabled = s.bSecurityEnabled;
        c.dot11DefaultAuthAlgorithm = s.dot11DefaultAuthAlgorithm;
        c.dot11DefaultCipherAlgorithm = s.dot11DefaultCipherAlgorithm;
        c.flags = s.dwFlags;
        c.reserved = s.dwReserved;
        return c;
    }
}

public class AvailableNetworkList
{
    public static AvailableNetwork[] FromStructPtr(IntPtr ptr)
    {
        int offset = 0;
        var numberOfItems = Marshal.ReadInt32(ptr, offset);
        offset += sizeof(uint);
        // uint index;
        offset += sizeof(uint);
        if (numberOfItems > 0)
        {
            var list = new AvailableNetwork[numberOfItems];
            for (int i = 0; i < numberOfItems; i++)
            {
                list[i] = AvailableNetwork.FromStructPtr(IntPtr.Add(ptr, offset));
                offset += Marshal.SizeOf<API.WLAN_AVAILABLE_NETWORK>();
            }
            return list;
        }
        return [];
    }
}

public class Bssid
{
    public static string StructToString(API.DOT11_MAC_ADDRESS dot11Bssid)
    {
        return BitConverter.ToString(dot11Bssid.ucDot11MacAddress).Replace("-", "").ToLowerInvariant();
    }

    public static API.DOT11_MAC_ADDRESS StringToStruct(string bssid)
    {
        if (bssid.Length != API.BSSID_BYTES_LENGTH * 2)
        {
            throw new ArgumentException($"BSSID must be {API.BSSID_BYTES_LENGTH * 2} hexadecimal characters (no separators)");
        }
        byte[] bytes = new byte[bssid.Length / 2];
        for (int i = 0; i < bytes.Length; i++)
        {
            bytes[i] = Convert.ToByte(bssid.Substring(i * 2, 2), 16);
        }
        var dot11Bssid = new API.DOT11_MAC_ADDRESS
        {
            ucDot11MacAddress = bytes,
        };
        return dot11Bssid;
    }
}

public class BssidList
{
    public static IntPtr ToStructPtr(string[] bssidList)
    {
        int headerSize = Marshal.SizeOf<API.NDIS_OBJECT_HEADER>();
        int bssidCount = bssidList.Length;
        int totalSize = headerSize + (2 * sizeof(uint)) + (API.BSSID_BYTES_LENGTH * bssidCount);
        int offset = 0;
        IntPtr ptr = Marshal.AllocHGlobal(totalSize);
        var header = new API.NDIS_OBJECT_HEADER
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
            var bssid = Bssid.StringToStruct(bssidList[i]);
            Marshal.StructureToPtr(bssid, IntPtr.Add(ptr, offset), false);
            offset += API.BSSID_BYTES_LENGTH;
        }
        return ptr;
    }
}

public class BssEntry
{
    public string dot11Ssid = "";
    public uint phyId;
    public string dot11Bssid = "";
    public API.DOT11_BSS_TYPE dot11BssType;
    public API.DOT11_PHY_TYPE dot11BssPhyType;
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

    public static BssEntry FromStructPtr(IntPtr ptr)
    {
        var c = new BssEntry();
        var s = Marshal.PtrToStructure<API.WLAN_BSS_ENTRY>(ptr);
        c.dot11Ssid = Ssid.StructToString(s.dot11Ssid);
        c.phyId = s.uPhyId;
        c.dot11Bssid = Bssid.StructToString(s.dot11Bssid);
        c.dot11BssType = s.dot11BssType;
        c.dot11BssPhyType = s.dot11BssPhyType;
        c.rssi = s.lRssi;
        c.linkQuality = s.uLinkQuality;
        c.inRegDomain = s.bInRegDomain != 0;
        c.beaconPeriod = s.usBeaconPeriod;
        c.timestamp = s.ullTimestamp;
        c.hostTimestamp = s.ullHostTimestamp;
        c.capabilityInformation = s.usCapabilityInformation;
        c.chCenterFrequency = s.ulChCenterFrequency;
        c.wlanRateSet = s.wlanRateSet.usRateSet;
        c.ieOffset = s.ulIeOffset;
        c.ieSize = s.ulIeSize;
        return c;
    }
}

public class BssEntryList
{
    public static BssEntry[] FromStructPtr(IntPtr ptr)
    {
        int offset = 0;
        // uint totalSize;
        offset += sizeof(uint);
        var numberOfItems = Marshal.ReadInt32(ptr, offset);
        offset += sizeof(uint);
        if (numberOfItems > 0)
        {
            var list = new BssEntry[numberOfItems];
            for (int i = 0; i < numberOfItems; i++)
            {
                list[i] = BssEntry.FromStructPtr(IntPtr.Add(ptr, offset));
                offset += Marshal.SizeOf<API.WLAN_BSS_ENTRY>();
            }
            return list;
        }
        return [];
    }
}

public class ConnectionAttributes
{
    public API.WLAN_INTERFACE_STATE state;
    public API.WLAN_CONNECTION_MODE wlanConnectionMode;
    public string profileName = "";
    public AssociationAttributes wlanAssociationAttributes = new AssociationAttributes();
    public SecurityAttributes wlanSecurityAttributes = new SecurityAttributes();

    public static ConnectionAttributes FromStructPtr(IntPtr ptr)
    {
        var c = new ConnectionAttributes();
        var s = Marshal.PtrToStructure<API.WLAN_CONNECTION_ATTRIBUTES>(ptr);
        c.state = s.isState;
        c.wlanConnectionMode = s.wlanConnectionMode;
        c.profileName = s.strProfileName;
        c.wlanAssociationAttributes.dot11Ssid = Ssid.StructToString(s.wlanAssociationAttributes.dot11Ssid);
        c.wlanAssociationAttributes.dot11BssType = s.wlanAssociationAttributes.dot11BssType;
        c.wlanAssociationAttributes.dot11Bssid = Bssid.StructToString(s.wlanAssociationAttributes.dot11Bssid);
        c.wlanAssociationAttributes.dot11PhyType = s.wlanAssociationAttributes.dot11PhyType;
        c.wlanAssociationAttributes.dot11PhyIndex = s.wlanAssociationAttributes.uDot11PhyIndex;
        c.wlanAssociationAttributes.wlanSignalQuality = s.wlanAssociationAttributes.wlanSignalQuality;
        c.wlanAssociationAttributes.rxRate = s.wlanAssociationAttributes.ulRxRate;
        c.wlanAssociationAttributes.txRate = s.wlanAssociationAttributes.ulTxRate;
        c.wlanSecurityAttributes.securityEnabled = s.wlanSecurityAttributes.bSecurityEnabled;
        c.wlanSecurityAttributes.oneXEnabled = s.wlanSecurityAttributes.bOneXEnabled;
        c.wlanSecurityAttributes.dot11AuthAlgorithm = s.wlanSecurityAttributes.dot11AuthAlgorithm;
        c.wlanSecurityAttributes.dot11CipherAlgorithm = s.wlanSecurityAttributes.dot11CipherAlgorithm;
        return c;
    }
}

public class ConnectionParameters
{
    public API.WLAN_CONNECTION_MODE wlanConnectionMode;
    public string profile = "";
    public string dot11Ssid = "";
    public string[] desiredBssidList = [];
    public API.DOT11_BSS_TYPE dot11BssType;
    public uint flags;
}

public class InterfaceInfo
{
    public Guid interfaceGuid;
    public string interfaceDescription = "";
    public API.WLAN_INTERFACE_STATE state;

    public static InterfaceInfo FromStructPtr(IntPtr ptr)
    {
        var c = new InterfaceInfo();
        var s = Marshal.PtrToStructure<API.WLAN_INTERFACE_INFO>(ptr);
        c.interfaceGuid = s.InterfaceGuid;
        c.interfaceDescription = s.strInterfaceDescription;
        c.state = s.isState;
        return c;
    }
}

public class InterfaceInfoList
{
    public static InterfaceInfo[] FromStructPtr(IntPtr ptr)
    {
        int offset = 0;
        var numberOfItems = (uint)Marshal.ReadInt32(ptr, offset);
        offset += sizeof(uint);
        // uint index;
        offset += sizeof(uint);
        if (numberOfItems > 0)
        {
            var list = new InterfaceInfo[numberOfItems];
            for (int i = 0; i < numberOfItems; i++)
            {
                list[i] = InterfaceInfo.FromStructPtr(IntPtr.Add(ptr, offset));
                offset += Marshal.SizeOf<API.WLAN_INTERFACE_INFO>();
            }
            return list;
        }
        return [];
    }
}

public class SecurityAttributes
{
    [MarshalAs(UnmanagedType.Bool)]
    public bool securityEnabled;
    [MarshalAs(UnmanagedType.Bool)]
    public bool oneXEnabled;
    public API.DOT11_AUTH_ALGORITHM dot11AuthAlgorithm;
    public API.DOT11_CIPHER_ALGORITHM dot11CipherAlgorithm;
}

public class Ssid
{
    public static IntPtr ToStructPtr(string ssid)
    {
        IntPtr ptr = Marshal.AllocHGlobal(Marshal.SizeOf<API.DOT11_SSID>());
        Marshal.StructureToPtr(StringToStruct(ssid), ptr, false);
        return ptr;
    }

    public static string StructToString(API.DOT11_SSID dot11Ssid)
    {
        return Encoding.UTF8.GetString(dot11Ssid.ucSSID, 0, (int)dot11Ssid.uSSIDLength);
    }

    public static API.DOT11_SSID StringToStruct(string ssid)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(ssid);
        if (bytes.Length > API.MAX_SSID_BYTES_LENGTH)
        {
            throw new ArgumentException($"SSID must be {API.MAX_SSID_BYTES_LENGTH} characters in bytes");
        }
        API.DOT11_SSID dot11Ssid = new API.DOT11_SSID
        {
            uSSIDLength = (uint)bytes.Length,
            ucSSID = new byte[API.MAX_SSID_BYTES_LENGTH]
        };
        Array.Copy(bytes, dot11Ssid.ucSSID, bytes.Length);
        return dot11Ssid;
    }
}

public class Client : IDisposable
{
    public const int BSSID_STRING_LENGTH = 12;
    public const uint WLAN_CLIENT_VERSION = 2;

    private IntPtr clientHandle = IntPtr.Zero;
    private uint negotiatedVersion = 0;
    public uint NegotiatedVersion { get { return negotiatedVersion; } }

    public Client()
    {
        var result = API.WlanOpenHandle(WLAN_CLIENT_VERSION, IntPtr.Zero, out negotiatedVersion, out clientHandle);
        if (result != 0)
        {
            throw new Exception($"WlanOpenHandle failed with reason code {result}");
        }
    }

    public void Dispose()
    {
        if (clientHandle != IntPtr.Zero)
        {
            API.WlanCloseHandle(clientHandle, IntPtr.Zero);
            clientHandle = IntPtr.Zero;
        }
    }

    public uint Connect(Guid interfaceGuid, ConnectionParameters connParams)
    {
        IntPtr ssidPtr = IntPtr.Zero;
        IntPtr bssidListPtr = IntPtr.Zero;
        try
        {
            ssidPtr = Ssid.ToStructPtr(connParams.dot11Ssid);
            bssidListPtr = BssidList.ToStructPtr(connParams.desiredBssidList);
            var connParamsStruct = new API.WLAN_CONNECTION_PARAMETERS
            {
                wlanConnectionMode = connParams.wlanConnectionMode,
                strProfile = connParams.profile,
                pDot11Ssid = ssidPtr,
                pDesiredBssidList = bssidListPtr,
                dot11BssType = connParams.dot11BssType,
                dwFlags = connParams.flags,
            };
            return API.WlanConnect(clientHandle, ref interfaceGuid, ref connParamsStruct, IntPtr.Zero);
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
        return API.WlanDisconnect(clientHandle, ref interfaceGuid, IntPtr.Zero);
    }

    public InterfaceInfo[] EnumInterfaces()
    {
        IntPtr ppInterfaceList = IntPtr.Zero;
        try
        {
            var result = API.WlanEnumInterfaces(clientHandle, IntPtr.Zero, out ppInterfaceList);
            if (result != 0)
            {
                throw new Exception($"WlanEnumInterfaces(): Error {result}");
            }
            return InterfaceInfoList.FromStructPtr(ppInterfaceList);
        }
        finally
        {
            API.WlanFreeMemory(ppInterfaceList);
        }
    }

    public AvailableNetwork[] GetAvailableNetworkList(Guid interfaceGuid, uint flags)
    {
        IntPtr ppAvailableNetworkList = IntPtr.Zero;
        try
        {
            var result = API.WlanGetAvailableNetworkList(clientHandle, ref interfaceGuid, flags, IntPtr.Zero, out ppAvailableNetworkList);
            if (result != 0)
            {
                throw new Exception($"WlanGetAvailableNetworkList(): Error {result}");
            }
            return AvailableNetworkList.FromStructPtr(ppAvailableNetworkList);
        }
        finally
        {
            API.WlanFreeMemory(ppAvailableNetworkList);
        }
    }

    public BssEntry[] GetNetworkBssList(Guid interfaceGuid, string ssid, API.DOT11_BSS_TYPE dot11BssType, bool securityEnabled)
    {
        IntPtr pDot11Ssid = IntPtr.Zero;
        IntPtr ppWlanBssList = IntPtr.Zero;
        try
        {
            if (ssid != "")
            {
                pDot11Ssid = Ssid.ToStructPtr(ssid);
            }
            var result = API.WlanGetNetworkBssList(clientHandle, ref interfaceGuid, pDot11Ssid, dot11BssType, securityEnabled ? 1 : 0, IntPtr.Zero, out ppWlanBssList);
            if (result != 0)
            {
                throw new Exception($"WlanGetNetworkBssList(): Error {result}");
            }
            return BssEntryList.FromStructPtr(ppWlanBssList);
        }
        finally
        {
            if (pDot11Ssid != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(pDot11Ssid);
            }
            API.WlanFreeMemory(ppWlanBssList);
        }
    }

    public ConnectionAttributes QueryInterfaceCurrentConnection(Guid interfaceGuid)
    {
        IntPtr ppData = IntPtr.Zero;
        try
        {
            var result = API.WlanQueryInterface(clientHandle, ref interfaceGuid, API.WLAN_INTF_OPCODE.wlan_intf_opcode_current_connection, IntPtr.Zero, out int pdwDataSize, out ppData, out API.WLAN_OPCODE_VALUE_TYPE pWlanOpcodeValueType);
            if (result != 0)
            {
                throw new Exception($"WlanQueryInterface(): Error {result}");
            }
            return ConnectionAttributes.FromStructPtr(ppData);
        }
        finally
        {
            if (ppData != IntPtr.Zero)
            {
                API.WlanFreeMemory(ppData);
            }
        }
    }

    public void Scan(Guid interfaceGuid)
    {
        // This function returns immidiately.
        // Actual scan will be completed within 4 seconds.
        var result = API.WlanScan(clientHandle, ref interfaceGuid, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
        if (result != 0)
        {
            throw new Exception($"WlanScan(): Error {result}");
        }
    }
}
