using System;
using System.Runtime.InteropServices;
using CERTCLILib;

public static class CertServerPolicyExtensions
{
    [StructLayout(LayoutKind.Sequential)]
    struct VARIANT
    {
        public short vt;
        public short reserved1;
        public short reserved2;
        public short reserved3;
        public IntPtr pvRecord; // For VT_BSTR, this points to the data (after 4-byte length)
        public IntPtr reserved;
    }

    public static void SetCertificateExtension(this CCertServerPolicy serverPolicy, string oid, byte[] value, bool critical = false)
    {
        // Allocate BSTR: 4-byte length prefix + data
        var pBstr = Marshal.AllocHGlobal(value.Length + 4);
        Marshal.WriteInt32(pBstr, value.Length); // Length prefix
        Marshal.Copy(value, 0, pBstr + 4, value.Length);

        var variant = new VARIANT
        {
            vt = (short)8, // VT_BSTR
            reserved1 = 0,
            reserved2 = 0,
            reserved3 = 0,
            pvRecord = pBstr + 4, // point to start of data (skipping length)
            reserved = IntPtr.Zero
        };

        var pvarValue = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(VARIANT)));
        Marshal.StructureToPtr(variant, pvarValue, false);

        int dwCritical = critical ? 0x1 : 0; // EXTENSION_CRITICAL_FLAG = 0x1

        try
        {
            serverPolicy.SetCertificateExtension(oid, 3, dwCritical, pvarValue); // 3 = PROPTYPE_BINARY
        }
        finally
        {
            Marshal.FreeHGlobal(pBstr);
            Marshal.FreeHGlobal(pvarValue);
        }
    }
}