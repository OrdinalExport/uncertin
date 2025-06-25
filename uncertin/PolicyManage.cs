using System.Reflection;
using System.Runtime.InteropServices;
using CERTPOLICYLib;

namespace uncertin
{
    [ComVisible(true)]
    [ClassInterface(ClassInterfaceType.None)]
    [ProgId("uncertin.PolicyManage")]
    [Guid("24738F5D-C7B2-4F7F-B134-6B0DF755A3F2")]
    public class PolicyManage : CCertManagePolicyModule
    {
        public dynamic GetProperty(string strConfig, string strStorageLocation, string strPropertyName, int Flags)
        {
            var assembly = Assembly.GetExecutingAssembly();

            switch(strPropertyName)
            {
                case "Name":
                    return "uncertin";
                case "Description":
                    return "A custom honey policy module extension for Active Directory Certificate Services.";
                case "Copyright":
                    return "Copyright © OrdinalExport 2025";
                case "File Version":
                    return "0.1";
                case "Product Version":
                    return "0.1";
                default:
                    return $"Unknown Property: {strPropertyName}";
            }
        }

        public void SetProperty(string strConfig, string strStorageLocation, string strPropertyName, int Flags, ref object pvarProperty)
        {
            //
        }

        public void Configure(string strConfig, string strStorageLocation, int Flags)
        {
            //
        }
    }
}
