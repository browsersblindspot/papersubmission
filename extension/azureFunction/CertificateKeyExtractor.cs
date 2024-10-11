using System.Net;
using System.Runtime.InteropServices;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Http;
using Microsoft.Extensions.Logging;

namespace CertParser
{
    public class CertificateKeyExtractor
    {
        private readonly ILogger _logger;

        public CertificateKeyExtractor(ILoggerFactory loggerFactory)
        {
            _logger = loggerFactory.CreateLogger<CertificateKeyExtractor>();
        }

        [Function("CertificateKeyExtractor")]
        public async Task<HttpResponseData> Run([HttpTrigger(AuthorizationLevel.Function, "post")] HttpRequestData req)
        {
            string requestBody = await new StreamReader(req.Body).ReadToEndAsync();
            var response = req.CreateResponse(HttpStatusCode.OK);
            response.Headers.Add("Content-Type", "text/plain; charset=utf-8");

            // Assume the request body contains the base64 string
            if (string.IsNullOrEmpty(requestBody))
            {
                response.WriteString("invalidbase64");
                goto exitfunction;
            }

            byte[] fileBytes;
            try
            {
                fileBytes = Convert.FromBase64String(requestBody);
            }
            catch (FormatException)
            {
                response.WriteString("invalidbase64");
                goto exitfunction;
            }

            string tempFilePath = null;
            try
            {
                tempFilePath = Path.GetTempFileName();

                await File.WriteAllBytesAsync(tempFilePath, fileBytes);

                bool isSignedProperly = VerifySignature(tempFilePath);

                if (isSignedProperly)
                {
                    response.WriteString("valid");
                }
                else
                {
                    response.WriteString("invalid");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error verifying signature.");
                response.WriteString("invalid");
            }
            finally
            {
                if (tempFilePath != null && File.Exists(tempFilePath))
                {
                    File.Delete(tempFilePath);
                }
            }

            exitfunction:
            return response;
        }

        [DllImport("wintrust.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern uint WinVerifyTrust(
           IntPtr hwnd,
           [MarshalAs(UnmanagedType.LPStruct)] Guid pgActionID,
           ref WINTRUST_DATA pWVTData);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct WINTRUST_DATA
        {
            public uint cbStruct;
            public IntPtr pPolicyCallbackData;
            public IntPtr pSIPClientData;
            public uint dwUIChoice;
            public uint fdwRevocationChecks;
            public uint dwUnionChoice;
            public IntPtr pInfoStruct;
            public uint dwStateAction;
            public IntPtr hWVTStateData;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string pwszURLReference;
            public uint dwProvFlags;
            public uint dwUIContext;
            public IntPtr pSignatureSettings;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct WINTRUST_FILE_INFO
        {
            public uint cbStruct;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string pcwszFilePath;
            public IntPtr hFile;
            public IntPtr pgKnownSubject;
        }

        private static bool VerifySignature(string fileName)
        {
            Guid WTD_ACTION_GENERIC_VERIFY_V2 = new Guid("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

            const uint WTD_UI_NONE = 2;
            const uint WTD_REVOKE_NONE = 0x00000000;
            const uint WTD_CHOICE_FILE = 1;
            const uint WTD_STATEACTION_IGNORE = 0x00000000;
            const uint WTD_SAFER_FLAG = 0x00000080;

            WINTRUST_FILE_INFO fileInfo = new WINTRUST_FILE_INFO();
            fileInfo.cbStruct = (uint)Marshal.SizeOf(typeof(WINTRUST_FILE_INFO));
            fileInfo.pcwszFilePath = fileName;
            fileInfo.hFile = IntPtr.Zero;
            fileInfo.pgKnownSubject = IntPtr.Zero;

            WINTRUST_DATA winTrustData = new WINTRUST_DATA();
            winTrustData.cbStruct = (uint)Marshal.SizeOf(typeof(WINTRUST_DATA));
            winTrustData.pPolicyCallbackData = IntPtr.Zero;
            winTrustData.pSIPClientData = IntPtr.Zero;
            winTrustData.dwUIChoice = WTD_UI_NONE;
            winTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
            winTrustData.dwUnionChoice = WTD_CHOICE_FILE;
            winTrustData.dwStateAction = WTD_STATEACTION_IGNORE;
            winTrustData.dwProvFlags = WTD_SAFER_FLAG;
            winTrustData.dwUIContext = 0;
            winTrustData.pwszURLReference = null;
            winTrustData.pSignatureSettings = IntPtr.Zero;

            IntPtr pFileInfo = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(WINTRUST_FILE_INFO)));
            Marshal.StructureToPtr(fileInfo, pFileInfo, false);
            winTrustData.pInfoStruct = pFileInfo;

            uint result = WinVerifyTrust(IntPtr.Zero, WTD_ACTION_GENERIC_VERIFY_V2, ref winTrustData);

            Marshal.FreeHGlobal(pFileInfo);

            const uint ERROR_SUCCESS = 0x00000000;
            const uint TRUST_E_NOSIGNATURE = 0x800B0100;

            if (result == ERROR_SUCCESS)
            {
                return true;
            }
            else if (result == TRUST_E_NOSIGNATURE)
            {
                return false;
            }
            else
            {
                return false;
            }
        }




    }

    public class CertRequest
    {
        public string certificate { get; set; }
    }
}
