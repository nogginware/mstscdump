/**
 * mstscdump: MSTSC Packet Dump Utility
 * MSTSCAX Packet Dump Hook
 *
 * Copyright 2014-2022 Nogginware Corporation <mikem@nogginware.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define _CRT_SECURE_NO_WARNINGS
#define SECURITY_WIN32
#define WIN32_LEAN_AND_MEAN

#include <intrin.h>
#include <winsock2.h>
#include <sspi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tchar.h>
#include <time.h>
#include <psapi.h>
#include <comdef.h>

#include "NWHookAPI.h"

#if 0
#import "mstscax.dll" named_guids
#else
#include "mstscax.tlh"
#include "mstscax.tli"
#endif

#pragma comment(lib, "ws2_32.lib")

using namespace MSTSCLib;

////////////////////////////////////////////////////////////////////////
//
// Constant Definitions
//
#define REGISTRY_KEY           TEXT("SOFTWARE\\Nogginware\\MsTscHook")

#define PCAP_FILE              "mstscdump.pcap"

#define WRITE_LOG              0

////////////////////////////////////////////////////////////////////////
//
// Type Definitions
//

typedef void (WINAPI *LPCloseThreadpoolIo)(PTP_IO);
typedef PTP_IO (WINAPI *LPCreateThreadpoolIo)(HANDLE, PTP_WIN32_IO_CALLBACK, PVOID, PTP_CALLBACK_ENVIRON);
typedef BOOL (WINAPI *LPGetOverlappedResult)(HANDLE, LPWSAOVERLAPPED, LPDWORD, BOOL);
typedef BOOL (WINAPI *LPGetOverlappedResultEx)(HANDLE, LPWSAOVERLAPPED, LPDWORD, DWORD, BOOL);
typedef void (WINAPI *LPStartThreadpoolIo)(PTP_IO);

typedef HRESULT (WINAPI *LPDllGetClassObject)(REFCLSID rclsid, REFIID riid, LPVOID *ppv);

typedef int (WSAAPI *LPWSAAsyncSelect)(SOCKET, HWND, UINT, long);
typedef int (WSAAPI *LPWSAEnumNetworkEvents)(SOCKET, WSAEVENT, LPWSANETWORKEVENTS);
typedef int (WSAAPI *LPWSAEventSelect)(SOCKET, WSAEVENT, long);
typedef int (WSAAPI *LPWSAGetLastError)();
typedef BOOL (WSAAPI *LPWSAGetOverlappedResult)(SOCKET, LPWSAOVERLAPPED, LPDWORD, BOOL, LPDWORD);
typedef int (WSAAPI *LPWSAIoctl)(SOCKET, DWORD, LPVOID, DWORD, LPVOID, DWORD, LPDWORD, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
typedef int (WSAAPI *LPWSARecv)(SOCKET, LPWSABUF, DWORD, LPDWORD, LPDWORD, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
typedef int (WSAAPI *LPWSASend)(SOCKET, LPWSABUF, DWORD, LPDWORD, DWORD, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
typedef void (WSAAPI *LPWSASetLastError)(int iError);
typedef SOCKET (WSAAPI *LPWSASocketW)(int, int, int, LPWSAPROTOCOL_INFOW, GROUP, DWORD);
typedef DWORD (WSAAPI *LPWSAWaitForMultipleEvents)(DWORD, const WSAEVENT *, BOOL, DWORD, BOOL);
typedef int (WSAAPI *LPgetsockopt)(SOCKET, int, int, char *, int *);
typedef int (WSAAPI *LPioctlsocket)(SOCKET, long cmd, u_long *argp);
typedef int (WSAAPI *LPrecv)(SOCKET, char *, int, int);
typedef int (WSAAPI *LPselect)(int, fd_set *, fd_set *, fd_set *, const timeval *);
typedef int (WSAAPI *LPsend)(SOCKET, char *, int, int);
typedef int (WSAAPI *LPsetsockopt)(SOCKET, int, int, const char *, int);

typedef signed char sint8;
typedef signed short sint16;
typedef signed long sint32;

typedef unsigned char uint8;
typedef unsigned short uint16;
typedef unsigned int uint32;

#pragma pack(push, 1)

typedef struct pcap_hdr_s
{
    uint32 magic_number;    /* magic number */
    uint16 version_major;   /* major version number */
    uint16 version_minor;   /* minor version number */
    sint32 thiszone;        /* GMT to local correction */
    uint32 sigfigs;         /* accuracy of timestamps */
    uint32 snaplen;         /* max length of captured packets, in octets */
    uint32 network;         /* data link type */
} pcap_hdr_t;

typedef struct pcaprec_hdr_s
{
    uint32 ts_sec;          /* timestamp seconds */
    uint32 ts_usec;         /* timestamp microseconds */
    uint32 incl_len;        /* number of octets of packet saved in file */
    uint32 orig_len;        /* actual length of packet */
} pcaprec_hdr_t;

typedef struct ethernet_hdr_s
{
    uint8 dest_addr[6];     /* destination MAC address */
    uint8 source_addr[6];   /* source MAC address */
    uint16 frame_type;      /* ethernet frame type */
} ethernet_hdr_t;

typedef struct ipv4_hdr_s
{
    uint8 version_ihl;      /* version and internet header length (IHL) */
    uint8 dscp_ecn;         /* DSCP and ECN */
    uint16 total_length;    /* total length */
    uint16 identification;  /* identification */
    uint16 flags_fragment_offset;   /* flags and fragment offset */
    uint8 ttl;              /* time to live */
    uint8 protocol;         /* protocol */
    uint16 checksum;        /* header checksum */
    uint32 source_ip_addr;  /* source IP address */
    uint32 dest_ip_addr;    /* destination IP address */
} ipv4_hdr_t;

typedef struct tcp_hdr_s
{
    uint16 source_port;     /* source port */
    uint16 dest_port;       /* destination port */
    uint32 seq_number;      /* sequence number */
    uint32 ack_number;      /* acknowledgement number */
    uint16 flags;           /* data offset and flags */
    uint16 window_size;     /* window size */
    uint16 checksum;        /* checksum */
    uint16 urgent_pointer;  /* urgent pointer */
} tcp_hdr_t;

#pragma pack(pop)

////////////////////////////////////////////////////////////////////////
//
// Data Declarations
//
static HMODULE g_hModule;
static HMODULE g_hModKernel32;
static HMODULE g_hModMsTscAx;
static HMODULE g_hModSspiCli;
static HMODULE g_hModWinsock;
static HANDLE g_hMutex;
static BOOL g_fShowAllBuffers;
static BOOL g_fPCapHeaderWritten;
static BOOL g_fTransportSecured;

static uint8 g_clientMacAddr[6] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 };
static uint8 g_serverMacAddr[6] = { 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6 };

static uint32 g_clientIPAddr = 0xc0a80164;
static uint32 g_serverIPAddr = 0xc0a801c8;

static uint16 g_clientTcpPort = 3389;
static uint16 g_serverTcpPort = 3389;

static uint32 g_clientSeqNumber;
static uint32 g_serverSeqNumber;

static NWHOOKAPI_HOOK(LPCloseThreadpoolIo, Real_CloseThreadpoolIo);
static NWHOOKAPI_HOOK(LPCreateThreadpoolIo, Real_CreateThreadpoolIo);
static NWHOOKAPI_HOOK(LPGetOverlappedResult, Real_GetOverlappedResult);
static NWHOOKAPI_HOOK(LPGetOverlappedResultEx, Real_GetOverlappedResultEx);
static NWHOOKAPI_HOOK(LPStartThreadpoolIo, Real_StartThreadpoolIo);

static NWHOOKAPI_HOOK(LPDllGetClassObject, Real_DllGetClassObject);

static NWHOOKAPI_HOOK(ACCEPT_SECURITY_CONTEXT_FN, Real_AcceptSecurityContext);
static NWHOOKAPI_HOOK(ACQUIRE_CREDENTIALS_HANDLE_FN_A, Real_AcquireCredentialsHandleA);
static NWHOOKAPI_HOOK(ACQUIRE_CREDENTIALS_HANDLE_FN_W, Real_AcquireCredentialsHandleW);
static NWHOOKAPI_HOOK(DECRYPT_MESSAGE_FN, Real_DecryptMessage);
static NWHOOKAPI_HOOK(ENCRYPT_MESSAGE_FN, Real_EncryptMessage);

static NWHOOKAPI_HOOK(LPWSAAsyncSelect, Real_WSAAsyncSelect);
static NWHOOKAPI_HOOK(LPWSAEnumNetworkEvents, Real_WSAEnumNetworkEvents);
static NWHOOKAPI_HOOK(LPWSAEventSelect, Real_WSAEventSelect);
static NWHOOKAPI_HOOK(LPWSAGetLastError, Real_WSAGetLastError);
static NWHOOKAPI_HOOK(LPWSAGetOverlappedResult, Real_WSAGetOverlappedResult);
static NWHOOKAPI_HOOK(LPWSAIoctl, Real_WSAIoctl);
static NWHOOKAPI_HOOK(LPWSARecv, Real_WSARecv);
static NWHOOKAPI_HOOK(LPWSASend, Real_WSASend);
static NWHOOKAPI_HOOK(LPWSASetLastError, Real_WSASetLastError);
static NWHOOKAPI_HOOK(LPWSASocketW, Real_WSASocketW);
static NWHOOKAPI_HOOK(LPWSAWaitForMultipleEvents, Real_WSAWaitForMultipleEvents);
static NWHOOKAPI_HOOK(LPgetsockopt, Real_getsockopt);
static NWHOOKAPI_HOOK(LPioctlsocket, Real_ioctlsocket);
static NWHOOKAPI_HOOK(LPrecv, Real_recv);
static NWHOOKAPI_HOOK(LPselect, Real_select);
static NWHOOKAPI_HOOK(LPsend, Real_send);
static NWHOOKAPI_HOOK(LPsetsockopt, Real_setsockopt);

typedef struct
{
    SOCKET socket;
    WSAOVERLAPPED overlapped;
    LPWSABUF lpBuffers;
    DWORD dwBufferCount;
    LPWSAOVERLAPPED lpOverlapped;
    LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine;
} wsa_context_t;

static wsa_context_t g_wsaRecvContext;
static wsa_context_t g_wsaSendContext;

////////////////////////////////////////////////////////////////////////
//
// Function Prototypes
//
static VOID WriteLog(LPCTSTR, ...);


////////////////////////////////////////////////////////////////////////
//
// COM Utility Functions
//
static VOID WriteCLSID(REFCLSID rclsid)
{
    LPOLESTR polestrCLSID;
    if (StringFromCLSID(rclsid, &polestrCLSID) == S_OK)
    {
        LONG lStatus;
        char szSubKey[128];
        char szValue[128];
        LONG cbValue;

        _bstr_t bstrCLSID = polestrCLSID;

        sprintf(szSubKey, "CLSID\\%s", (LPCTSTR)bstrCLSID);
        ZeroMemory(szValue, sizeof(szValue));
        cbValue = sizeof(szValue);
        lStatus = RegQueryValue(HKEY_CLASSES_ROOT, szSubKey, szValue, &cbValue);
        if ((lStatus == ERROR_SUCCESS) && (strlen(szValue) > 0))
        {
            WriteLog("--> CLSID=%s (%s)", (LPCTSTR)bstrCLSID, szValue);
        }
        else
        {
            WriteLog("--> CLSID=%s", (LPCTSTR)bstrCLSID);
        }
        CoTaskMemFree(polestrCLSID);
    }
}

static VOID WriteIID(REFIID riid)
{
    LPOLESTR polestrIID;
    
    if (StringFromIID(riid, &polestrIID) == S_OK)
    {
        LONG lStatus;
        char szSubKey[128];
        char szValue[128];
        LONG cbValue;

        _bstr_t bstrIID = polestrIID;

        sprintf(szSubKey, "Interface\\%s", (LPCTSTR)bstrIID);
        ZeroMemory(szValue, sizeof(szValue));
        cbValue = sizeof(szValue);
        lStatus = RegQueryValue(HKEY_CLASSES_ROOT, szSubKey, szValue, &cbValue);
        if ((lStatus == ERROR_SUCCESS) && (strlen(szValue) > 0))
        {
            WriteLog("--> IID=%s (%s)", (LPCTSTR)bstrIID, szValue);
        }
        else
        {
            WriteLog("--> IID=%s", (LPCTSTR)bstrIID);
        }
        CoTaskMemFree(polestrIID);
    }
}


////////////////////////////////////////////////////////////////////////
//
// DumpMsTscProperties
//

#define DumpBool(_name,_value)      try { WriteLog("  ." _name "=%s", _value ? "TRUE" : "FALSE"); } catch (...) { WriteLog("  ." _name "=(undefined)"); }
#define DumpLong(_name,_value)      try { WriteLog("  ." _name "=%d", _value); } catch (...) { WriteLog("  ." _name "=(undefined)"); }
#define DumpPointer(_name, _value)  try { WriteLog("  ." _name "=%x", _value); } catch (...) { WriteLog("  ." _name "=(undefined)"); }
#define DumpShort(_name,_value)     try { WriteLog("  ." _name "=%d", _value); } catch (...) { WriteLog("  ." _name "=(undefined)"); }
#define DumpString(_name,_value)    try { WriteLog("  ." _name "=%s", (LPCTSTR)_value); } catch (...) { WriteLog("  ." _name "=(undefined)"); }

static VOID DumpMsTscAdvancedSettings(IMsTscAdvancedSettings *p)
{
    if (p == NULL) return;

    WriteLog("IMsTscAdvancedSettings");
    
    DumpLong("Compress", p->GetCompress());
    DumpLong("BitmapPersistence", p->GetBitmapPeristence());
    DumpLong("AllowBackgroundInput", p->GetallowBackgroundInput());
    DumpLong("ContainerHandledFullScreen", p->GetContainerHandledFullScreen());
    DumpLong("DisableRdpdr", p->GetDisableRdpdr());
}

static VOID DumpMsTscDebug(IMsTscDebug *p)
{
    if (p == NULL) return;

    WriteLog("IMsTscDebug");

    DumpLong("HatchBitmapPDU", p->GetHatchBitmapPDU());
    DumpLong("HatchSSBOrder", p->GetHatchSSBOrder());
    DumpLong("HatchMembltOrder", p->GetHatchMembltOrder());
    DumpLong("HatchIndexPDU", p->GetHatchIndexPDU());
    DumpLong("LabelMemblt", p->GetLabelMemblt());
    DumpLong("BitmapCacheMonitor", p->GetBitmapCacheMonitor());
    DumpLong("MallocFailuresPercent", p->GetMallocFailuresPercent());
    DumpLong("MallocHugeFailuresPercent", p->GetMallocHugeFailuresPercent());
    DumpLong("NetThroughput", p->GetNetThroughput());
    DumpString("CLXCmdLine", p->GetCLXCmdLine());
    DumpString("CLXDll", p->GetCLXDll());
    DumpLong("RemoteProgramsHatchVisibleRegion", p->GetRemoteProgramsHatchVisibleRegion());
    DumpLong("RemoteProgramsHatchVisibleNoDataRegion", p->GetRemoteProgramsHatchVisibleNoDataRegion());
    DumpLong("RemoteProgramsHatchWindow", p->GetRemoteProgramsHatchWindow());
    DumpLong("RemoteProgramsStayConnectOnBadCaps", p->GetRemoteProgramsStayConnectOnBadCaps());
    DumpLong("ControlType", p->GetControlType());
}

static VOID DumpMsTscNonScriptable(IMsTscNonScriptable *p)
{
    if (p == NULL) return;

    WriteLog("IMsTscNonScriptable");

    DumpString("PortablePassword", p->GetPortablePassword());
    DumpString("PortableSalt", p->GetPortableSalt());
    DumpString("BinaryPassword", p->GetBinaryPassword());
    DumpString("BinarySalt", p->GetBinarySalt());
}

static VOID DumpMsTscSecuredSettings(IMsTscSecuredSettings *p)
{
    if (p == NULL) return;

    WriteLog("IMsTscSecuredSettings");
    
    DumpString("StartProgram", p->GetStartProgram());
    DumpString("WorkDir", p->GetWorkDir());
    DumpLong("FullScreen", p->GetFullScreen());
}

static VOID DumpMsRdpClientAdvancedSettings(IMsRdpClientAdvancedSettings *p)
{
    if (p == NULL) return;

    WriteLog("IMsRdpClientAdvancedSettings");

    DumpLong("SmoothScroll", p->GetSmoothScroll());
    DumpLong("AcceleratorPassthrough", p->GetAcceleratorPassthrough());
    DumpLong("ShadowBitmap", p->GetShadowBitmap());
    DumpLong("TransportType", p->GetTransportType());
    DumpLong("SasSequence", p->GetSasSequence());
    DumpLong("EncryptionEnabled", p->GetEncryptionEnabled());
    DumpLong("DedicatedTerminal", p->GetDedicatedTerminal());
    DumpLong("RDPPort", p->GetRDPPort());
    DumpLong("EnableMouse", p->GetEnableMouse());
    DumpLong("DisableCtrlAltDel", p->GetDisableCtrlAltDel());
    DumpLong("EnableWindowsKey", p->GetEnableWindowsKey());
    DumpLong("DoubleClickDetect", p->GetDoubleClickDetect());
    DumpLong("MaximizeShell", p->GetMaximizeShell());
    DumpLong("HotKeyFullScreen", p->GetHotKeyFullScreen());
    DumpLong("HotKeyCtrlEsc", p->GetHotKeyCtrlEsc());
    DumpLong("HotKeyAltEsc", p->GetHotKeyAltEsc());
    DumpLong("HotKeyAltTab", p->GetHotKeyAltTab());
    DumpLong("HotKeyAltShiftTab", p->GetHotKeyAltShiftTab());
    DumpLong("HotKeyAltSpace", p->GetHotKeyAltSpace());
    DumpLong("HotKeyCtrlAltDel", p->GetHotKeyCtrlAltDel());
    DumpLong("OrderDrawThreshold", p->GetorderDrawThreshold());
    DumpLong("BitmapCacheSize", p->GetBitmapCacheSize());
    DumpLong("BitmapVirtualCacheSize", p->GetBitmapVirtualCacheSize());
    DumpLong("ScaleBitmapCachesByBPP", p->GetScaleBitmapCachesByBPP());
    DumpLong("NumBitmapCaches", p->GetNumBitmapCaches());
    DumpLong("CachePersistenceActive", p->GetCachePersistenceActive());
    DumpLong("BrushSupportLevel", p->GetbrushSupportLevel());
    DumpLong("MinInputSendInterval", p->GetminInputSendInterval());
    DumpLong("InputEventsAtOnce", p->GetInputEventsAtOnce());
    DumpLong("MaxEventCount", p->GetmaxEventCount());
    DumpLong("KeepAliveInterval", p->GetkeepAliveInterval());
    DumpLong("ShutdownTimeout", p->GetshutdownTimeout());
    DumpLong("OverallConnectionTimeout", p->GetoverallConnectionTimeout());
    DumpLong("SingleConnectionTimeout", p->GetsingleConnectionTimeout());
    DumpLong("KeyboardType", p->GetKeyboardType());
    DumpLong("KeyboardSubType", p->GetKeyboardSubType());
    DumpLong("KeyboardFunctionKey", p->GetKeyboardFunctionKey());
    DumpLong("WinceFixedPalette", p->GetWinceFixedPalette());
    DumpLong("ConnectToServerConsole", p->GetConnectToServerConsole());
    DumpLong("BitmapPersistence", p->GetBitmapPersistence());
    DumpLong("MinutesToIdleTimeout", p->GetMinutesToIdleTimeout());
    DumpLong("SmartSizing", p->GetSmartSizing());
    DumpString("RdpdrLocalPrintingDocName", (LPCTSTR)p->GetRdpdrLocalPrintingDocName());
    DumpString("RdpdrClipCleanTempDirString", (LPCTSTR)p->GetRdpdrClipCleanTempDirString());
    DumpString("RdpdrClipPasteInfoString", (LPCTSTR)p->GetRdpdrClipPasteInfoString());
    DumpBool("DisplayConnectionBar", p->GetDisplayConnectionBar());
    DumpBool("PinConnectionBar", p->GetPinConnectionBar());
    DumpBool("GrabFocusOnConnect", p->GetGrabFocusOnConnect());
    DumpString("LoadBalanceInfo", (LPCTSTR)p->GetLoadBalanceInfo());
    DumpBool("RedirectDrives", p->GetRedirectDrives());
    DumpBool("RedirectPrinters", p->GetRedirectPrinters());
    DumpBool("RedirectPorts", p->GetRedirectPorts());
    DumpBool("RedirectSmartCards", p->GetRedirectSmartCards());
    DumpLong("BitmapVirtualCache16BppSize", p->GetBitmapVirtualCache16BppSize());
    DumpLong("BitmapVirtualCache24BppSize", p->GetBitmapVirtualCache24BppSize());
    DumpLong("PerformanceFlags", p->GetPerformanceFlags());
    DumpBool("NotifyTSPublicKey", p->GetNotifyTSPublicKey());

    DumpMsTscAdvancedSettings((IMsTscAdvancedSettings *)p);
}

static VOID DumpMsRdpClientAdvancedSettings2(IMsRdpClientAdvancedSettings2 *p)
{
    if (p == NULL) return;

    WriteLog("IMsRdpClientAdvancedSettings2");

    DumpBool("CanAutoReconnect", p->GetCanAutoReconnect());
    DumpBool("EnableAutoReconnect", p->GetEnableAutoReconnect());
    DumpLong("MaxReconnectAttempts", p->GetMaxReconnectAttempts());

    DumpMsRdpClientAdvancedSettings((IMsRdpClientAdvancedSettings *)p);
}

static VOID DumpMsRdpClientAdvancedSettings3(IMsRdpClientAdvancedSettings3 *p)
{
    if (p == NULL) return;

    WriteLog("IMsRdpClientAdvancedSettings3");

    DumpBool("ConnectionBarShowMinimizeButton", p->GetConnectionBarShowMinimizeButton());
    DumpBool("ConnectionBarShowRestoreButton", p->GetConnectionBarShowRestoreButton());

    DumpMsRdpClientAdvancedSettings2((IMsRdpClientAdvancedSettings2 *)p);
}

static VOID DumpMsRdpClientAdvancedSettings4(IMsRdpClientAdvancedSettings4 *p)
{
    if (p == NULL) return;

    WriteLog("IMsRdpClientAdvancedSettings4");

    DumpLong("AuthenticationLevel", p->GetAuthenticationLevel());

    DumpMsRdpClientAdvancedSettings3((IMsRdpClientAdvancedSettings3 *)p);
}

static VOID DumpMsRdpClientAdvancedSettings5(IMsRdpClientAdvancedSettings5 *p)
{
    if (p == NULL) return;

    WriteLog("IMsRdpClientAdvancedSettings5");

    DumpBool("RedirectClipboard", p->GetRedirectClipboard());
    DumpLong("AudioRedirectionMode", p->GetAudioRedirectionMode());
    DumpBool("ConnectionBarShowPinButton", p->GetConnectionBarShowPinButton());
    DumpBool("PublicMode", p->GetPublicMode());
    DumpBool("RedirectDevices", p->GetRedirectDevices());
    DumpBool("RedirectPOSDevices", p->GetRedirectPOSDevices());
    DumpLong("BitmapVirtualCache32BppSize", p->GetBitmapVirtualCache32BppSize());

    DumpMsRdpClientAdvancedSettings4((IMsRdpClientAdvancedSettings4 *)p);
}

static VOID DumpMsRdpClientAdvancedSettings6(IMsRdpClientAdvancedSettings6 *p)
{
    if (p == NULL) return;

    WriteLog("IMsRdpClientAdvancedSettings6");

    DumpBool("RelativeMouseMode", p->GetRelativeMouseMode());
    DumpString("AuthenticationServiceClass", p->GetAuthenticationServiceClass());
    DumpString("PCB", p->GetPCB());
    DumpLong("HotKeyFocusReleaseLeft", p->GetHotKeyFocusReleaseLeft());
    DumpLong("HotKeyFocusReleaseRight", p->GetHotKeyFocusReleaseRight());
    DumpBool("EnableCredSspSupport", p->GetEnableCredSspSupport());
    DumpLong("AuthenticationType", p->GetAuthenticationType());

    DumpMsRdpClientAdvancedSettings5((IMsRdpClientAdvancedSettings5 *)p);
}

static VOID DumpMsRdpClientAdvancedSettings7(IMsRdpClientAdvancedSettings7 *p)
{
    if (p == NULL) return;

    WriteLog("IMsRdpClientAdvancedSettings7");

    DumpBool("AudioCaptureRedirectionMode", p->GetAudioCaptureRedirectionMode());
    DumpLong("VideoPlaybackMode", p->GetVideoPlaybackMode());
    DumpBool("EnableSuperPan", p->GetEnableSuperPan());
    DumpLong("SuperPanAccelerationFactor", p->GetSuperPanAccelerationFactor());
    DumpBool("NegotiateSecurityLayer", p->GetNegotiateSecurityLayer());
    DumpLong("AudioQualityMode", p->GetAudioQualityMode());
    DumpBool("RedirectDirectX", p->GetRedirectDirectX());
    DumpLong("NetworkConnectionType", p->GetNetworkConnectionType());

    DumpMsRdpClientAdvancedSettings6((IMsRdpClientAdvancedSettings6 *)p);
}

static VOID DumpMsRdpClientAdvancedSettings8(IMsRdpClientAdvancedSettings8 *p)
{
    if (p == NULL) return;

    WriteLog("IMsRdpClientAdvancedSettings8");

    DumpBool("BandwidthDetection", p->GetBandwidthDetection());
    DumpLong("ClientProtocolSpec", p->GetClientProtocolSpec());
    
    DumpMsRdpClientAdvancedSettings7((IMsRdpClientAdvancedSettings7 *)p);
}

static VOID DumpMsRdpClientNonScriptable(IMsRdpClientNonScriptable *p)
{
    if (p == NULL) return;

    WriteLog("IMsRdpClientNonScriptable");

    DumpMsTscNonScriptable((IMsTscNonScriptable *)p);
}

static VOID DumpMsRdpClientNonScriptable2(IMsRdpClientNonScriptable2 *p)
{
    if (p == NULL) return;

    WriteLog("IMsRdpClientNonScriptable2");
    
    DumpPointer("UIParentWindowHandle", p->GetUIParentWindowHandle());

    DumpMsRdpClientNonScriptable((IMsRdpClientNonScriptable *)p);
}

static VOID DumpMsRdpClientNonScriptable3(IMsRdpClientNonScriptable3 *p)
{
    if (p == NULL) return;

    WriteLog("IMsRdpClientNonScriptable3");

    DumpBool("ShowRedirectionWarningDialog", p->GetShowRedirectionWarningDialog());
    DumpBool("PromptForCredentials", p->GetPromptForCredentials());
    DumpBool("NegotiateSecurityLayer", p->GetNegotiateSecurityLayer());
    DumpBool("EnableCredSspSupport", p->GetEnableCredSspSupport());
    DumpBool("RedirectDynamicDrives", p->GetRedirectDynamicDrives());
    DumpBool("RedirectDynamicDevices", p->GetRedirectDynamicDevices());
    DumpPointer("DeviceCollection", p->GetDeviceCollection());
    DumpPointer("DriveCollection", p->GetDriveCollection());
    DumpBool("WarnAboutSendingCredentials", p->GetWarnAboutSendingCredentials());
    DumpBool("WarnAboutClipboardRedirection", p->GetWarnAboutClipboardRedirection());
    DumpString("ConnectionBarText", p->GetConnectionBarText());

    DumpMsRdpClientNonScriptable2((IMsRdpClientNonScriptable2 *)p);
}

static VOID DumpMsRdpClientSecuredSettings(IMsRdpClientSecuredSettings *p)
{
    if (p == NULL) return;

    WriteLog("IMsRdpClientSecuredSettings");

    DumpLong("KeyboardHookMode", p->GetKeyboardHookMode());
    DumpLong("AudioRedirectionMode", p->GetAudioRedirectionMode());
    
    DumpMsTscSecuredSettings((IMsTscSecuredSettings *)p);
}

static VOID DumpMsRdpClientSecuredSettings2(IMsRdpClientSecuredSettings2 *p)
{
    if (p == NULL) return;

    WriteLog("IMsRdpClientSecuredSettings2");

    DumpString("PCB", p->GetPCB());
    
    DumpMsRdpClientSecuredSettings((IMsRdpClientSecuredSettings *)p);
}

static VOID DumpMsRdpClientShell(IMsRdpClientShell *p)
{
    if (p == NULL) return;

    WriteLog("IMsRdpClientShell");

    DumpString("RdpFileContents", p->GetRdpFileContents());
    DumpBool("IsRemoteProgramClientInstalled", p->GetIsRemoteProgramClientInstalled());
    DumpBool("PublicMode", p->GetPublicMode());
}

static VOID DumpMsRdpClientTransportSettings(IMsRdpClientTransportSettings *p)
{
    if (p == NULL) return;

    WriteLog("IMsRdpClientTransportSettings");
    
    DumpString("GatewayHostname", p->GetGatewayHostname());
    DumpLong("GatewayUsageMethod", p->GetGatewayUsageMethod());
    DumpLong("GatewayProfileUsageMethod", p->GetGatewayProfileUsageMethod());
    DumpLong("GatewayCredsSource", p->GetGatewayCredsSource());
    DumpLong("GatewayUserSelectedCredsSource", p->GetGatewayUserSelectedCredsSource());
    DumpLong("GatewayDefaultUsageMethod", p->GetGatewayDefaultUsageMethod());
}

static VOID DumpMsRdpClientTransportSettings2(IMsRdpClientTransportSettings2 *p)
{
    if (p == NULL) return;

    WriteLog("IMsRdpClientTransportSettings2");

    DumpLong("GatewayCredSharing", p->GetGatewayCredSharing());
    DumpLong("GatewayPreAuthRequirement", p->GetGatewayPreAuthRequirement());
    DumpString("GatewayPreAuthServerAddr", p->GetGatewayPreAuthServerAddr());
    DumpString("GatewaySupportUrl", p->GetGatewaySupportUrl());
    DumpString("GatewayEncryptedOtpCookie", p->GetGatewayEncryptedOtpCookie());
    DumpLong("GatewayEncryptedOtpCookeSize", p->GetGatewayEncryptedOtpCookieSize());
    DumpString("GatewayUsername", p->GetGatewayUsername());
    DumpString("GatewayDomain", p->GetGatewayDomain());

    DumpMsRdpClientTransportSettings((IMsRdpClientTransportSettings *)p);
}

static VOID DumpMsRdpClientTransportSettings3(IMsRdpClientTransportSettings3 *p)
{
    if (p == NULL) return;

    WriteLog("IMsRdpClientTransportSettings3");

    DumpLong("GatewayCredSourceCookie", p->GetGatewayCredSourceCookie());
    DumpString("GatewayAuthCookieServerAddr", p->GetGatewayAuthCookieServerAddr());
    DumpString("GatewayEncryptedAuthCookie", p->GetGatewayEncryptedAuthCookie());
    DumpLong("GatewayEncryptedAuthCookieSize", p->GetGatewayEncryptedAuthCookieSize());
    DumpString("GatewayAuthLoginPage", p->GetGatewayAuthLoginPage());

    DumpMsRdpClientTransportSettings2((IMsRdpClientTransportSettings2 *)p);
}

static VOID DumpTSRemoteProgram(ITSRemoteProgram *p)
{
    if (p == NULL) return;

    WriteLog("ITSRemoteProgram");

    DumpBool("RemoteProgramMode", p->GetRemoteProgramMode());
}

static VOID DumpMsTscAx(IMsTscAx *p, BOOL fDumpChildren = TRUE)
{
    if (p == NULL) return;

    WriteLog("IMsTscAx");
    
    DumpString("Server", p->GetServer());
    DumpString("Domain", p->GetDomain());
    DumpString("UserName", p->GetUserName());
    DumpString("DisconnectedText", p->GetDisconnectedText());
    DumpString("ConnectingText", p->GetConnectingText());
    DumpShort("Connected", p->GetConnected());
    DumpPointer("AdvancedSettings", p->GetAdvancedSettings());
    DumpPointer("SecuredSettings", p->GetSecuredSettings());
    DumpPointer("Debugger", p->GetDebugger());
    DumpLong("DesktopWidth", p->GetDesktopWidth());
    DumpLong("DesktopHeight", p->GetDesktopHeight());
    DumpLong("StartConnected", p->GetStartConnected());
    DumpLong("HorizontalScrollBarVisible", p->GetHorizontalScrollBarVisible());
    DumpLong("VerticalScrollBarVisible", p->GetVerticalScrollBarVisible());
    DumpLong("CipherStrength", p->GetCipherStrength());
    DumpString("Version", p->GetVersion());
    DumpLong("SecuredSettingsEnabled", p->GetSecuredSettingsEnabled());

    if (fDumpChildren)
    {
        DumpMsTscAdvancedSettings(p->GetAdvancedSettings());
        DumpMsTscSecuredSettings(p->GetSecuredSettings());
        DumpMsTscDebug(p->GetDebugger());
    }
}

static VOID DumpMsRdpClient(IMsRdpClient *p, BOOL fDumpChildren = TRUE)
{
    if (p == NULL) return;

    WriteLog("IMsRdpClient");
    
    DumpLong("ColorDepth", p->GetColorDepth());
    DumpPointer("AdvancedSettings2", p->GetAdvancedSettings2());
    DumpPointer("SecuredSettings2", p->GetSecuredSettings2());
    DumpBool("FullScreen", p->GetFullScreen());
    DumpLong("ExtendedDisconnectReason", p->GetExtendedDisconnectReason());

    DumpMsTscAx((IMsTscAx *)p, FALSE);
    
    if (fDumpChildren)
    {
        if (p->GetAdvancedSettings2())
        {
            DumpMsRdpClientAdvancedSettings(p->GetAdvancedSettings2());
        }
        else
        {
            DumpMsTscAdvancedSettings(p->GetAdvancedSettings());
        }

        if (p->GetSecuredSettings2())
        {
            DumpMsRdpClientSecuredSettings(p->GetSecuredSettings2());
        }
        else
        {
            DumpMsTscSecuredSettings(p->GetSecuredSettings());
        }       

        DumpMsTscDebug(p->GetDebugger());
    }
}

static VOID DumpMsRdpClient2(IMsRdpClient2 *p, BOOL fDumpChildren = TRUE)
{
    if (p == NULL) return;

    WriteLog("IMsRdpClient2");
    
    DumpPointer("AdvancedSettings3", p->GetAdvancedSettings3());
    DumpString("ConnectedStatusText", p->GetConnectedStatusText());

    DumpMsRdpClient((IMsRdpClient *)p, FALSE);

    if (fDumpChildren)
    {
        if (p->GetAdvancedSettings3())
        {
            DumpMsRdpClientAdvancedSettings2(p->GetAdvancedSettings3());
        }
        else if (p->GetAdvancedSettings2())
        {
            DumpMsRdpClientAdvancedSettings(p->GetAdvancedSettings2());
        }
        else
        {
            DumpMsTscAdvancedSettings(p->GetAdvancedSettings());
        }

        if (p->GetSecuredSettings2())
        {
            DumpMsRdpClientSecuredSettings(p->GetSecuredSettings2());
        }
        else
        {
            DumpMsTscSecuredSettings(p->GetSecuredSettings());
        }   

        DumpMsTscDebug(p->GetDebugger());
    }
}

static VOID DumpMsRdpClient3(IMsRdpClient3 *p, BOOL fDumpChildren = TRUE)
{
    if (p == NULL) return;
    
    WriteLog("IMsRdpClient3");

    DumpPointer("AdvancedSettings4", p->GetAdvancedSettings4());

    DumpMsRdpClient2((IMsRdpClient2 *)p, FALSE);
    
    if (fDumpChildren)
    {
        if (p->GetAdvancedSettings4())
        {
            DumpMsRdpClientAdvancedSettings3(p->GetAdvancedSettings4());
        }
        else if (p->GetAdvancedSettings3())
        {
            DumpMsRdpClientAdvancedSettings2(p->GetAdvancedSettings3());
        }
        else if (p->GetAdvancedSettings2())
        {
            DumpMsRdpClientAdvancedSettings(p->GetAdvancedSettings2());
        }
        else
        {
            DumpMsTscAdvancedSettings(p->GetAdvancedSettings());
        }

        if (p->GetSecuredSettings2())
        {
            DumpMsRdpClientSecuredSettings(p->GetSecuredSettings2());
        }
        else
        {
            DumpMsTscSecuredSettings(p->GetSecuredSettings());
        }       

        DumpMsTscDebug(p->GetDebugger());
    }
}

static VOID DumpMsRdpClient4(IMsRdpClient4 *p, BOOL fDumpChildren = TRUE)
{
    if (p == NULL) return;
    
    WriteLog("IMsRdpClient4");

    DumpPointer("AdvancedSettings5", p->GetAdvancedSettings5());

    DumpMsRdpClient3((IMsRdpClient3 *)p, FALSE);
    
    if (fDumpChildren)
    {
        if (p->GetAdvancedSettings5())
        {
            DumpMsRdpClientAdvancedSettings4(p->GetAdvancedSettings5());
        }
        else if (p->GetAdvancedSettings4())
        {
            DumpMsRdpClientAdvancedSettings3(p->GetAdvancedSettings4());
        }
        else if (p->GetAdvancedSettings3())
        {
            DumpMsRdpClientAdvancedSettings2(p->GetAdvancedSettings3());
        }
        else if (p->GetAdvancedSettings2())
        {
            DumpMsRdpClientAdvancedSettings(p->GetAdvancedSettings2());
        }
        else
        {
            DumpMsTscAdvancedSettings(p->GetAdvancedSettings());
        }
        
        if (p->GetSecuredSettings2())
        {
            DumpMsRdpClientSecuredSettings(p->GetSecuredSettings2());
        }
        else
        {
            DumpMsTscSecuredSettings(p->GetSecuredSettings());
        }       

        DumpMsTscDebug(p->GetDebugger());
    }
}

static VOID DumpMsRdpClient5(IMsRdpClient5 *p, BOOL fDumpChildren = TRUE)
{
    if (p == NULL) return;

    WriteLog("IMsRdpClient5");

    DumpPointer("AdvancedSettings6", p->GetAdvancedSettings6());
    DumpPointer("TransportSettings", p->GetTransportSettings());
    DumpPointer("RemoteProgram", p->GetRemoteProgram());
    DumpPointer("MsRdpClientShell", p->GetMsRdpClientShell());

    DumpMsRdpClient4((IMsRdpClient4 *)p, FALSE);
    
    if (fDumpChildren)
    {
        if (p->GetAdvancedSettings6())
        {
            DumpMsRdpClientAdvancedSettings5(p->GetAdvancedSettings6());
        }
        else if (p->GetAdvancedSettings5())
        {
            DumpMsRdpClientAdvancedSettings4(p->GetAdvancedSettings5());
        }
        else if (p->GetAdvancedSettings4())
        {
            DumpMsRdpClientAdvancedSettings3(p->GetAdvancedSettings4());
        }
        else if (p->GetAdvancedSettings3())
        {
            DumpMsRdpClientAdvancedSettings2(p->GetAdvancedSettings3());
        }
        else if (p->GetAdvancedSettings2())
        {
            DumpMsRdpClientAdvancedSettings(p->GetAdvancedSettings2());
        }
        else
        {
            DumpMsTscAdvancedSettings(p->GetAdvancedSettings());
        }

        if (p->GetSecuredSettings2())
        {
            DumpMsRdpClientSecuredSettings(p->GetSecuredSettings2());
        }
        else
        {
            DumpMsTscSecuredSettings(p->GetSecuredSettings());
        }
        
        DumpMsRdpClientTransportSettings(p->GetTransportSettings());
        DumpMsRdpClientShell(p->GetMsRdpClientShell());
        DumpTSRemoteProgram(p->GetRemoteProgram());
        DumpMsTscDebug(p->GetDebugger());
    }
}

static VOID DumpMsRdpClient6(IMsRdpClient6 *p, BOOL fDumpChildren = TRUE)
{
    if (p == NULL) return;

    WriteLog("IMsRdpClient6");

    DumpPointer("AdvancedSettings7", p->GetAdvancedSettings7());
    DumpPointer("TransportSettings2", p->GetTransportSettings2());

    DumpMsRdpClient5((IMsRdpClient5 *)p, FALSE);
    
    if (fDumpChildren)
    {
        if (p->GetAdvancedSettings7())
        {
            DumpMsRdpClientAdvancedSettings6(p->GetAdvancedSettings7());
        }
        else if (p->GetAdvancedSettings6())
        {
            DumpMsRdpClientAdvancedSettings5(p->GetAdvancedSettings6());
        }
        else if (p->GetAdvancedSettings5())
        {
            DumpMsRdpClientAdvancedSettings4(p->GetAdvancedSettings5());
        }
        else if (p->GetAdvancedSettings4())
        {
            DumpMsRdpClientAdvancedSettings3(p->GetAdvancedSettings4());
        }
        else if (p->GetAdvancedSettings3())
        {
            DumpMsRdpClientAdvancedSettings2(p->GetAdvancedSettings3());
        }
        else if (p->GetAdvancedSettings2())
        {
            DumpMsRdpClientAdvancedSettings(p->GetAdvancedSettings2());
        }
        else
        {
            DumpMsTscAdvancedSettings(p->GetAdvancedSettings());
        }

        if (p->GetSecuredSettings2())
        {
            DumpMsRdpClientSecuredSettings(p->GetSecuredSettings2());
        }
        else
        {
            DumpMsTscSecuredSettings(p->GetSecuredSettings());
        }

        if (p->GetTransportSettings2())
        {
            DumpMsRdpClientTransportSettings2(p->GetTransportSettings2());
        }
        else
        {
            DumpMsRdpClientTransportSettings(p->GetTransportSettings());
        }

        DumpMsRdpClientShell(p->GetMsRdpClientShell());
        DumpTSRemoteProgram(p->GetRemoteProgram());
        DumpMsTscDebug(p->GetDebugger());
    }
}

static VOID DumpMsRdpClient7(IMsRdpClient7 *p, BOOL fDumpChildren = TRUE)
{
    if (p == NULL) return;

    WriteLog("IMsRdpClient7");
    
    DumpPointer("AdvancedSettings8", p->GetAdvancedSettings8());
    DumpPointer("TransportSettings3", p->GetTransportSettings3());
    DumpPointer("SecuredSettings3", p->GetSecuredSettings3());
    DumpPointer("RemoteProgram2", p->GetRemoteProgram2());

    DumpMsRdpClient6((IMsRdpClient6 *)p, FALSE);
    
    if (fDumpChildren)
    {
        if (p->GetAdvancedSettings8())
        {
            DumpMsRdpClientAdvancedSettings7(p->GetAdvancedSettings8());
        }
        else if (p->GetAdvancedSettings7())
        {
            DumpMsRdpClientAdvancedSettings6(p->GetAdvancedSettings7());
        }
        else if (p->GetAdvancedSettings6())
        {
            DumpMsRdpClientAdvancedSettings5(p->GetAdvancedSettings6());
        }
        else if (p->GetAdvancedSettings5())
        {
            DumpMsRdpClientAdvancedSettings4(p->GetAdvancedSettings5());
        }
        else if (p->GetAdvancedSettings4())
        {
            DumpMsRdpClientAdvancedSettings3(p->GetAdvancedSettings4());
        }
        else if (p->GetAdvancedSettings3())
        {
            DumpMsRdpClientAdvancedSettings2(p->GetAdvancedSettings3());
        }
        else if (p->GetAdvancedSettings2())
        {
            DumpMsRdpClientAdvancedSettings(p->GetAdvancedSettings2());
        }
        else
        {
            DumpMsTscAdvancedSettings(p->GetAdvancedSettings());
        }

        if (p->GetSecuredSettings3())
        {
            DumpMsRdpClientSecuredSettings2(p->GetSecuredSettings3());
        }
        else if (p->GetSecuredSettings2())
        {
            DumpMsRdpClientSecuredSettings(p->GetSecuredSettings2());
        }
        else
        {
            DumpMsTscSecuredSettings(p->GetSecuredSettings());
        }
        
        if (p->GetTransportSettings3())
        {
            DumpMsRdpClientTransportSettings3(p->GetTransportSettings3());
        }
        else if (p->GetTransportSettings2())
        {
            DumpMsRdpClientTransportSettings2(p->GetTransportSettings2());
        }
        else
        {
            DumpMsRdpClientTransportSettings(p->GetTransportSettings());
        }

        DumpMsRdpClientShell(p->GetMsRdpClientShell());
        DumpTSRemoteProgram(p->GetRemoteProgram());
        DumpMsTscDebug(p->GetDebugger());
    }
}

static VOID DumpMsRdpClient8(IMsRdpClient8 *p, BOOL fDumpChildren = TRUE)
{
    if (p == NULL) return;

    WriteLog("IMsRdpClient8");
    
    DumpPointer("AdvancedSettings9", p->GetAdvancedSettings9());

    DumpMsRdpClient7((IMsRdpClient7 *)p, FALSE);

    if (fDumpChildren)
    {
        if (p->GetAdvancedSettings9())
        {
            DumpMsRdpClientAdvancedSettings8(p->GetAdvancedSettings9());
        }
        else if (p->GetAdvancedSettings8())
        {
            DumpMsRdpClientAdvancedSettings7(p->GetAdvancedSettings8());
        }
        else if (p->GetAdvancedSettings7())
        {
            DumpMsRdpClientAdvancedSettings6(p->GetAdvancedSettings7());
        }
        else if (p->GetAdvancedSettings6())
        {
            DumpMsRdpClientAdvancedSettings5(p->GetAdvancedSettings6());
        }
        else if (p->GetAdvancedSettings5())
        {
            DumpMsRdpClientAdvancedSettings4(p->GetAdvancedSettings5());
        }
        else if (p->GetAdvancedSettings4())
        {
            DumpMsRdpClientAdvancedSettings3(p->GetAdvancedSettings4());
        }
        else if (p->GetAdvancedSettings3())
        {
            DumpMsRdpClientAdvancedSettings2(p->GetAdvancedSettings3());
        }
        else if (p->GetAdvancedSettings2())
        {
            DumpMsRdpClientAdvancedSettings(p->GetAdvancedSettings2());
        }
        else
        {
            DumpMsTscAdvancedSettings(p->GetAdvancedSettings());
        }

        if (p->GetSecuredSettings3())
        {
            DumpMsRdpClientSecuredSettings2(p->GetSecuredSettings3());
        }
        else if (p->GetSecuredSettings2())
        {
            DumpMsRdpClientSecuredSettings(p->GetSecuredSettings2());
        }
        else
        {
            DumpMsTscSecuredSettings(p->GetSecuredSettings());
        }
        
        if (p->GetTransportSettings3())
        {
            DumpMsRdpClientTransportSettings3(p->GetTransportSettings3());
        }
        else if (p->GetTransportSettings2())
        {
            DumpMsRdpClientTransportSettings2(p->GetTransportSettings2());
        }
        else
        {
            DumpMsRdpClientTransportSettings(p->GetTransportSettings());
        }

        DumpMsRdpClientShell(p->GetMsRdpClientShell());
        DumpTSRemoteProgram(p->GetRemoteProgram());
        DumpMsTscDebug(p->GetDebugger());
    }
}

static VOID DumpMsTscProperties(IUnknown *pUnknown)
{
    IMsRdpClient *pMsRdpClient;
    IMsRdpClient2 *pMsRdpClient2;
    IMsRdpClient3 *pMsRdpClient3;
    IMsRdpClient4 *pMsRdpClient4;
    IMsRdpClient5 *pMsRdpClient5;
    IMsRdpClient6 *pMsRdpClient6;
    IMsRdpClient7 *pMsRdpClient7;
    IMsRdpClient8 *pMsRdpClient8;
    IMsRdpClientNonScriptable *pMsRdpClientNonScriptable;
    IMsRdpClientNonScriptable2 *pMsRdpClientNonScriptable2;
    IMsRdpClientNonScriptable3 *pMsRdpClientNonScriptable3;
    IMsRdpClientNonScriptable4 *pMsRdpClientNonScriptable4;
    IMsRdpClientNonScriptable5 *pMsRdpClientNonScriptable5;
    IMsRdpClientShell *pMsRdpClientShell;
    IMsRdpExtendedSettings *pMsRdpExtendedSettings;
    IMsRdpPreferredRedirectionInfo *pMsRdpPreferredRedirectionInfo;
    IMsTscAx *pMsTscAx;
    IMsTscDebug *pMsTscDebug;
    IMsTscNonScriptable *pMsTscNonScriptable;
    ITSRemoteProgram *pTSRemoteProgram;
    ITSRemoteProgram2 *pTSRemoteProgram2;

    if (pUnknown->QueryInterface(IID_IMsRdpClient8, (LPVOID *)&pMsRdpClient8) == S_OK)
    {
        DumpMsRdpClient8(pMsRdpClient8);
        pMsRdpClient8->Release();
    }
    else if (pUnknown->QueryInterface(IID_IMsRdpClient7, (LPVOID *)&pMsRdpClient7) == S_OK)
    {
        DumpMsRdpClient7(pMsRdpClient7);
        pMsRdpClient7->Release();
    }
    else if (pUnknown->QueryInterface(IID_IMsRdpClient6, (LPVOID *)&pMsRdpClient6) == S_OK)
    {
        DumpMsRdpClient6(pMsRdpClient6);
        pMsRdpClient6->Release();
    }
    else if (pUnknown->QueryInterface(IID_IMsRdpClient5, (LPVOID *)&pMsRdpClient5) == S_OK)
    {
        DumpMsRdpClient5(pMsRdpClient5);
        pMsRdpClient5->Release();
    }
    else if (pUnknown->QueryInterface(IID_IMsRdpClient4, (LPVOID *)&pMsRdpClient4) == S_OK)
    {
        DumpMsRdpClient4(pMsRdpClient4);
        pMsRdpClient4->Release();
    }
    else if (pUnknown->QueryInterface(IID_IMsRdpClient3, (LPVOID *)&pMsRdpClient3) == S_OK)
    {
        DumpMsRdpClient3(pMsRdpClient3);
        pMsRdpClient3->Release();
    }
    else if (pUnknown->QueryInterface(IID_IMsRdpClient2, (LPVOID *)&pMsRdpClient2) == S_OK)
    {
        DumpMsRdpClient2(pMsRdpClient2);
        pMsRdpClient2->Release();
    }
    else if (pUnknown->QueryInterface(IID_IMsRdpClient, (LPVOID *)&pMsRdpClient) == S_OK)
    {
        DumpMsRdpClient(pMsRdpClient);
        pMsRdpClient->Release();
    }
    else WriteLog("IMsRdpClient not implemented");

#if 1
    if (pUnknown->QueryInterface(IID_IMsRdpClientNonScriptable, (LPVOID *)&pMsRdpClientNonScriptable) == S_OK)
    {
        pMsRdpClientNonScriptable->Release();
    }
    else WriteLog("IMsRdpClientNonScriptable not implemented");
    
    if (pUnknown->QueryInterface(IID_IMsRdpClientNonScriptable2, (LPVOID *)&pMsRdpClientNonScriptable2) == S_OK)
    {
        pMsRdpClientNonScriptable2->Release();
    }
    else WriteLog("IMsRdpClientNonScriptable2 not implemented");
    
    if (pUnknown->QueryInterface(IID_IMsRdpClientNonScriptable3, (LPVOID *)&pMsRdpClientNonScriptable3) == S_OK)
    {
        pMsRdpClientNonScriptable3->Release();
    }
    else WriteLog("IMsRdpClientNonScriptable3 not implemented");
    
    if (pUnknown->QueryInterface(IID_IMsRdpClientNonScriptable4, (LPVOID *)&pMsRdpClientNonScriptable4) == S_OK)
    {
        pMsRdpClientNonScriptable4->Release();
    }
    else WriteLog("IMsRdpClientNonScriptable4 not implemented");
    
    if (pUnknown->QueryInterface(IID_IMsRdpClientNonScriptable5, (LPVOID *)&pMsRdpClientNonScriptable5) == S_OK)
    {
        pMsRdpClientNonScriptable5->Release();
    }
    else WriteLog("IMsRdpClientNonScriptable5 not implemented");    
    
    if (pUnknown->QueryInterface(IID_IMsRdpClientShell, (LPVOID *)&pMsRdpClientShell) == S_OK)
    {
        pMsRdpClientShell->Release();
    }
    else WriteLog("IMsRdpClientShell not implemented");
    
    if (pUnknown->QueryInterface(IID_IMsRdpPreferredRedirectionInfo, (LPVOID *)&pMsRdpPreferredRedirectionInfo) == S_OK)
    {
        pMsRdpPreferredRedirectionInfo->Release();
    }
    else WriteLog("IMsRdpPreferredRedirectionInfo not implemented");
    
    if (pUnknown->QueryInterface(IID_IMsRdpExtendedSettings, (LPVOID *)&pMsRdpExtendedSettings) == S_OK)
    {
        pMsRdpExtendedSettings->Release();
    }
    else WriteLog("IMsRdpExtendedSettings not implemented");
    
    if (pUnknown->QueryInterface(IID_IMsTscDebug, (LPVOID *)&pMsTscAx) == S_OK)
    {
        pMsTscAx->Release();
    }
    else WriteLog("IMsTscAx not implemented");

    if (pUnknown->QueryInterface(IID_IMsTscDebug, (LPVOID *)&pMsTscDebug) == S_OK)
    {
        pMsTscDebug->Release();
    }
    else WriteLog("IMsTscDebug not implemented");

    if (pUnknown->QueryInterface(IID_IMsTscNonScriptable, (LPVOID *)&pMsTscNonScriptable) == S_OK)
    {
        pMsTscNonScriptable->Release();
    }
    else WriteLog("IMsTscNonScriptable not implemented");

    if (pUnknown->QueryInterface(IID_ITSRemoteProgram, (LPVOID *)&pTSRemoteProgram) == S_OK)
    {
        pTSRemoteProgram->Release();
    }
    else WriteLog("ITSRemoteProgram not implemented");

    if (pUnknown->QueryInterface(IID_ITSRemoteProgram2, (LPVOID *)&pTSRemoteProgram2) == S_OK)
    {
        pTSRemoteProgram2->Release();
    }
    else WriteLog("ITSRemoteProgram2 not implemented");
#endif
}


////////////////////////////////////////////////////////////////////////
//
// CMsRdpClient
//
class CMsRdpClient : public IMsRdpClient8
{
public:
    CMsRdpClient(IUnknown *pUnknown)
    {
        m_refCount = 0;
        m_pUnknown = pUnknown;
        
        pUnknown->QueryInterface(IID_IDispatch, (LPVOID *)&m_pDispatch);
        pUnknown->QueryInterface(IID_IMsTscAx, (LPVOID *)&m_pMsTscAx);
        pUnknown->QueryInterface(IID_IMsRdpClient, (LPVOID *)&m_pMsRdpClient);
        pUnknown->QueryInterface(IID_IMsRdpClient2, (LPVOID *)&m_pMsRdpClient2);
        pUnknown->QueryInterface(IID_IMsRdpClient3, (LPVOID *)&m_pMsRdpClient3);
        pUnknown->QueryInterface(IID_IMsRdpClient4, (LPVOID *)&m_pMsRdpClient4);
        pUnknown->QueryInterface(IID_IMsRdpClient5, (LPVOID *)&m_pMsRdpClient5);
        pUnknown->QueryInterface(IID_IMsRdpClient6, (LPVOID *)&m_pMsRdpClient6);
        pUnknown->QueryInterface(IID_IMsRdpClient7, (LPVOID *)&m_pMsRdpClient7);
        pUnknown->QueryInterface(IID_IMsRdpClient8, (LPVOID *)&m_pMsRdpClient8);
    }
    
    ~CMsRdpClient()
    {
        m_pUnknown->Release();
        if (m_pDispatch) m_pDispatch->Release();
        if (m_pMsTscAx) m_pMsTscAx->Release();
        if (m_pMsRdpClient) m_pMsRdpClient->Release();
        if (m_pMsRdpClient2) m_pMsRdpClient2->Release();
        if (m_pMsRdpClient3) m_pMsRdpClient3->Release();
        if (m_pMsRdpClient4) m_pMsRdpClient4->Release();
        if (m_pMsRdpClient5) m_pMsRdpClient5->Release();
        if (m_pMsRdpClient6) m_pMsRdpClient6->Release();
        if (m_pMsRdpClient7) m_pMsRdpClient7->Release();
        if (m_pMsRdpClient8) m_pMsRdpClient8->Release();
    }
    
// IUnknown interface
public:
    HRESULT STDMETHODCALLTYPE QueryInterface(
        REFIID riid,
        LPVOID *ppvObject
    )
    {
        HRESULT hr;
        WriteLog("CMsRdpClient::QueryInterface");
        WriteIID(riid);
        
        if (riid == IID_IUnknown)
        {
            *ppvObject = (LPVOID)((IUnknown *)this);
            m_refCount++;
            return S_OK;
        }
        if ((riid == IID_IDispatch) && m_pDispatch)
        {
            *ppvObject = (LPVOID)((IDispatch *)this);
            m_refCount++;
            return S_OK;
        }
        if ((riid == IID_IMsTscAx) && m_pMsTscAx)
        {
            *ppvObject = (LPVOID)((IMsTscAx *)this);
            m_refCount++;
            return S_OK;
        }
        if ((riid == IID_IMsRdpClient) && m_pMsRdpClient)
        {
            *ppvObject = (LPVOID)((IMsRdpClient *)this);
            m_refCount++;
            return S_OK;
        }
        if ((riid == IID_IMsRdpClient2) && m_pMsRdpClient2)
        {
            *ppvObject = (LPVOID)((IMsRdpClient2 *)this);
            m_refCount++;
            return S_OK;
        }
        if ((riid == IID_IMsRdpClient3) && m_pMsRdpClient3)
        {
            *ppvObject = (LPVOID)((IMsRdpClient3 *)this);
            m_refCount++;
            return S_OK;
        }
        if ((riid == IID_IMsRdpClient4) && m_pMsRdpClient4)
        {
            *ppvObject = (LPVOID)((IMsRdpClient4 *)this);
            m_refCount++;
            return S_OK;
        }
        if ((riid == IID_IMsRdpClient5) && m_pMsRdpClient5)
        {
            *ppvObject = (LPVOID)((IMsRdpClient5 *)this);
            m_refCount++;
            return S_OK;
        }
        if ((riid == IID_IMsRdpClient6) && m_pMsRdpClient6)
        {
            *ppvObject = (LPVOID)((IMsRdpClient6 *)this);
            m_refCount++;
            return S_OK;
        }
        if ((riid == IID_IMsRdpClient7) && m_pMsRdpClient7)
        {
            *ppvObject = (LPVOID)((IMsRdpClient7 *)this);
            m_refCount++;
            return S_OK;
        }
        if ((riid == IID_IMsRdpClient8) && m_pMsRdpClient8)
        {
            *ppvObject = (LPVOID)((IMsRdpClient8 *)this);
            m_refCount++;
            return S_OK;
        }

        hr = m_pUnknown->QueryInterface(riid, ppvObject);
        WriteLog("--> hr=%x", hr);
        return hr;
    }
  
    ULONG STDMETHODCALLTYPE AddRef()
    {
        WriteLog("CMsRdpClient::AddRef");
        return ++m_refCount;
    }

    ULONG STDMETHODCALLTYPE Release()
    {
        WriteLog("CMsRdpClient::Release");
        if (--m_refCount == 0)
        {
            WriteLog("--> deleting object");
            delete this;
            return 0;
        }
        WriteLog("--> refCount=%d", m_refCount);
        return m_refCount;
    }

// IDispatch interface
public:
    HRESULT STDMETHODCALLTYPE GetTypeInfoCount(__RPC__out UINT *pctinfo)
    {
        WriteLog("CMsRdpClient::GetTypeInfoCount");
        return m_pDispatch->GetTypeInfoCount(pctinfo);
    }   

    HRESULT STDMETHODCALLTYPE GetTypeInfo(
        UINT iTInfo,
        LCID lcid,
        ITypeInfo **ppTInfo)
    {
        WriteLog("CMsRdpClient::GetTypeInfo");
        return m_pDispatch->GetTypeInfo(iTInfo, lcid, ppTInfo);
    }
        
    HRESULT STDMETHODCALLTYPE GetIDsOfNames( 
        REFIID riid,
        LPOLESTR *rgszNames,
        UINT cNames,
        LCID lcid,
        DISPID *rgDispId)
    {
        WriteLog("CMsRdpClient::GetIDsOfNames");
        return m_pDispatch->GetIDsOfNames(riid, rgszNames, cNames, lcid, rgDispId);
    }

    HRESULT STDMETHODCALLTYPE Invoke( 
        DISPID dispIdMember,
        REFIID riid,
        LCID lcid,
        WORD wFlags,
        DISPPARAMS *pDispParams,
        VARIANT *pVarResult,
        EXCEPINFO *pExcepInfo,
        UINT *puArgErr)
    {
        WriteLog("CMsRdpClient::Invoke");
        return m_pDispatch->Invoke(dispIdMember, riid, lcid, wFlags, pDispParams, pVarResult, pExcepInfo, puArgErr);
    }

// IMsTscAx interface
public:
    HRESULT __stdcall put_Server ( BSTR pServer ) {
        return m_pMsTscAx->put_Server(pServer);
    }

    HRESULT __stdcall get_Server ( BSTR * pServer ) {
        return m_pMsTscAx->get_Server(pServer);
    }

    HRESULT __stdcall put_Domain ( BSTR pDomain ) {
        return m_pMsTscAx->put_Domain(pDomain);
    }

    HRESULT __stdcall get_Domain ( BSTR * pDomain ) {
        return m_pMsTscAx->get_Domain(pDomain);
    }

    HRESULT __stdcall put_UserName ( BSTR pUserName ) {
        return m_pMsTscAx->put_UserName(pUserName);
    }

    HRESULT __stdcall get_UserName ( BSTR * pUserName ) {
        return m_pMsTscAx->get_UserName(pUserName);
    }

    HRESULT __stdcall put_DisconnectedText ( BSTR pDisconnectedText ) {
        return m_pMsTscAx->put_DisconnectedText(pDisconnectedText);
    }

    HRESULT __stdcall get_DisconnectedText ( BSTR * pDisconnectedText ) {
        return m_pMsTscAx->get_DisconnectedText(pDisconnectedText);
    }

    HRESULT __stdcall put_ConnectingText ( BSTR pConnectingText ) {
        return m_pMsTscAx->put_ConnectingText(pConnectingText);
    }

    HRESULT __stdcall get_ConnectingText ( BSTR * pConnectingText ) {
        return m_pMsTscAx->get_ConnectingText(pConnectingText);
    }

    HRESULT __stdcall get_Connected ( short * pIsConnected ) {
        return m_pMsTscAx->get_Connected(pIsConnected);
    }

    HRESULT __stdcall put_DesktopWidth ( long pVal ) {
        return m_pMsTscAx->put_DesktopWidth(pVal);
    }

    HRESULT __stdcall get_DesktopWidth ( long * pVal ) {
        return m_pMsTscAx->get_DesktopWidth(pVal);
    }

    HRESULT __stdcall put_DesktopHeight ( long pVal ) {
        return m_pMsTscAx->put_DesktopHeight(pVal);
    }

    HRESULT __stdcall get_DesktopHeight ( long * pVal ) {
        return m_pMsTscAx->get_DesktopHeight(pVal);
    }

    HRESULT __stdcall put_StartConnected ( long pfStartConnected ) {
        return m_pMsTscAx->put_StartConnected(pfStartConnected);
    }

    HRESULT __stdcall get_StartConnected ( long * pfStartConnected ) {
        return m_pMsTscAx->get_StartConnected(pfStartConnected);
    }

    HRESULT __stdcall get_HorizontalScrollBarVisible ( long * pfHScrollVisible ) {
        return m_pMsTscAx->get_HorizontalScrollBarVisible(pfHScrollVisible);
    }

    HRESULT __stdcall get_VerticalScrollBarVisible ( long * pfVScrollVisible ) {
        return m_pMsTscAx->get_VerticalScrollBarVisible(pfVScrollVisible);
    }

    HRESULT __stdcall put_FullScreenTitle ( BSTR _arg1 ) {
        return m_pMsTscAx->put_FullScreenTitle(_arg1);
    }

    HRESULT __stdcall get_CipherStrength ( long * pCipherStrength ) {
        return m_pMsTscAx->get_CipherStrength(pCipherStrength);
    }

    HRESULT __stdcall get_Version ( BSTR * pVersion ) {
        return m_pMsTscAx->get_Version(pVersion);
    }

    HRESULT __stdcall get_SecuredSettingsEnabled ( long * pSecuredSettingsEnabled ) {
        return m_pMsTscAx->get_SecuredSettingsEnabled(pSecuredSettingsEnabled);
    }

    HRESULT __stdcall get_SecuredSettings ( struct IMsTscSecuredSettings * * ppSecuredSettings ) {
        return m_pMsTscAx->get_SecuredSettings(ppSecuredSettings);
    }

    HRESULT __stdcall get_AdvancedSettings ( struct IMsTscAdvancedSettings * * ppAdvSettings ) {
        return m_pMsTscAx->get_AdvancedSettings(ppAdvSettings);
    }

    HRESULT __stdcall get_Debugger ( struct IMsTscDebug * * ppDebugger ) {
        return m_pMsTscAx->get_Debugger(ppDebugger);
    }

    HRESULT __stdcall raw_Connect ( ) {
        WriteLog("CMsRdpClient::Connect");
        IMsRdpClientNonScriptable3 *pMsRdpClientNonScriptable3;
        HRESULT hr = m_pMsTscAx->QueryInterface(IID_IMsRdpClientNonScriptable3, (LPVOID *)&pMsRdpClientNonScriptable3);
        if (hr == S_OK)
        {
            pMsRdpClientNonScriptable3->PutConnectionBarText("FreeRDP Client");
            pMsRdpClientNonScriptable3->Release();
        }
        DumpMsTscProperties(m_pUnknown);
        return m_pMsTscAx->raw_Connect();
    }

    HRESULT __stdcall raw_Disconnect ( ) {
        return m_pMsTscAx->raw_Disconnect();
    }

    HRESULT __stdcall raw_CreateVirtualChannels ( BSTR newVal ) {
        return m_pMsTscAx->raw_CreateVirtualChannels(newVal);
    }

    HRESULT __stdcall raw_SendOnVirtualChannel ( BSTR chanName, BSTR ChanData ) {
        return m_pMsTscAx->raw_SendOnVirtualChannel(chanName, ChanData);
    }

// IMsRdpClient interface
public:
    HRESULT __stdcall put_ColorDepth ( long pcolorDepth ) {
        return m_pMsRdpClient->put_ColorDepth(pcolorDepth);
    }

    HRESULT __stdcall get_ColorDepth ( long * pcolorDepth ) {
        return m_pMsRdpClient->get_ColorDepth(pcolorDepth);
    }

    HRESULT __stdcall get_AdvancedSettings2 ( struct IMsRdpClientAdvancedSettings * * ppAdvSettings ) {
        return m_pMsRdpClient->get_AdvancedSettings2(ppAdvSettings);
    }

    HRESULT __stdcall get_SecuredSettings2 ( struct IMsRdpClientSecuredSettings * * ppSecuredSettings ) {
        return m_pMsRdpClient->get_SecuredSettings2(ppSecuredSettings);
    }

    HRESULT __stdcall get_ExtendedDisconnectReason ( ExtendedDisconnectReasonCode * pExtendedDisconnectReason ) {
        return m_pMsRdpClient->get_ExtendedDisconnectReason(pExtendedDisconnectReason);
    }

    HRESULT __stdcall put_FullScreen ( VARIANT_BOOL pfFullScreen ) {
        return m_pMsRdpClient->put_FullScreen(pfFullScreen);
    }

    HRESULT __stdcall get_FullScreen ( VARIANT_BOOL * pfFullScreen ) {
        return m_pMsRdpClient->get_FullScreen(pfFullScreen);
    }

    HRESULT __stdcall raw_SetVirtualChannelOptions ( BSTR chanName, long chanOptions ) {
        return m_pMsRdpClient->raw_SetVirtualChannelOptions(chanName, chanOptions);
    }

    HRESULT __stdcall raw_GetVirtualChannelOptions ( BSTR chanName, long * pChanOptions ) {
        return m_pMsRdpClient->raw_GetVirtualChannelOptions(chanName, pChanOptions);
    }

    HRESULT __stdcall raw_RequestClose ( ControlCloseStatus * pCloseStatus ) {
        return m_pMsRdpClient->raw_RequestClose(pCloseStatus);
    }

// IMsRdpClient2 interface
public:
    HRESULT __stdcall get_AdvancedSettings3 ( struct IMsRdpClientAdvancedSettings2 * * ppAdvSettings ) {
        return m_pMsRdpClient2->get_AdvancedSettings3(ppAdvSettings);
    }

    HRESULT __stdcall put_ConnectedStatusText ( BSTR pConnectedStatusText ) {
        return m_pMsRdpClient2->put_ConnectedStatusText(pConnectedStatusText);
    }

    HRESULT __stdcall get_ConnectedStatusText ( BSTR * pConnectedStatusText ) {
        return m_pMsRdpClient2->get_ConnectedStatusText(pConnectedStatusText);
    }

// IMsRdpClient3 interface
public:
    HRESULT __stdcall get_AdvancedSettings4 ( struct IMsRdpClientAdvancedSettings3 * * ppAdvSettings ) {
        return m_pMsRdpClient3->get_AdvancedSettings4(ppAdvSettings);
    }

// IMsRdpClient4 interface
public:
    HRESULT __stdcall get_AdvancedSettings5 ( struct IMsRdpClientAdvancedSettings4 * * ppAdvSettings ) {
        return m_pMsRdpClient4->get_AdvancedSettings5(ppAdvSettings);
    }

// IMsRdpClient5 interface
public:
    HRESULT __stdcall get_TransportSettings ( struct IMsRdpClientTransportSettings * * ppXportSet ) {
        return m_pMsRdpClient5->get_TransportSettings(ppXportSet);
    }   

    HRESULT __stdcall get_AdvancedSettings6 ( struct IMsRdpClientAdvancedSettings5 * * ppAdvSettings ) {
        return m_pMsRdpClient5->get_AdvancedSettings6(ppAdvSettings);
    }

    HRESULT __stdcall raw_GetErrorDescription (
        unsigned int disconnectReason,
        unsigned int ExtendedDisconnectReason,
        BSTR * pBstrErrorMsg
    ) {
        return m_pMsRdpClient5->raw_GetErrorDescription(disconnectReason, ExtendedDisconnectReason, pBstrErrorMsg);
    }

    HRESULT __stdcall get_RemoteProgram ( struct ITSRemoteProgram * * ppRemoteProgram ) {
        return m_pMsRdpClient5->get_RemoteProgram(ppRemoteProgram);
    }

    HRESULT __stdcall get_MsRdpClientShell ( struct IMsRdpClientShell * * ppLauncher ) {
        return m_pMsRdpClient5->get_MsRdpClientShell(ppLauncher);
    }

// IMsRdpClient6 interface
public:
    HRESULT __stdcall get_AdvancedSettings7 ( struct IMsRdpClientAdvancedSettings6 * * ppAdvSettings ) {
        return m_pMsRdpClient6->get_AdvancedSettings7(ppAdvSettings);
    }

    HRESULT __stdcall get_TransportSettings2 ( struct IMsRdpClientTransportSettings2 * * ppXportSet2 ) {
        return m_pMsRdpClient6->get_TransportSettings2(ppXportSet2);
    }

// IMsRdpClient7 interface
public:
    HRESULT __stdcall get_AdvancedSettings8 ( struct IMsRdpClientAdvancedSettings7 * * ppAdvSettings ) {
        return m_pMsRdpClient7->get_AdvancedSettings8(ppAdvSettings);
    }

    HRESULT __stdcall get_TransportSettings3 ( struct IMsRdpClientTransportSettings3 * * ppXportSet3 ) {
        return m_pMsRdpClient7->get_TransportSettings3(ppXportSet3);
    }

    HRESULT __stdcall raw_GetStatusText (
        unsigned int statusCode,
        BSTR * pBstrStatusText
    ) {
        return m_pMsRdpClient7->raw_GetStatusText(statusCode, pBstrStatusText);
    }

    HRESULT __stdcall get_SecuredSettings3 ( struct IMsRdpClientSecuredSettings2 * * ppSecuredSettings ) {
        return m_pMsRdpClient7->get_SecuredSettings3(ppSecuredSettings);
    }

    HRESULT __stdcall get_RemoteProgram2 ( struct ITSRemoteProgram2 * * ppRemoteProgram ) {
        return m_pMsRdpClient7->get_RemoteProgram2(ppRemoteProgram);
    }

// IMsRdpClient8 interface
public:
    HRESULT __stdcall raw_SendRemoteAction ( RemoteSessionActionType actionType ) {
        return m_pMsRdpClient8->raw_SendRemoteAction(actionType);
    }
    
    HRESULT __stdcall get_AdvancedSettings9 ( struct IMsRdpClientAdvancedSettings8 * * ppAdvSettings ) {
        return m_pMsRdpClient8->get_AdvancedSettings9(ppAdvSettings);
    }

    HRESULT __stdcall raw_Reconnect (
        unsigned long ulWidth,
        unsigned long ulHeight,
        ControlReconnectStatus * pReconnectStatus
    ) {
        return m_pMsRdpClient8->raw_Reconnect(ulWidth, ulHeight, pReconnectStatus);
    }

private:
    ULONG m_refCount;
    IUnknown *m_pUnknown;
    IDispatch *m_pDispatch;
    IMsTscAx *m_pMsTscAx;
    IMsRdpClient *m_pMsRdpClient;
    IMsRdpClient2 *m_pMsRdpClient2;
    IMsRdpClient3 *m_pMsRdpClient3;
    IMsRdpClient4 *m_pMsRdpClient4;
    IMsRdpClient5 *m_pMsRdpClient5;
    IMsRdpClient6 *m_pMsRdpClient6;
    IMsRdpClient7 *m_pMsRdpClient7;
    IMsRdpClient8 *m_pMsRdpClient8;
};



////////////////////////////////////////////////////////////////////////
//
// CClassFactory
//
class CClassFactory : IClassFactory
{
public:
    CClassFactory(REFCLSID rclsid, IClassFactory *pDelegate)
    {
        m_clsid = rclsid;
        m_pDelegate = pDelegate;
        m_refCount = 1;
    }
  
    ~CClassFactory()
    {
        m_pDelegate->Release();
    }

// IUnknown interface
public:
    HRESULT STDMETHODCALLTYPE QueryInterface(
        REFIID riid,
        LPVOID *ppvObject
    )
    {
        WriteLog("CClassFactory::QueryInterface");
        return m_pDelegate->QueryInterface(riid, ppvObject);
    }
  
    ULONG STDMETHODCALLTYPE AddRef()
    {
        WriteLog("CClassFactory::AddRef");
        return ++m_refCount;
    }

    ULONG STDMETHODCALLTYPE Release()
    {
        WriteLog("CClassFactory::Release");
        if (--m_refCount == 0)
        {
            delete this;
            return 0;
        }   
        return m_refCount;
    }

// IClassFactory interface
public:
    HRESULT STDMETHODCALLTYPE CreateInstance(
        IUnknown *pUnkOuter,
        REFIID riid,
        LPVOID *ppvObject
    )
    {
        WriteLog("CClassFactory::CreateInstance");
        WriteCLSID(m_clsid);
        WriteIID(riid);
        
        HRESULT hr = m_pDelegate->CreateInstance(pUnkOuter, riid, ppvObject);
        if (hr == S_OK)
        {
            if ((m_clsid == CLSID_MsRdpClientNotSafeForScripting) ||
                (m_clsid == CLSID_MsRdpClient6NotSafeForScripting))
            {
                CMsRdpClient *pMsRdpClient = new CMsRdpClient((IUnknown *)*ppvObject);
                hr = pMsRdpClient->QueryInterface(riid, ppvObject);
            }
        }

        return hr;
    }

    HRESULT STDMETHODCALLTYPE LockServer(
        BOOL fLock
    )
    {
        WriteLog("CClassFactory::LockServer");
        return m_pDelegate->LockServer(fLock);
    }

private:
    CLSID m_clsid;
    IClassFactory *m_pDelegate;
    ULONG m_refCount;
};


////////////////////////////////////////////////////////////////////////
//
// IsAddressInModule
//
// Determines if an address in a specified module.
//
static BOOL IsAddressInModule(PVOID pAddress, LPCTSTR pszModule)
{
    HMODULE hModule;
    MODULEINFO mi;
    MEMORY_BASIC_INFORMATION mbi;
    LPVOID pStartAddr, pEndAddr;
    BOOL fOk;

    //WriteLog("IsAddressInModule - Address=%x,Module=%s", pAddress, pszModule);

    // Check the validity of the given address.
    if (VirtualQuery(pAddress, &mbi, sizeof(mbi)) == 0) return FALSE;

    // Retrieve information regarding the specified module.
    hModule = GetModuleHandle(pszModule);
    if (!hModule) return FALSE;
    if (!GetModuleInformation(GetCurrentProcess(), hModule, &mi, sizeof(mi))) return FALSE;

    // Check the validity of the given address.
    if (VirtualQuery(pAddress, &mbi, sizeof(mbi)) == 0) return FALSE;

    // Determine if the specified address is in the module. 
    pStartAddr = mi.lpBaseOfDll;
    pEndAddr = (LPVOID)((PBYTE)mi.lpBaseOfDll + mi.SizeOfImage - 1);
    fOk = (pAddress >= pStartAddr) && (pAddress <= pEndAddr) ? TRUE : FALSE;
    WriteLog("   BaseAddress=%p,RegionSize=%d,%s", mbi.BaseAddress, mbi.RegionSize, fOk ? "YES" : "NO");

    return fOk;
}


#if defined(_MSC_VER) || defined(_MSC_EXTENSIONS)
    #define DELTA_EPOCH_IN_MICROSECS  11644473600000000Ui64
#else
    #define DELTA_EPOCH_IN_MICROSECS  11644473600000000ULL
#endif
 
struct timezone 
{
    int  tz_minuteswest; /* minutes W of Greenwich */
    int  tz_dsttime;     /* type of dst correction */
};
 
int gettimeofday(struct timeval *tv, struct timezone *tz)
{
    FILETIME ft;
    unsigned __int64 tmpres = 0;
    static int tzflag;
 
    if (NULL != tv)
    {
        GetSystemTimeAsFileTime(&ft);

        tmpres |= ft.dwHighDateTime;
        tmpres <<= 32;
        tmpres |= ft.dwLowDateTime;
 
        /*converting file time to unix epoch*/
        tmpres /= 10;  /*convert into microseconds*/
        tmpres -= DELTA_EPOCH_IN_MICROSECS; 
        tv->tv_sec = (long)(tmpres / 1000000UL);
        tv->tv_usec = (long)(tmpres % 1000000UL);
    }
 
    if (NULL != tz)
    {
        if (!tzflag)
        {
            _tzset();
            tzflag++;
        }
        tz->tz_minuteswest = _timezone / 60;
        tz->tz_dsttime = _daylight;
    }
 
    return 0;
}

static uint16 IPv4Checksum(LPBYTE ipv4, int length)
{
    uint16 tmp16;
    long checksum = 0;

    while (length > 1)
    {
        tmp16 = *((uint16*) ipv4);
        checksum += tmp16;
        length -= 2;
        ipv4 += 2;
    }

    if (length > 0)
        checksum += *ipv4;

    while (checksum >> 16)
        checksum = (checksum & 0xFFFF) + (checksum >> 16);

    return (uint16) (~checksum);
}

static VOID WritePCapGlobalHeader(FILE *file)
{
    pcap_hdr_t pcap_hdr;

    pcap_hdr.magic_number = 0xa1b2c3d4;
    pcap_hdr.version_major = 2;
    pcap_hdr.version_minor = 4;
    pcap_hdr.thiszone = 0;
    pcap_hdr.sigfigs = 0;
    pcap_hdr.snaplen = 0xFFFFFFFF;
    pcap_hdr.network = 1;
    fwrite(&pcap_hdr, sizeof(pcap_hdr), 1, file);
}

static VOID WritePCapPacket(FILE *file, LPBYTE pBuffer, DWORD cbBuffer, BOOL fOutbound)
{
    struct timeval tp;
    pcaprec_hdr_t pcapRecordHdr;
    ethernet_hdr_t ethernetHdr;
    ipv4_hdr_t ipv4Hdr;
    tcp_hdr_t tcpHdr;
    unsigned int uiPacketLength;

    WriteLog("WritePCapPacket - pBuffer=%p, cbBuffer=%lu, fOutbound=%d", pBuffer, cbBuffer, fOutbound);

    if (pBuffer == NULL) return;
    if (cbBuffer == 0) return;
    if (cbBuffer > 32768) return;
    //if (pBuffer[0] != 0x03) return;

    uiPacketLength = cbBuffer + sizeof(ethernetHdr) + sizeof(ipv4Hdr) + sizeof(tcpHdr);

    WriteLog("uiPacketLength=%lu", cbBuffer);

    if (!g_fPCapHeaderWritten)
    {
        WritePCapGlobalHeader(file);
        g_fPCapHeaderWritten = TRUE;
    }

    gettimeofday(&tp, NULL);

    // Write the pcap record header.
    pcapRecordHdr.ts_sec = tp.tv_sec;
    pcapRecordHdr.ts_usec = tp.tv_usec;
    pcapRecordHdr.incl_len = uiPacketLength;
    pcapRecordHdr.orig_len = uiPacketLength;
    fwrite(&pcapRecordHdr, sizeof(pcapRecordHdr), 1, file);

    // Write the ethernet header.
    if (fOutbound)
    {
        memcpy(ethernetHdr.dest_addr, g_serverMacAddr, 6);
        memcpy(ethernetHdr.source_addr, g_clientMacAddr, 6);
    }
    else
    {
        memcpy(ethernetHdr.dest_addr, g_clientMacAddr, 6);
        memcpy(ethernetHdr.source_addr, g_serverMacAddr, 6);
    }
    ethernetHdr.frame_type = htons(0x0800);
    fwrite(&ethernetHdr, sizeof(ethernetHdr), 1, file);

    // Write the IPv4 header.
    ipv4Hdr.version_ihl = (0x04 << 4) | 0x05;
    ipv4Hdr.dscp_ecn = (0x00 << 2) | 0x00;
    ipv4Hdr.total_length = htons((u_short)cbBuffer + sizeof(ipv4Hdr) + sizeof(tcpHdr));
    ipv4Hdr.identification = htons(0);
    ipv4Hdr.flags_fragment_offset = htons((0x02 << 13) | 0x00);
    ipv4Hdr.ttl = 128;
    ipv4Hdr.protocol = 6;
    ipv4Hdr.checksum = 0;
    if (fOutbound)
    {
        ipv4Hdr.source_ip_addr = htonl(g_clientIPAddr);
        ipv4Hdr.dest_ip_addr = htonl(g_serverIPAddr);
    }
    else
    {
        ipv4Hdr.source_ip_addr = htonl(g_serverIPAddr);
        ipv4Hdr.dest_ip_addr = htonl(g_clientIPAddr);
    }
    ipv4Hdr.checksum = htons(IPv4Checksum((LPBYTE)&ipv4Hdr, sizeof(ipv4Hdr)));
    fwrite(&ipv4Hdr, sizeof(ipv4Hdr), 1, file);

    // Write the TCP header.
    if (fOutbound)
    {
        tcpHdr.source_port = htons(g_clientTcpPort);
        tcpHdr.dest_port = htons(g_serverTcpPort);
        tcpHdr.seq_number = htonl(g_clientSeqNumber);
        tcpHdr.ack_number = htonl(g_serverSeqNumber);
        g_clientSeqNumber += cbBuffer;
    }
    else
    {
        tcpHdr.source_port = htons(g_serverTcpPort);
        tcpHdr.dest_port = htons(g_clientTcpPort);
        tcpHdr.seq_number = htonl(g_serverSeqNumber);
        tcpHdr.ack_number = htonl(g_clientSeqNumber);
        g_serverSeqNumber += cbBuffer;
    }
    tcpHdr.flags = htons((5 << 12) | 0x18);
    tcpHdr.window_size = htons(0x7FFF);
    tcpHdr.checksum = 0;
    tcpHdr.urgent_pointer = 0;
    fwrite(&tcpHdr, sizeof(tcpHdr), 1, file);

    // Write the payload.
    fwrite(pBuffer, cbBuffer, 1, file);
}

static VOID DumpBuffer(LPBYTE pBuffer, ULONG cbBuffer)
{
    while (cbBuffer > 0)
    {
        TCHAR szBinary[80], szAscii[80];
        LPTSTR pszBinary = szBinary;
        LPTSTR pszAscii = szAscii;
        for (ULONG i = 0; i < 16; i++)
        {
            if (cbBuffer > 0)
            {
                BYTE byte = *pBuffer++; cbBuffer--;
                pszBinary += wsprintf(pszBinary, "%02X ", byte);
                pszAscii += wsprintf(pszAscii, "%c", isprint(byte) ? byte : '.');
            }
            else
            {
                pszBinary += wsprintf(pszBinary, "   ");
                pszAscii += wsprintf(pszAscii, " ");
            }
        }
        WriteLog("%s %s", szBinary, szAscii);
    }
}

static VOID DumpSecBuffer(PSecBuffer pSecBuffer)
{
    if ((pSecBuffer->cbBuffer == 0) || (pSecBuffer->pvBuffer == NULL)) return;

    if (g_fShowAllBuffers)
    {
        switch (pSecBuffer->BufferType & ~SECBUFFER_READONLY)
        {
            case SECBUFFER_EMPTY:
                WriteLog("SECBUFFER_EMPTY");
                break;
            case SECBUFFER_DATA:
                WriteLog("SECBUFFER_DATA");
                break;
            case SECBUFFER_TOKEN:
                WriteLog("SECBUFFER_TOKEN");
                break;
            case SECBUFFER_PKG_PARAMS:
                WriteLog("SECBUFFER_PKG_PARAMS");
                break;
            case SECBUFFER_MISSING:
                WriteLog("SECBUFFER_MISSING");
                break;
            case SECBUFFER_EXTRA:
                WriteLog("SECBUFFER_EXTRA");
                break;
            case SECBUFFER_STREAM_TRAILER:
                WriteLog("SECBUFFER_STREAM_TRAILER");
                break;
            case SECBUFFER_STREAM_HEADER:
                WriteLog("SECBUFFER_STREAM_HEADER");
                break;
            default:
                WriteLog("SECBUFFER_UNKNOWN");
                break;
        }
    }
    else
    {
        if ((pSecBuffer->BufferType & ~SECBUFFER_READONLY) != SECBUFFER_DATA) return;
    }

    DumpBuffer((LPBYTE)pSecBuffer->pvBuffer, pSecBuffer->cbBuffer);
}

static VOID DumpSecBuffers(LPCTSTR pszLabel, PSecBufferDesc pSecBufferDesc)
{
    if (g_fShowAllBuffers) WriteLog(pszLabel);
    for (ULONG i = 0; i < pSecBufferDesc->cBuffers; i++)
    {
        DumpSecBuffer(&pSecBufferDesc->pBuffers[i]);
    }
}

static VOID CaptureWSABuffers(LPWSABUF lpBuffers, DWORD dwBufferCount, DWORD cbTransferred, BOOL fOutbound)
{
    WaitForSingleObject(g_hMutex, INFINITE);

    FILE *fp = fopen(PCAP_FILE, "ab");
    if (fp != NULL)
    {
        for (DWORD i = 0; i < dwBufferCount; i++)
        {
            if (cbTransferred == 0) break;

            CHAR *buf = lpBuffers[i].buf;
            ULONG len = cbTransferred > lpBuffers[i].len ? lpBuffers[i].len : cbTransferred;
            WritePCapPacket(fp, (LPBYTE)buf, len, fOutbound);
            DumpBuffer((LPBYTE)buf, len);
            cbTransferred -= len;
        }
        fclose(fp);
    }

    ReleaseMutex(g_hMutex);
}


////////////////////////////////////////////////////////////////////////
//
// KERNEL32 Hooks
//
typedef struct {
    PTP_IO pio;
    PTP_WIN32_IO_CALLBACK pfnio;
    PVOID pv;
} ThreadpoolIoContext;

#define MAX_THREADPOOL_IO_CONTEXTS 10

static ThreadpoolIoContext g_ThreadpoolIoContext[MAX_THREADPOOL_IO_CONTEXTS];

ThreadpoolIoContext *AllocThreadpoolIoContext()
{
    for (int i = 0; i < MAX_THREADPOOL_IO_CONTEXTS; i++)
    {
        ThreadpoolIoContext *pContext = &g_ThreadpoolIoContext[i];
        if (pContext->pio == NULL) return pContext;
    }
    return NULL;
}

ThreadpoolIoContext *FindThreadpoolIoContext(PTP_IO pio)
{
    for (int i = 0; i < MAX_THREADPOOL_IO_CONTEXTS; i++)
    {
        ThreadpoolIoContext *pContext = &g_ThreadpoolIoContext[i];
        if (pContext->pio == pio) return pContext;
    }
    return NULL;
}

VOID FreeThreadpoolIoContext(ThreadpoolIoContext *pContext)
{
    ZeroMemory(pContext, sizeof(*pContext));
}

VOID CALLBACK
ThreadpoolIoCompletionCallback(
    PTP_CALLBACK_INSTANCE Instance,
    PVOID Context,
    PVOID Overlapped,
    ULONG IoResult,
    ULONG_PTR NumberOfBytesTransferred,
    PTP_IO pio
)
{
    WriteLog("ThreadpoolIoCompletionCallback(Instance=%p, Context=%p, Overlapped=%p, IoResult=%lx, NumberOfBytesTransferred=%ld, pio=%p",
        Instance, Context, Overlapped, IoResult, NumberOfBytesTransferred, pio);

    if (!g_fTransportSecured)
    {
        if (g_wsaRecvContext.lpOverlapped == Overlapped)
        {
            CaptureWSABuffers(g_wsaRecvContext.lpBuffers, g_wsaRecvContext.dwBufferCount, (DWORD)NumberOfBytesTransferred, FALSE);
        }

        if (g_wsaSendContext.lpOverlapped == Overlapped)
        {
            CaptureWSABuffers(g_wsaSendContext.lpBuffers, g_wsaSendContext.dwBufferCount, (DWORD)NumberOfBytesTransferred, TRUE);
        }
    }

    ThreadpoolIoContext *pContext = (ThreadpoolIoContext *)Context;
    pContext->pfnio(Instance, pContext->pv, Overlapped, IoResult, NumberOfBytesTransferred, pio);
}

void WINAPI
Hook_CloseThreadpoolIo(
    PTP_IO pio
)
{
    WriteLog("CloseThreadpoolIo(pio=%p)", pio);

    NWHOOKAPI_CALL(Real_CloseThreadpoolIo)(pio);

    ThreadpoolIoContext *pContext = FindThreadpoolIoContext(pio);
    if (pContext) FreeThreadpoolIoContext(pContext);
}

PTP_IO WINAPI
Hook_CreateThreadpoolIo(
  HANDLE                fl,
  PTP_WIN32_IO_CALLBACK pfnio,
  PVOID                 pv,
  PTP_CALLBACK_ENVIRON  pcbe
)
{
    PTP_IO pio = NULL;

    WriteLog("CreateThreadpoolIo(fl=%p, pfnio=%p, pv=%p, pcbe=%p)", fl, pfnio, pv, pcbe);

    ThreadpoolIoContext *pContext = AllocThreadpoolIoContext();
    if (pContext)
    {
        pio = NWHOOKAPI_CALL(Real_CreateThreadpoolIo)(fl, ThreadpoolIoCompletionCallback, pContext, pcbe);
        if (pio)
        {
            pContext->pio = pio;
            pContext->pfnio = pfnio;
            pContext->pv = pv;
        }
        else FreeThreadpoolIoContext(pContext);
    }
    else
    {
        pio = NWHOOKAPI_CALL(Real_CreateThreadpoolIo)(fl, pfnio, pv, pcbe);
    }
    WriteLog("\tpio=%p", pio);

    return pio;
}

BOOL WINAPI
Hook_GetOverlappedResult(
    HANDLE hFile,
    LPWSAOVERLAPPED lpOverlapped,
    LPDWORD lpcbTransfer,
    BOOL fWait
)
{
    WriteLog("GetOverlappedResult(hFile=%x, lpOverlapped=%p, lpcbTransfer=%p, fWait=%d)", hFile, lpOverlapped, lpcbTransfer, fWait ? 1 : 0);

    return NWHOOKAPI_CALL(Real_GetOverlappedResult)(hFile, lpOverlapped, lpcbTransfer, fWait);
}

BOOL WINAPI
Hook_GetOverlappedResultEx(
  HANDLE       hFile,
  LPOVERLAPPED lpOverlapped,
  LPDWORD      lpcbTransfer,
  DWORD        dwMilliseconds,
  BOOL         bAlertable
)
{
    WriteLog("GetOverlappedResultEx(hFile=%x, lpOverlapped=%p, lpcbTransfer=%p, dwMilliseconds=%lu, bAlertable=%d)", hFile, lpOverlapped, lpcbTransfer, dwMilliseconds, bAlertable ? 1 : 0);

    return NWHOOKAPI_CALL(Real_GetOverlappedResultEx)(hFile, lpOverlapped, lpcbTransfer, dwMilliseconds, bAlertable);
}

void WINAPI
Hook_StartThreadpoolIo(
    PTP_IO pio
)
{
    WriteLog("StartThreadpoolIo(pio=%p)", pio);

    NWHOOKAPI_CALL(Real_StartThreadpoolIo)(pio);
}


////////////////////////////////////////////////////////////////////////
//
// MSTSCAX Hooks
//
HRESULT WINAPI
Hook_DllGetClassObject(
    REFCLSID rclsid,
    REFIID riid,
    LPVOID *ppv
)
{
    WriteLog("DllGetClassObject");
  
    WriteCLSID(rclsid);
    WriteIID(riid);

    if (riid == IID_IClassFactory)
    {
        HRESULT hr = NWHOOKAPI_CALL(Real_DllGetClassObject)(rclsid, riid, ppv);
        if (hr == S_OK)
        {
            *ppv = (LPVOID)new CClassFactory(rclsid, (IClassFactory *)*ppv);
        }
        return hr;
    }

    return NWHOOKAPI_CALL(Real_DllGetClassObject)(rclsid, riid, ppv);
}


////////////////////////////////////////////////////////////////////////
//
// SSPICLI Hooks
//
SECURITY_STATUS SEC_ENTRY
Hook_AcceptSecurityContext(
    PCredHandle phCredential,               // Cred to base context
    PCtxtHandle phContext,                  // Existing context (OPT)
    PSecBufferDesc pInput,                  // Input buffer
    unsigned long pfContextReq,             // Context Requirements
    unsigned long TargetDataRep,            // Target Data Rep
    PCtxtHandle phNewContext,               // (out) New context handle
    PSecBufferDesc pOutput,                 // (inout) Output buffers
    unsigned long SEC_FAR * pfContextAttr,  // (out) Context attributes
    PTimeStamp ptsExpiry                    // (out) Life span (OPT)
)
{
    //WriteLog("AcceptSecurityContext");
    return NWHOOKAPI_CALL(Real_AcceptSecurityContext)(
        phCredential,
        phContext,
        pInput,
        pfContextReq,
        TargetDataRep,
        phNewContext,
        pOutput,
        pfContextAttr,
        ptsExpiry);
}

SECURITY_STATUS SEC_ENTRY
Hook_AcquireCredentialsHandleA(
    SEC_CHAR SEC_FAR * pszPrincipal,    // Name of principal
    SEC_CHAR SEC_FAR * pszPackage,      // Name of package
    unsigned long fCredentialUse,       // Flags indicating use
    void SEC_FAR * pvLogonId,           // Pointer to logon ID
    void SEC_FAR * pAuthData,           // Package specific data
    SEC_GET_KEY_FN pGetKeyFn,           // Pointer to GetKey() func
    void SEC_FAR * pvGetKeyArgument,    // Value to pass to GetKey()
    PCredHandle phCredential,           // (out) Cred Handle
    PTimeStamp ptsExpiry                // (out) Lifetime (optional)
)
{
    //WriteLog("AcquireCredentialsHandleA");
    return NWHOOKAPI_CALL(Real_AcquireCredentialsHandleA)(
        pszPrincipal,
        pszPackage,
        fCredentialUse,
        pvLogonId,
        pAuthData,
        pGetKeyFn,
        pvGetKeyArgument,
        phCredential,
        ptsExpiry);
}

SECURITY_STATUS SEC_ENTRY
Hook_AcquireCredentialsHandleW(
    SEC_WCHAR SEC_FAR * pszPrincipal,   // Name of principal
    SEC_WCHAR SEC_FAR * pszPackage,     // Name of package
    unsigned long fCredentialUse,       // Flags indicating use
    void SEC_FAR * pvLogonId,           // Pointer to logon ID
    void SEC_FAR * pAuthData,           // Package specific data
    SEC_GET_KEY_FN pGetKeyFn,           // Pointer to GetKey() func
    void SEC_FAR * pvGetKeyArgument,    // Value to pass to GetKey()
    PCredHandle phCredential,           // (out) Cred Handle
    PTimeStamp ptsExpiry                // (out) Lifetime (optional)
)
{
    //WriteLog("AcquireCredentialsHandleW");
    return NWHOOKAPI_CALL(Real_AcquireCredentialsHandleW)(
        pszPrincipal,
        pszPackage,
        fCredentialUse,
        pvLogonId,
        pAuthData,
        pGetKeyFn,
        pvGetKeyArgument,
        phCredential,
        ptsExpiry);
}

SECURITY_STATUS SEC_ENTRY
Hook_DecryptMessage(
    PCtxtHandle phContext,
    PSecBufferDesc pMessage,
    unsigned long MessageSeqNo,
    unsigned long * pfQOP
)
{
    SECURITY_STATUS status;

    WriteLog("DecryptMessage");

    if (!IsAddressInModule(_ReturnAddress(), "MSTSCAX.DLL"))
    {
        return NWHOOKAPI_CALL(Real_DecryptMessage)(
            phContext,
            pMessage,
            MessageSeqNo,
            pfQOP);
    }

    WaitForSingleObject(g_hMutex, INFINITE);

    WriteLog("DecryptMessage");
    if (g_fShowAllBuffers)
    {
        DumpSecBuffers("PRE-DECRYPTION", pMessage);
    }
    status = NWHOOKAPI_CALL(Real_DecryptMessage)(
        phContext,
        pMessage,
        MessageSeqNo,
        pfQOP);
    DumpSecBuffers("POST-DECRYPTION", pMessage);

    FILE *fp = fopen(PCAP_FILE, "ab");
    WriteLog("fp=%p", fp);
    if (fp != NULL)
    {
        for (ULONG i = 0; i < pMessage->cBuffers; i++)
        {
            PSecBuffer pSecBuffer = &pMessage->pBuffers[i];
            if ((pSecBuffer->BufferType & ~SECBUFFER_READONLY) == SECBUFFER_DATA)
            {
                WritePCapPacket(fp, (LPBYTE)pSecBuffer->pvBuffer, pSecBuffer->cbBuffer, FALSE);
            }
        }
        fclose(fp);
    }

    ReleaseMutex(g_hMutex);

    return status;
}

SECURITY_STATUS SEC_ENTRY
Hook_EncryptMessage(
    PCtxtHandle phContext,
    unsigned long fQOP,
    PSecBufferDesc pMessage,
    unsigned long MessageSeqNo
)
{
    SECURITY_STATUS status;

    WriteLog("EncryptMessage");

    if (!IsAddressInModule(_ReturnAddress(), "MSTSCAX.DLL"))
    {
        return NWHOOKAPI_CALL(Real_EncryptMessage)(
            phContext,
            fQOP,
            pMessage,
            MessageSeqNo);
    }

    WaitForSingleObject(g_hMutex, INFINITE);

    FILE *fp = fopen(PCAP_FILE, "ab");
    if (fp != NULL)
    {
        for (ULONG i = 0; i < pMessage->cBuffers; i++)
        {
            PSecBuffer pSecBuffer = &pMessage->pBuffers[i];
            WritePCapPacket(fp, (LPBYTE)pSecBuffer->pvBuffer, pSecBuffer->cbBuffer, TRUE);
        }
        fclose(fp);
    }
    
    WriteLog("EncryptMessage - phContext=%x, fQOP=%d, pMessage=%x, MessageSeqNo=%lu", phContext, fQOP, pMessage, MessageSeqNo);
    DumpSecBuffers("PRE-ENCRYPTION", pMessage);
    status = NWHOOKAPI_CALL(Real_EncryptMessage)(
        phContext,
        fQOP,
        pMessage,
        MessageSeqNo);
    if (g_fShowAllBuffers)
    {
        DumpSecBuffers("POST-ENCRYPTION", pMessage);
    }

    g_fTransportSecured = TRUE;

    ReleaseMutex(g_hMutex);

    return status;
}


////////////////////////////////////////////////////////////////////////
//
// WS2_32 Hooks
//

static BOOL IsStreamSocket(SOCKET s)
{
    int soType;
    char *optval;
    int optlen;
    int retval;

    optval = (char *)&soType;
    optlen = sizeof(soType);
    retval = NWHOOKAPI_CALL(Real_getsockopt)(s, SOL_SOCKET, SO_TYPE, optval, &optlen);
    if (retval == 0)
    {
        return soType == SOCK_STREAM ? TRUE : FALSE;
    }
    
    return TRUE;
}

int WSAAPI
Hook_WSAAsyncSelect(
    SOCKET s,
    HWND hWnd,
    UINT wMsg,
    long lEvent
)
{
    WriteLog("WSAAsyncSelect(s=%x, hWnd=%p, wMsg=%x, lEvent=%lx)", s, hWnd, wMsg, lEvent);

    return NWHOOKAPI_CALL(Real_WSAAsyncSelect)(s, hWnd, wMsg, lEvent);
}

int WSAAPI
Hook_WSAEnumNetworkEvents(
    SOCKET s,
    WSAEVENT hEventObject,
    LPWSANETWORKEVENTS lpNetworkEvents
)
{
    WriteLog("WSAEnumNetworkEvents(s=%x, hEventObject=%p, lpNetworkEvents=%p)", s, hEventObject, lpNetworkEvents);

    int retval = NWHOOKAPI_CALL(Real_WSAEnumNetworkEvents)(s, hEventObject, lpNetworkEvents);
    if ((retval == 0) && lpNetworkEvents)
    {
        WriteLog("lNetworkEvents=%lx", lpNetworkEvents->lNetworkEvents);
    }

    return retval;
}

int WSAAPI
Hook_WSAEventSelect(
    SOCKET s,
    WSAEVENT hEventObject,
    long lNetworkEvents
)
{
    WriteLog("WSAEventSelect(s=%x, hEventObject=%p, lNetworkEvents=%lx)", s, hEventObject, lNetworkEvents);

    return NWHOOKAPI_CALL(Real_WSAEventSelect)(s, hEventObject, lNetworkEvents);
}

int WSAAPI
Hook_WSAGetLastError()
{
    return NWHOOKAPI_CALL(Real_WSAGetLastError)();
}

BOOL WSAAPI
Hook_WSAGetOverlappedResult(
    SOCKET s,
    LPWSAOVERLAPPED lpOverlapped,
    LPDWORD lpcbTransfer,
    BOOL fWait,
    LPDWORD lpdwFlags
)
{
    WriteLog("WSAGetOverlappedResult(s=%x, lpOverlapped=%p, lpcbTransfer=%p, fWait=%d, lpdwFlags=%p)",
        s, lpOverlapped, lpcbTransfer, fWait ? 1 : 0, lpdwFlags);

    return NWHOOKAPI_CALL(Real_WSAGetOverlappedResult)(s, lpOverlapped, lpcbTransfer, fWait, lpdwFlags);
}

int WSAAPI
Hook_WSAIoctl(
  SOCKET s,
  DWORD dwIoControlCode,
  LPVOID lpvInBuffer,
  DWORD cbInBuffer,
  LPVOID lpvOutBuffer,
  DWORD cbOutBuffer,
  LPDWORD lpcbBytesReturned,
  LPWSAOVERLAPPED lpOverlapped,
  LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
)
{
    WriteLog("WSAIoctl(s=%x, dwIoControlCode=%lx, lpvInBuffer=%p, cbInBuffer=%ld, lpvOutBuffer=%p, cbOutBuffer=%ld, lpcbBytesReturned=%p, lpOverlapped=%p, lpCompletionRoutine=%p",
        s, dwIoControlCode, lpvInBuffer, cbInBuffer, lpvOutBuffer, cbOutBuffer, lpcbBytesReturned, lpOverlapped, lpCompletionRoutine);

    return NWHOOKAPI_CALL(Real_WSAIoctl)(s, dwIoControlCode, lpvInBuffer, cbInBuffer, lpvOutBuffer, cbOutBuffer, lpcbBytesReturned, lpOverlapped, lpCompletionRoutine);
}

void CALLBACK
WSARecvCompletionRoutine(
    DWORD dwError,
    DWORD cbTransferred,
    LPWSAOVERLAPPED lpOverlapped,
    DWORD dwFlags
)
{
    WriteLog("WSARecvCompletionRoutine(dwError=%lu, cbTransferred=%lu, lpOverlapped=%p, dwFlags=%lx)", dwError, cbTransferred, lpOverlapped, dwFlags);

    if (cbTransferred > 0)
    {
        CaptureWSABuffers(g_wsaRecvContext.lpBuffers, g_wsaRecvContext.dwBufferCount, cbTransferred, FALSE);
    }

    if (g_wsaRecvContext.lpCompletionRoutine)
    {
        g_wsaRecvContext.lpCompletionRoutine(dwError, cbTransferred, lpOverlapped, dwFlags);
    }
}

void CALLBACK
WSASendCompletionRoutine(
    DWORD dwError,
    DWORD cbTransferred,
    LPWSAOVERLAPPED lpOverlapped,
    DWORD dwFlags
)
{
    WriteLog("WSASendCompletionRoutine(dwError=%lu, cbTransferred=%lu, lpOverlapped=%p, dwFlags=%lx)", dwError, cbTransferred, lpOverlapped, dwFlags);

    if (cbTransferred > 0)
    {
        CaptureWSABuffers(g_wsaSendContext.lpBuffers, g_wsaSendContext.dwBufferCount, cbTransferred, TRUE);
    }

    if (g_wsaSendContext.lpCompletionRoutine)
    {
        g_wsaSendContext.lpCompletionRoutine(dwError, cbTransferred, lpOverlapped, dwFlags);
    }
}

int WSAAPI
Hook_WSARecv(
    SOCKET s,
    LPWSABUF lpBuffers,
    DWORD dwBufferCount,
    LPDWORD lpNumberOfBytesRecvd,
    LPDWORD lpFlags,
    LPWSAOVERLAPPED lpOverlapped,
    LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
)
{
    WriteLog("WSARecv(s=%x, lpBuffers=%p, dwBufferCount=%lu, lpNumberOfBytesRecvd=%p, lpFlags=%p, lpOverlapped=%p, lpCompletionRoutine=%p)",
        s, lpBuffers, dwBufferCount, lpNumberOfBytesRecvd, lpFlags, lpOverlapped, lpCompletionRoutine);
    if (lpFlags)
    {
        WriteLog("lpFlags=%x", *lpFlags);
    }

    if (lpOverlapped)
    {
        WriteLog("hEvent=%p", lpOverlapped->hEvent);
    }

    int retval, lasterror;
    if (IsStreamSocket(s) && !g_fTransportSecured)
    {
        // Stash the receive context.
        ZeroMemory(&g_wsaRecvContext, sizeof(g_wsaRecvContext));
        g_wsaRecvContext.socket = s;
        g_wsaRecvContext.lpBuffers = lpBuffers;
        g_wsaRecvContext.dwBufferCount = dwBufferCount;
        g_wsaRecvContext.lpOverlapped = lpOverlapped;
        g_wsaRecvContext.lpCompletionRoutine = lpCompletionRoutine;

        //lpOverlapped = NULL;
        //lpCompletionRoutine = WSARecvCompletionRoutine;

        retval = NWHOOKAPI_CALL(Real_WSARecv)(s, lpBuffers, dwBufferCount, lpNumberOfBytesRecvd, lpFlags, lpOverlapped, lpCompletionRoutine);
        lasterror = NWHOOKAPI_CALL(Real_WSAGetLastError)();
        WriteLog("retval=%d, lasterror=%d", retval, lasterror);
        if (retval == 0)
        {
            // The receive completed successfully - capture the buffers.
            CaptureWSABuffers(lpBuffers, dwBufferCount, *lpNumberOfBytesRecvd, FALSE);
        }
        if ((retval == SOCKET_ERROR) && (lasterror == WSA_IO_PENDING))
        {
            // Asynchronous receive started - remember the receive buffers.
        }
        else
        {
            // Forget the receive buffers.
            ZeroMemory(&g_wsaRecvContext, sizeof(g_wsaRecvContext));
        }
        NWHOOKAPI_CALL(Real_WSASetLastError)(lasterror);

        return retval;
    }       

    retval = NWHOOKAPI_CALL(Real_WSARecv)(s, lpBuffers, dwBufferCount, lpNumberOfBytesRecvd, lpFlags, lpOverlapped, lpCompletionRoutine);
    lasterror = NWHOOKAPI_CALL(Real_WSAGetLastError)();
    WriteLog("retval=%d, lasterror=%d", retval, lasterror);
    NWHOOKAPI_CALL(Real_WSASetLastError)(lasterror);

    return retval;
}

int WSAAPI
Hook_WSASend(
    SOCKET s,
    LPWSABUF lpBuffers,
    DWORD dwBufferCount,
    LPDWORD lpNumberOfBytesSent,
    DWORD dwFlags,
    LPWSAOVERLAPPED lpOverlapped,
    LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
)
{
    WriteLog("WSASend(s=%x, lpBuffers=%p, dwBufferCount=%lu, lpNumberOfBytesSent=%p, dwFlags=%x, lpOverlapped=%p, lpCompletionRoutine=%p)",
        s, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags, lpOverlapped, lpCompletionRoutine);

    int retval, lasterror;
    if (IsStreamSocket(s) && !g_fTransportSecured)
    {
        // Stash the send context.
        ZeroMemory(&g_wsaSendContext, sizeof(g_wsaSendContext));
        g_wsaSendContext.socket = s;
        g_wsaSendContext.lpBuffers = lpBuffers;
        g_wsaSendContext.dwBufferCount = dwBufferCount;
        g_wsaSendContext.lpOverlapped = lpOverlapped;
        g_wsaSendContext.lpCompletionRoutine = lpCompletionRoutine;

        retval = NWHOOKAPI_CALL(Real_WSASend)(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags, lpOverlapped, lpCompletionRoutine);
        lasterror = NWHOOKAPI_CALL(Real_WSAGetLastError)();
        WriteLog("retval=%d, lasterror=%d", retval, lasterror);
        if ((retval == 0) || ((retval == SOCKET_ERROR) && (lasterror == WSA_IO_PENDING)))
        {
            // Asynchronous send started - remember the send buffers.
        }
        else
        {
            // Forget the send buffers.
            ZeroMemory(&g_wsaSendContext, sizeof(g_wsaSendContext));
        }
        NWHOOKAPI_CALL(Real_WSASetLastError)(lasterror);

        return retval;
    }       

    return NWHOOKAPI_CALL(Real_WSASend)(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags, lpOverlapped, lpCompletionRoutine);
}

void WSAAPI
Hook_WSASetLastError(int iError)
{
    return NWHOOKAPI_CALL(Real_WSASetLastError)(iError);
}

SOCKET WSAAPI
Hook_WSASocketW(
    int af,
    int type,
    int protocol,
    LPWSAPROTOCOL_INFOW lpProtocolInfo,
    GROUP g,
    DWORD dwFlags
)
{
    WriteLog("WSASocketW(af=%d, type=%d, protocol=%d, lpProtocolInfo=%p, dwFlags=%lx)", af, type, protocol, lpProtocolInfo, g, dwFlags);

    SOCKET s = NWHOOKAPI_CALL(Real_WSASocketW)(af, type, protocol, lpProtocolInfo, g, dwFlags);
    WriteLog("\ts=%x", s);
    return s;
}

DWORD WSAAPI
Hook_WSAWaitForMultipleEvents(
    DWORD cEvents,
    const WSAEVENT *lphEvents,
    BOOL fWaitAll,
    DWORD dwTimeout,
    BOOL fAlertable
)
{
    WriteLog("WSAWaitForMultipleEvents(cEvents=%lu, lphEvents=%p, fWaitAll=%d, dwTimeout=%lu, fAlertable=%d)",
        cEvents, lphEvents, fWaitAll ? 1 : 0, dwTimeout, fAlertable ? 1 : 0);
    if (lphEvents)
    {
        for (DWORD i = 0; i < cEvents; i++)
        {
            WriteLog("\thEvent[%lu]=%x", i, lphEvents[i]);
        }
    }

    DWORD retval = NWHOOKAPI_CALL(Real_WSAWaitForMultipleEvents)(cEvents, lphEvents, fWaitAll, dwTimeout, fAlertable);
    int iLastError = WSAGetLastError();
    WriteLog("retval=%lu", retval);
    if (g_wsaRecvContext.lpOverlapped)
    {
        DWORD cbTransfer = 0;
        DWORD dwFlags = 0;
        if (WSAGetOverlappedResult(g_wsaRecvContext.socket, g_wsaRecvContext.lpOverlapped, &cbTransfer, FALSE, &dwFlags))
        {
            WriteLog("I/O completed - cbTransfer=%u, dwFlags=%x", cbTransfer, dwFlags);
        }
    }
    WSASetLastError(iLastError);
    return retval;
}

int WSAAPI
Hook_getsockopt(
    SOCKET s,
    int level,
    int optname,
    char *optval,
    int *optlen
)
{
    WriteLog("getsockopt(s=%x, level=%d(0x%x), optname=%d(0x%x), optval=%p, optlen=%p)", s, level, level, optname, optname, optval, optlen);

    return NWHOOKAPI_CALL(Real_getsockopt)(s, level, optname, optval, optlen);
}

int WSAAPI
Hook_ioctlsocket(
    SOCKET s,
    long cmd,
    u_long *argp
)
{
    WriteLog("ioctlsocket(s=%x, cmd=%ld, argp=%p)", s, cmd, argp);

    int retval = NWHOOKAPI_CALL(Real_ioctlsocket)(s, cmd, argp);

    return retval;
}

int WSAAPI
Hook_recv(
    SOCKET s,
    char *buf,
    int len,
    int flags
)
{
    WriteLog("recv(s=%x)", s);
    
    int retval = NWHOOKAPI_CALL(Real_recv)(s, buf, len, flags);

    if (IsStreamSocket(s) && (retval > 0) && !g_fTransportSecured)
    {
        WaitForSingleObject(g_hMutex, INFINITE);

        FILE *fp = fopen(PCAP_FILE, "ab");
        if (fp != NULL)
        {
            WritePCapPacket(fp, (LPBYTE)buf, retval, FALSE);
            fclose(fp);
        }
        
        DumpBuffer((LPBYTE)buf, retval);

        ReleaseMutex(g_hMutex);
    }
    
    return retval;
}

int WSAAPI
Hook_select(
    int nfds,
    fd_set *readfds,
    fd_set *writefds,
    fd_set *exceptfds,
    const timeval *timeout
)
{
    WriteLog("select(nfds=%d, readfds=%p, writefds=%p, exceptfds=%p, timeout=%p", nfds, readfds, writefds, exceptfds, timeout);

    return NWHOOKAPI_CALL(Real_select)(nfds, readfds, writefds, exceptfds, timeout);
}

int WSAAPI
Hook_send(
    SOCKET s,
    char *buf,
    int len,
    int flags
)
{
    WriteLog("send(s=%x)", s);

    if (IsStreamSocket(s) && (len > 0) && !g_fTransportSecured)
    {
        WaitForSingleObject(g_hMutex, INFINITE);

        FILE *fp = fopen(PCAP_FILE, "ab");
        if (fp != NULL)
        {
            WritePCapPacket(fp, (LPBYTE)buf, len, TRUE);
            fclose(fp);
        }
        
        DumpBuffer((LPBYTE)buf, len);

        ReleaseMutex(g_hMutex);
    }

    return NWHOOKAPI_CALL(Real_send)(s, buf, len, flags);
}

int WSAAPI
Hook_setsockopt(
    SOCKET s,
    int level,
    int optname,
    const char *optval,
    int optlen
)
{
    WriteLog("setsockopt(s=%x, level=%d(0x%x), optname=%d(0x%x), optval=%p, optlen=%d)", s, level, level, optname, optname, optval, optlen);

    return NWHOOKAPI_CALL(Real_setsockopt)(s, level, optname, optval, optlen);
}


////////////////////////////////////////////////////////////////////////
//  
// WriteLog
//
// Writes a message to a log file.
//
static HANDLE g_hWriteLogMutex;

static VOID WriteLog(LPCTSTR szFormat, ...)
{
    static BOOL fInitialized = FALSE;
    static TCHAR szFileName[MAX_PATH];

    va_list argList;
    HKEY hKey;
    FILE *fp = NULL;

    try
    {
        if (!fInitialized)
        {
            if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, REGISTRY_KEY, 0, KEY_READ | KEY_WOW64_64KEY, &hKey) == ERROR_SUCCESS)
            {
                DWORD cbData = sizeof(szFileName);
                RegQueryValueEx(hKey, TEXT("TraceLog"), NULL, NULL, (LPBYTE)szFileName, &cbData);
                RegCloseKey(hKey);
            }
#if 0
            strcpy(szFileName, "C:\\Windows\\Temp\\mstschook.log");
#endif
            fInitialized = TRUE;
        }
        if (szFileName[0] == '\0') return;

        if (g_hWriteLogMutex == NULL)
        {
            g_hWriteLogMutex = CreateMutex(NULL, FALSE, NULL);
        }

        if (g_hWriteLogMutex)
        {
            //WaitForSingleObject(g_hWriteLogMutex, INFINITE);
        }

        fp = fopen(szFileName, "a");
        if (fp)
        {
            TCHAR szTimeStamp[30];
            time_t t = time(NULL);
            _tcsftime(szTimeStamp, sizeof(szTimeStamp) / sizeof(TCHAR), TEXT("%d-%b-%Y %H:%M:%S"), localtime(&t));
            va_start(argList, szFormat);
            _ftprintf(fp, TEXT("%s - %u:%u - "), szTimeStamp, GetCurrentProcessId(), GetCurrentThreadId());
            _vftprintf(fp, szFormat, argList);
            va_end(argList);
            fputc('\n', fp);
            fclose(fp);
        }
    }
    catch (...)
    {
        if (fp != NULL)
        {
            fputc('\n', fp);
            _ftprintf(fp, TEXT("WriteLog exception occurred!\n"));
            fclose(fp);
        }
    }

    if (g_hWriteLogMutex)
    {
        ReleaseMutex(g_hWriteLogMutex);
    }
}



////////////////////////////////////////////////////////////////////////
//
// ModuleInHookList
//
// Determines if the application should be hooked.
//
static BOOL ModuleInHookList(LPCTSTR pszFileName)
{
    TCHAR szHookList[4096];
    TCHAR szModuleName[512];
    TCHAR szBase[256];
    TCHAR szExt[64];
    HKEY hKey;
  
    // Split the file name into its components.
    ZeroMemory(szBase, sizeof(szBase));
    ZeroMemory(szExt, sizeof(szExt));
    _splitpath(pszFileName, NULL, NULL, szBase, szExt);
    lstrcpy(szModuleName, szBase);
    if (lstrlen(szExt) > 0)
    {
        lstrcat(szModuleName, szExt);
    }
    if (lstrlen(szModuleName) == 0) return FALSE;

    // Check against MSTSC.EXE.
    if (!lstrcmpi(szModuleName, "mstsc.exe")) return TRUE;
    if (!lstrcmpi(szModuleName, "vmconnect.exe")) return TRUE;

    // Retrieve the exclusion list from the registry.
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, REGISTRY_KEY, 0, KEY_READ | KEY_WOW64_32KEY, &hKey) == ERROR_SUCCESS)
    {
        DWORD cbHookList = sizeof(szHookList);
        ZeroMemory(szHookList, cbHookList);
        RegQueryValueEx(hKey, TEXT("ModuleList"), NULL, NULL, (LPBYTE)szHookList, &cbHookList);
        RegCloseKey(hKey);
    }
    if (lstrlen(szHookList) == 0) return FALSE;

    // Check against the hook list.
    for (LPCTSTR p = szHookList;; )
    {
        LPTSTR pszComma = (LPTSTR)strchr(p, ',');
        if (pszComma) *pszComma = '\0';
        if (!lstrcmpi(p, szModuleName)) return TRUE;
        if (pszComma) p = pszComma + 1; else break;
    }

    return FALSE;
}



////////////////////////////////////////////////////////////////////////
//
// DoProcessAttach
//
// Handles a DLL_PROCESS_ATTACH call to DllMain.
//
static BOOL DoProcessAttach()
{
    TCHAR szFileName[MAX_PATH];
    GetModuleFileName(NULL, szFileName, sizeof(szFileName));
    if (!ModuleInHookList(szFileName)) return FALSE;
    //WriteLog("Loaded into %s...", szFileName);

    g_hMutex = CreateMutex(NULL, FALSE, "MsTscHookMutex");

    // Retrieve settings from the registry.
    HKEY hKey;
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, REGISTRY_KEY, 0, KEY_READ, &hKey) == ERROR_SUCCESS)
    {
        DWORD cbValue = sizeof(DWORD);
        RegQueryValueEx(hKey, TEXT("ShowAllBuffers"), NULL, NULL, (LPBYTE)&g_fShowAllBuffers, &cbValue);
        RegCloseKey(hKey);
    }

    NWHOOKAPI_BEGIN;

    // Hook entry points in KERNEL32.DLL.
    g_hModKernel32 = LoadLibrary("KERNEL32.DLL");
    if (g_hModKernel32)
    {
        NWHOOKAPI_ATTACH(GetProcAddress(g_hModKernel32, "CloseThreadpoolIo"), LPCloseThreadpoolIo, Real_CloseThreadpoolIo, Hook_CloseThreadpoolIo);
        NWHOOKAPI_ATTACH(GetProcAddress(g_hModKernel32, "CreateThreadpoolIo"), LPCreateThreadpoolIo, Real_CreateThreadpoolIo, Hook_CreateThreadpoolIo);
        NWHOOKAPI_ATTACH(GetProcAddress(g_hModKernel32, "GetOverlappedResult"), LPGetOverlappedResult, Real_GetOverlappedResult, Hook_GetOverlappedResult);
        NWHOOKAPI_ATTACH(GetProcAddress(g_hModKernel32, "GetOverlappedResultEx"), LPGetOverlappedResultEx, Real_GetOverlappedResultEx, Hook_GetOverlappedResultEx);
        NWHOOKAPI_ATTACH(GetProcAddress(g_hModKernel32, "StartThreadpoolIo"), LPStartThreadpoolIo, Real_StartThreadpoolIo, Hook_StartThreadpoolIo);
    }

    // Hook entry points in MSTSCAX.DLL.
    g_hModMsTscAx = LoadLibrary("MSTSCAX.DLL");
    if (g_hModMsTscAx)
    {
        NWHOOKAPI_ATTACH(GetProcAddress(g_hModMsTscAx, "DllGetClassObject"), LPDllGetClassObject, Real_DllGetClassObject, Hook_DllGetClassObject);
    }
    
    // Hook entry points in SSPICLI.DLL.
    g_hModSspiCli = GetModuleHandle("SSPICLI.DLL");
    if (g_hModSspiCli)
    {
        NWHOOKAPI_ATTACH(GetProcAddress(g_hModSspiCli, "AcceptSecurityContext"), ACCEPT_SECURITY_CONTEXT_FN, Real_AcceptSecurityContext, Hook_AcceptSecurityContext);
        NWHOOKAPI_ATTACH(GetProcAddress(g_hModSspiCli, "AcquireCredentialsHandleA"), ACQUIRE_CREDENTIALS_HANDLE_FN_A, Real_AcquireCredentialsHandleA, Hook_AcquireCredentialsHandleA);
        NWHOOKAPI_ATTACH(GetProcAddress(g_hModSspiCli, "AcquireCredentialsHandleW"), ACQUIRE_CREDENTIALS_HANDLE_FN_W, Real_AcquireCredentialsHandleW, Hook_AcquireCredentialsHandleW);
        NWHOOKAPI_ATTACH(GetProcAddress(g_hModSspiCli, "DecryptMessage"), DECRYPT_MESSAGE_FN, Real_DecryptMessage, Hook_DecryptMessage);
        NWHOOKAPI_ATTACH(GetProcAddress(g_hModSspiCli, "EncryptMessage"), ENCRYPT_MESSAGE_FN, Real_EncryptMessage, Hook_EncryptMessage);
    }
  
    // Hook entry points in WS2_32.DLL.
    g_hModWinsock = GetModuleHandle("WS2_32.DLL");
    if (g_hModWinsock)
    {
        NWHOOKAPI_ATTACH(GetProcAddress(g_hModWinsock, "WSAAsyncSelect"), LPWSAAsyncSelect, Real_WSAAsyncSelect, Hook_WSAAsyncSelect);
        NWHOOKAPI_ATTACH(GetProcAddress(g_hModWinsock, "WSAEnumNetworkEvents"), LPWSAEnumNetworkEvents, Real_WSAEnumNetworkEvents, Hook_WSAEnumNetworkEvents);
        NWHOOKAPI_ATTACH(GetProcAddress(g_hModWinsock, "WSAEventSelect"), LPWSAEventSelect, Real_WSAEventSelect, Hook_WSAEventSelect);
        NWHOOKAPI_ATTACH(GetProcAddress(g_hModWinsock, "WSAGetLastError"), LPWSAGetLastError, Real_WSAGetLastError, Hook_WSAGetLastError);
        NWHOOKAPI_ATTACH(GetProcAddress(g_hModWinsock, "WSAGetOverlappedResult"), LPWSAGetOverlappedResult, Real_WSAGetOverlappedResult, Hook_WSAGetOverlappedResult);
        NWHOOKAPI_ATTACH(GetProcAddress(g_hModWinsock, "WSAIoctl"), LPWSAIoctl, Real_WSAIoctl, Hook_WSAIoctl);
        NWHOOKAPI_ATTACH(GetProcAddress(g_hModWinsock, "WSARecv"), LPWSARecv, Real_WSARecv, Hook_WSARecv);
        NWHOOKAPI_ATTACH(GetProcAddress(g_hModWinsock, "WSASend"), LPWSASend, Real_WSASend, Hook_WSASend);
        NWHOOKAPI_ATTACH(GetProcAddress(g_hModWinsock, "WSASetLastError"), LPWSASetLastError, Real_WSASetLastError, Hook_WSASetLastError);
        NWHOOKAPI_ATTACH(GetProcAddress(g_hModWinsock, "WSASocketW"), LPWSASocketW, Real_WSASocketW, Hook_WSASocketW);
        NWHOOKAPI_ATTACH(GetProcAddress(g_hModWinsock, "WSAWaitForMultipleEvents"), LPWSAWaitForMultipleEvents, Real_WSAWaitForMultipleEvents, Hook_WSAWaitForMultipleEvents);
        NWHOOKAPI_ATTACH(GetProcAddress(g_hModWinsock, "getsockopt"), LPgetsockopt, Real_getsockopt, Hook_getsockopt);
        NWHOOKAPI_ATTACH(GetProcAddress(g_hModWinsock, "ioctlsocket"), LPioctlsocket, Real_ioctlsocket, Hook_ioctlsocket);
        NWHOOKAPI_ATTACH(GetProcAddress(g_hModWinsock, "recv"), LPrecv, Real_recv, Hook_recv);
        NWHOOKAPI_ATTACH(GetProcAddress(g_hModWinsock, "select"), LPselect, Real_select, Hook_select);
        NWHOOKAPI_ATTACH(GetProcAddress(g_hModWinsock, "send"), LPsend, Real_send, Hook_send);
        NWHOOKAPI_ATTACH(GetProcAddress(g_hModWinsock, "setsockopt"), LPsetsockopt, Real_setsockopt, Hook_setsockopt);
    }

    NWHOOKAPI_COMMIT;

    return TRUE;
}




////////////////////////////////////////////////////////////////////////
//
// DoProcessDetach
//
// Handles a DLL_PROCESS_DETACH call to DllMain.
//
static VOID DoProcessDetach()
{
    TCHAR szFileName[MAX_PATH];
    GetModuleFileName(NULL, szFileName, sizeof(szFileName));
    WriteLog("Unloaded from %s...", szFileName);

    CloseHandle(g_hMutex);

    NWHOOKAPI_BEGIN;

    // Unhook functions in KERNEL32.DLL.
    NWHOOKAPI_DETACH(Real_CloseThreadpoolIo, Hook_CloseThreadpoolIo);
    NWHOOKAPI_DETACH(Real_CreateThreadpoolIo, Hook_CreateThreadpoolIo);
    NWHOOKAPI_DETACH(Real_GetOverlappedResult, Hook_GetOverlappedResult);
    NWHOOKAPI_DETACH(Real_GetOverlappedResultEx, Hook_GetOverlappedResultEx);
    NWHOOKAPI_DETACH(Real_StartThreadpoolIo, Hook_StartThreadpoolIo);

    // Unhook functions in MSTSCAX.DLL.
    NWHOOKAPI_DETACH(Real_DllGetClassObject, Hook_DllGetClassObject);

    // Unhook functions in SSPICLI.DLL.
    NWHOOKAPI_DETACH(Real_AcceptSecurityContext, Hook_AcceptSecurityContext);
    NWHOOKAPI_DETACH(Real_AcquireCredentialsHandleA, Hook_AcquireCredentialsHandleA);
    NWHOOKAPI_DETACH(Real_AcquireCredentialsHandleW, Hook_AcquireCredentialsHandleW);
    NWHOOKAPI_DETACH(Real_DecryptMessage, Hook_DecryptMessage);
    NWHOOKAPI_DETACH(Real_EncryptMessage, Hook_EncryptMessage);
    
    // Unhook functions in WS2_32.DLL.
    NWHOOKAPI_DETACH(Real_WSAAsyncSelect, Hook_WSAAsyncSelect);
    NWHOOKAPI_DETACH(Real_WSAEnumNetworkEvents, Hook_WSAEnumNetworkEvents);
    NWHOOKAPI_DETACH(Real_WSAEventSelect, Hook_WSAEventSelect);
    NWHOOKAPI_DETACH(Real_WSAGetLastError, Hook_WSAGetLastError);
    //NWHOOKAPI_DETACH(Real_WSAGetOverlappedResult, Hook_WSAGetOverlappedResult);
    NWHOOKAPI_DETACH(Real_WSAIoctl, Hook_WSAIoctl);
    NWHOOKAPI_DETACH(Real_WSARecv, Hook_WSARecv);
    NWHOOKAPI_DETACH(Real_WSASend, Hook_WSASend);
    NWHOOKAPI_DETACH(Real_WSASetLastError, Hook_WSASetLastError);
    NWHOOKAPI_DETACH(Real_WSASocketW, Hook_WSASocketW);
    NWHOOKAPI_DETACH(Real_WSAWaitForMultipleEvents, Hook_WSAWaitForMultipleEvents);
    NWHOOKAPI_DETACH(Real_getsockopt, Hook_getsockopt);
    NWHOOKAPI_DETACH(Real_ioctlsocket, Hook_ioctlsocket);
    NWHOOKAPI_DETACH(Real_recv, Hook_recv);
    NWHOOKAPI_DETACH(Real_select, Hook_select);
    NWHOOKAPI_DETACH(Real_send, Hook_send);

    NWHOOKAPI_COMMIT;

    CloseHandle(g_hWriteLogMutex);
}



/////////////////////////////////////////////////////////////////////////////
//
// DllMain
//
// DLL main entry point.
//
extern "C"
BOOL WINAPI DllMain(
    HMODULE hModule,
    DWORD dwReason,
    LPVOID lpReserved
)
{
    BOOL bRet = TRUE;
    switch (dwReason)
    {
        case DLL_PROCESS_ATTACH:
            g_hModule = hModule;
            DisableThreadLibraryCalls(hModule);
            bRet = DoProcessAttach();
            break;

        case DLL_PROCESS_DETACH:
            DoProcessDetach();
            g_hModule = NULL;
            break;

        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
            break;
    }
    return bRet;
}
