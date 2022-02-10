//======================================================================
//
// NWHookAPI.h
//
// Copyright (C) 2014 Nogginware Corporation
//
// Unit test code for NWHookAPI.
//
// Change History:
//
//  19-Feb-2014   Mike McDonald
//      Initial release.
//
//======================================================================

#define SECURITY_WIN32

#include <intrin.h>
#include <windows.h>
#include <sspi.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef USE_DETOURS
#undef USE_DETOURS
#endif

#ifdef USE_DEVIARE
#undef USE_DEVIARE
#endif

#include "NWHookAPI.h"

typedef int (WINAPI *LPGETSYSTEMMETRICS)(int nIndex);

static LPGETSYSTEMMETRICS Real_GetSystemMetrics;

static ENCRYPT_MESSAGE_FN Real_EncryptMessage;

int WINAPI Hook_GetSystemMetrics(int nIndex)
{
  printf("Hook_GetSystemMetrics(%d)\n", nIndex);
  if (nIndex == SM_CMONITORS) return 0;
  
  return Real_GetSystemMetrics(nIndex);
}

SECURITY_STATUS SEC_ENTRY
Hook_EncryptMessage(
  PCtxtHandle phContext,
  unsigned long fQOP,
  PSecBufferDesc pMessage,
  unsigned long MessageSeqNo
)
{
  printf("Hook_EncryptMessage\n");
  return Real_EncryptMessage(
    phContext,
    fQOP,
    pMessage,
    MessageSeqNo);
}



void main(int argc, char **argv)
{
  HMODULE hModUser32;
  HMODULE hModSecur32;

  hModUser32 = LoadLibrary("USER32.DLL");
  if (hModUser32 == NULL) exit(1);
  hModSecur32 = LoadLibrary("SECUR32.DLL");
  if (hModSecur32 == NULL) exit(1);  

#if 1  
  printf("cMonitors(real)=%d\n", GetSystemMetrics(SM_CMONITORS));
  Real_GetSystemMetrics = (LPGETSYSTEMMETRICS)NWHookCreate(GetProcAddress(hModUser32, "GetSystemMetrics"), Hook_GetSystemMetrics);
  printf("cMonitors(hook)=%d\n", GetSystemMetrics(SM_CMONITORS));
  NWHookDelete(Real_GetSystemMetrics);
#endif
  
  Real_EncryptMessage = (ENCRYPT_MESSAGE_FN)NWHookCreate(GetProcAddress(hModSecur32, "EncryptMessage"), Hook_EncryptMessage);
  EncryptMessage(NULL, 0, NULL, 0);
  NWHookDelete(Real_EncryptMessage);
  
  FreeLibrary(hModUser32);
  FreeLibrary(hModSecur32);
  
  exit(0);
}