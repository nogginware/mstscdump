//======================================================================
//
// NWHookAPI.h
//
// Copyright (C) 2014 Nogginware Corporation
//
// Enables hooking of Windows system calls.
//
// Change History:
//
//  19-Feb-2014   Mike McDonald
//      Initial release.
//
//======================================================================

#ifndef NWHookAPI_H
#define NWHookAPI_H

////////////////////////////////////////////////////////////////////////
//
// Microsoft Detours
//

#if defined(USE_DETOURS)

#define NWHOOKAPI_HOOK(_type, _name) _type _name
#define NWHOOKAPI_CALL(_name) (_name)

#if defined(_X86_)

#include "detours15\detours.h"

#define NWHOOKAPI_BEGIN
#define NWHOOKAPI_COMMIT

#define NWHOOKAPI_ATTACH(_proc, _type, _real, _hook) \
{ \
  _real = (_type)DetourFunction((PBYTE)_proc, (PBYTE)_hook); \
}

#define NWHOOKAPI_DETACH(_real, _hook) \
{ \
  if (_real) DetourRemove((PBYTE)_real, (PBYTE)_hook); \
}

#elif defined(_AMD64_)

#include "detours21\detours.h"

#define NWHOOKAPI_BEGIN \
{ \
  DetourTransactionBegin(); \
  DetourUpdateThread(GetCurrentThread()); \
}

#define NWHOOKAPI_COMMIT DetourTransactionCommit()

#define NWHOOKAPI_ATTACH(_proc, _type, _real, _hook) \
{ \
  _real = (_type)_proc; \
  if (_real) DetourAttach(&(PVOID&)_real, _hook); \
}

#define NWHOOKAPI_DETACH(_real, _hook) \
{ \
  if (_real) DetourDetach(&(PVOID&)_real, _hook); \
}

#else
**** _X86_ or _AMD64_ must be defined for Detours hooking
#endif


////////////////////////////////////////////////////////////////////////
//
// Deviare
//

#elif defined(USE_DEVIARE)

#include "deviare\NktHookLib.h"

static CNktHookLib cNktHookMgr;

#define NWHOOKAPI_HOOK(_type, _name) \
struct { \
  SIZE_T nHookId; \
  _type pProcAddr; \
} _name = { 0, NULL };

#define NWHOOKAPI_CALL(_name) (_name.pProcAddr)

#define NWHOOKAPI_BEGIN
#define NWHOOKAPI_COMMIT

#define NWHOOKAPI_ATTACH(_proc, _type, _real, _hook) \
{ \
	_type _addr = (_type)_proc; \
	if (_addr) cNktHookMgr.Hook(&_real.nHookId, (LPVOID *)&_real.pProcAddr, _proc, _hook); \
}
#define NWHOOKAPI_DETACH(_real, _hook) \
{ \
	cNktHookMgr.Unhook(_real.nHookId); \
}


////////////////////////////////////////////////////////////////////////
//
// Custom API
//

#else

#define NWHOOKAPI_HOOK(_type, _name) _type _name
#define NWHOOKAPI_CALL(_name) (_name)

#define NWHOOKAPI_BEGIN
#define NWHOOKAPI_COMMIT

#define NWHOOKAPI_ATTACH(_proc, _type, _real, _hook) _real = (_type)NWHookCreate(_proc, _hook)
#define NWHOOKAPI_DETACH(_real, _hook) NWHookDelete(_real)

#ifdef __cplusplus
extern "C" {
LPVOID NWHookCreate(LPVOID lpOrigFunction, LPVOID lpHookFunction);
VOID   NWHookDelete(LPVOID lpHook);
}
#endif

#endif

#endif