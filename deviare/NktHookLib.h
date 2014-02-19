/*
 * Copyright (C) 2010-2013 Nektra S.A., Buenos Aires, Argentina.
 * All rights reserved. Contact: http://www.nektra.com
 *
 *
 * This file is part of Deviare In-Proc
 *
 *
 * Commercial License Usage
 * ------------------------
 * Licensees holding valid commercial Deviare In-Proc licenses may use this
 * file in accordance with the commercial license agreement provided with the
 * Software or, alternatively, in accordance with the terms contained in
 * a written agreement between you and Nektra.  For licensing terms and
 * conditions see http://www.nektra.com/licensing/.  For further information
 * use the contact form at http://www.nektra.com/contact/.
 *
 *
 * GNU General Public License Usage
 * --------------------------------
 * Alternatively, this file may be used under the terms of the GNU
 * General Public License version 3.0 as published by the Free Software
 * Foundation and appearing in the file LICENSE.GPL included in the
 * packaging of this file.  Please review the following information to
 * ensure the GNU General Public License version 3.0 requirements will be
 * met: http://www.gnu.org/copyleft/gpl.html.
 *
 **/

#ifndef _NKTHOOKLIB
#define _NKTHOOKLIB

#include <windows.h>

//-----------------------------------------------------------

#define NKTHOOKLIB_DontSkipInitialJumps               0x0001
#define NKTHOOKLIB_DontRemoveOnUnhook                 0x0002

//-----------------------------------------------------------

class CNktHookLib
{
public:
  typedef struct {
    SIZE_T nHookId;
    LPVOID lpProcToHook;
    LPVOID lpNewProcAddr;
    //----
    LPVOID lpCallOriginal;
  } HOOK_INFO;

  CNktHookLib();
  ~CNktHookLib();

  DWORD Hook(__out SIZE_T *lpnHookId, __out LPVOID *lplpCallOriginal, __in LPVOID lpProcToHook,
             __in LPVOID lpNewProcAddr, __in DWORD dwFlags=0);
  DWORD Hook(__inout HOOK_INFO aHookInfo[], __in SIZE_T nCount, __in DWORD dwFlags=0);

  DWORD RemoteHook(__out SIZE_T *lpnHookId, __out LPVOID *lplpCallOriginal, __in DWORD dwPid,
                   __in LPVOID lpProcToHook, __in LPVOID lpNewProcAddr, __in DWORD dwFlags);
  DWORD RemoteHook(__inout HOOK_INFO aHookInfo[], __in SIZE_T nCount, __in DWORD dwPid, __in DWORD dwFlags);

  DWORD RemoteHook(__out SIZE_T *lpnHookId, __out LPVOID *lplpCallOriginal, __in HANDLE hProcess,
                   __in LPVOID lpProcToHook, __in LPVOID lpNewProcAddr, __in DWORD dwFlags);
  DWORD RemoteHook(__inout HOOK_INFO aHookInfo[], __in SIZE_T nCount, __in HANDLE hProcess, __in DWORD dwFlags);

  DWORD Unhook(__in SIZE_T nHookId);
  DWORD Unhook(__in HOOK_INFO aHookInfo[], __in SIZE_T nCount);
  VOID UnhookProcess(__in DWORD dwPid);
  VOID UnhookAll();

  DWORD EnableHook(__in SIZE_T nHookId, __in BOOL bEnable);
  DWORD EnableHook(__in HOOK_INFO aHookInfo[], __in SIZE_T nCount, __in BOOL bEnable);

  DWORD SetSuspendThreadsWhileHooking(__in BOOL bEnable);
  BOOL GetSuspendThreadsWhileHooking();

  DWORD SetEnableDebugOutput(__in BOOL bEnable);
  BOOL GetEnableDebugOutput();

private:
  LPVOID lpInternals;
};

//-----------------------------------------------------------

#endif //_NKTHOOKLIB
