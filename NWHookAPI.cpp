//======================================================================
//
// NWHookAPI.cpp
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

#include <intrin.h>
#include <windows.h>
#include <stdio.h>

#ifdef USE_DETOURS
#undef USE_DETOURS
#endif

#ifdef USE_DEVIARE
#undef USE_DEVIARE
#endif

#include "NWHookAPI.h"

#define DEBUG 1

////////////////////////////////////////////////////////////////////////
//
// Type Definitions
//
#define MAGIC_NUMBER 0x6b6f6f68

#ifdef _AMD64_
#define JMP_INSTRUCTION_SIZE 12
typedef ULONGLONG QWORD;
#else
#define JMP_INSTRUCTION_SIZE 5
#endif

typedef struct {
  DWORD  dwMagicNumber;
  LPVOID lpOrigFunction;
  LPVOID lpHookFunction;
  DWORD  dwPreambleSize;
} HOOK, *LPHOOK;

////////////////////////////////////////////////////////////////////////
//
// Local Functions
//
static VOID WriteJMPInstruction(LPBYTE lpSource, LPBYTE lpTarget);
static DWORD PreambleSize(LPBYTE);
static DWORD InstructionSize(LPBYTE);

////////////////////////////////////////////////////////////////////////
//
// NWHookCreate
//
// Hooks a function.
//
LPVOID NWHookCreate(LPVOID lpOrigFunction, LPVOID lpHookFunction)
{
  DWORD dwSize, dwOldProtect;
  LPHOOK lpHook = NULL;
  LPBYTE lpCode = NULL;
  DWORD dwDiff;

  // Check the function being hooked.
  if ((lpOrigFunction != NULL) && (dwSize = PreambleSize((LPBYTE)lpOrigFunction)) > 0)
  {
    // Change the protection on the function being hooked.
    if (VirtualProtect(lpOrigFunction, dwSize, PAGE_READWRITE, &dwOldProtect))
    {
      // Allocate a HOOK data structure.
      lpHook = (LPHOOK)VirtualAlloc(NULL, sizeof(HOOK) + dwSize + JMP_INSTRUCTION_SIZE, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
      lpHook->dwMagicNumber = MAGIC_NUMBER;
      lpHook->lpOrigFunction = lpOrigFunction;
      lpHook->lpHookFunction = lpHookFunction;
      lpHook->dwPreambleSize = dwSize;

      // Save the first few instructions of the original function.
      lpCode = (LPBYTE)lpHook + sizeof(HOOK);
      memcpy(lpCode, lpOrigFunction, dwSize);

      // Store a JMP to the original function.
      WriteJMPInstruction((LPBYTE)&lpCode[dwSize], (LPBYTE)lpOrigFunction + dwSize);

      // Replace the first N bytes of original function with a JMP instruction.
      WriteJMPInstruction((LPBYTE)lpOrigFunction, (LPBYTE)lpHookFunction);

#if DEBUG
      printf("lpOrigFunction=%p\n", lpOrigFunction);
      printf("lpHookFunction=%p\n", lpHookFunction);
      printf("code(%08X)=", lpOrigFunction);
      for (int i = 0; i < dwSize; i++)
      {
        printf("%02X ", *((LPBYTE)lpOrigFunction + i));
      }
      printf("\n");
#endif

      // Restore the protection on the function being hooked.
      VirtualProtect(lpOrigFunction, dwSize, dwOldProtect, &dwOldProtect);
    }
  }

  return (LPVOID)((LPBYTE)lpHook + sizeof(HOOK));
}

////////////////////////////////////////////////////////////////////////
//
// NWHookDelete
//
// Unhooks a function.
//
VOID NWHookDelete(LPVOID lpVoid)
{
  LPBYTE lpOrigCode = (LPBYTE)lpVoid;
  LPHOOK lpHook = (LPHOOK)(lpOrigCode ? lpOrigCode - sizeof(HOOK) : NULL);
  DWORD dwOldProtect;

  if ((lpHook == NULL) || (lpHook->dwMagicNumber != MAGIC_NUMBER)) return;

  // Change the protection on the function being hooked.
  if (VirtualProtect(lpHook->lpOrigFunction, lpHook->dwPreambleSize, PAGE_READWRITE, &dwOldProtect))
  {
    // Restore the first few instructions of the original function.
    memcpy(lpHook->lpOrigFunction, lpOrigCode, lpHook->dwPreambleSize);

    // Restore the protection on the function being hooked.
    VirtualProtect(lpHook->lpOrigFunction, lpHook->dwPreambleSize, dwOldProtect, &dwOldProtect);
  }

  // Release the hook data structure.
  VirtualFree(lpHook, 0, MEM_RELEASE);
}

static VOID WriteJMPInstruction(LPBYTE lpSource, LPBYTE lpTarget)
{
#ifdef _AMD64_
  // Replace the first N bytes of source function with a JMP instruction to the target.

#if 1
  // This one requires 12 bytes.
  //
  //   mov rax,lpTarget
  lpSource[0] = 0x48;
  lpSource[1] = 0xB8;
  *(QWORD *)&lpSource[2] = (QWORD)lpTarget;
  //   jmp rax
  lpSource[10] = 0xFF;
  lpSource[11] = 0xE0;
#endif

#if 0
  // This one requires 10 bytes (but doesn't always work).
  //
  //   push lpHookFunction
  lpSource[0] = 0x68;
  *(QWORD *)&lpSource[1] = (QWORD)lpTarget;
  //   ret
  lpSource[9] = 0xC3;
#endif

#if 0
  // This one requires 14 bytes (but doesn't always work).
  //
  //   push lodword(lpTarget) ;this pushes 64 bits
  lpSource[0] = 0x68;
  *(DWORD *)&lpSource[1] = (DWORD)lpTarget;
  //   mov  dword ptr [rsp + 4h],hidword(lpTarget)
  lpSource[5] = 0xC7;
  lpSource[6] = 0x44;
  lpSource[7] = 0x24;
  lpSource[8] = 0x04;
  *(DWORD *)&lpSource[9] = (DWORD)((QWORD)lpTarget >> 32) & 0xFFFFFFFF;
  //   ret
  lpSource[13] = 0xC3;
#endif

#if 0
  // This one requires 21 bytes (but doesn't always work).
  //
  //
  lpSource[0] = 0x48; // sub rsp,8
  lpSource[1] = 0x83;
  lpSource[2] = 0xEC;
  lpSource[3] = 0x08;
  //lpSource[4] = 0xFF; // push rax
  //lpSource[5] = 0xF0;
  lpSource[4] = 0xC7; // mov dword ptr [rsp + 0h],lodword(lpTarget)
  lpSource[5] = 0x44;
  lpSource[6] = 0x24;
  lpSource[7] = 0x00;
  *(DWORD *)&lpSource[8] = (DWORD)((QWORD)lpTarget >> 0) & 0xFFFFFFFF;
  lpSource[12] = 0xC7; // mov dword ptr [rsp + 4h],hidword(lpTarget)
  lpSource[13] = 0x44;
  lpSource[14] = 0x24;
  lpSource[15] = 0x04;
  *(DWORD *)&lpSource[16] = (DWORD)((QWORD)lpTarget >> 32) & 0xFFFFFFFF;
  //lpSource[20] = 0x58; // pop rax
  lpSource[20] = 0xC3; // ret
#endif

#else
  // Replace the first 5 bytes of source function with a JMP instruction to the target.
  lpSource[0] = 0xE9;
  *(DWORD *)&lpSource[1] = (DWORD)lpTarget - (DWORD)lpSource - JMP_INSTRUCTION_SIZE;
#endif
}


////////////////////////////////////////////////////////////////////////
//
// PreambleSize
//
// Determines the size of the preamble of a function.
//
static DWORD PreambleSize(LPBYTE lpCode)
{
#ifdef _AMD64_
  return JMP_INSTRUCTION_SIZE;
#endif
  DWORD dwSize = 0;
  while (dwSize < JMP_INSTRUCTION_SIZE)
  {
    dwSize += InstructionSize(&lpCode[dwSize]);
  }
  return dwSize;
}





////////////////////////////////////////////////////////////////////////
//
// 80x86 Instruction Parser
//
#define LOCK_PREFIX        0xf0
#define REPNE_PREFIX       0xf2
#define REPE_PREFIX        0xf3

#define CS_PREFIX          0x2e
#define SS_PREFIX          0x36
#define DS_PREFIX          0x3e
#define ES_PREFIX          0x26
#define FS_PREFIX          0x64
#define GS_PREFIX          0x65

#define OPERAND_PREFIX     0x66
#define ADDRESS_PREFIX     0x67

#ifdef _AMD64_
#define REX_PREFIX_LO      0x40
#define REX_PREFIX_HI      0x4f

#define REX_W_BIT          0x8
#define REX_R_BIT          0x4
#define REX_X_BIT          0x2
#define REX_B_BIT          0x1
#endif

static BYTE OpCodeTable[] = {
/*        0   1   2   3   4   5   6   7   8   9   A   B   C   D   E   F   */
/* -----------------------------------------------------------------------*/
/*00*/    5,  5,  5,  5,  1,  3,  0,  0,  5,  5,  5,  5,  1,  3,  0, -1,    
/*10*/    5,  5,  5,  5,  1,  3,  0,  0,  5,  5,  5,  5,  1,  3,  0,  0,    
/*20*/    5,  5,  5,  5,  1,  3, 99,  0,  5,  5,  5,  5,  1,  3, 99,  0,    
/*30*/    5,  5,  5,  5,  1,  3, 99,  0,  5,  5,  5,  5,  1,  3, 99,  0,    
/*40*/    0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,    
/*50*/    0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,    
/*60*/    0,  0,  5,  5, 99, 99, 99, 99,  3,  8,  1,  6,  0,  0,  0,  0,    
/*70*/    1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,    
/*80*/    6,  8,  6,  6,  5,  5,  5,  5,  5,  5,  5,  5,  5,  5,  5,  5,    
/*90*/    0,  0,  0,  0,  0,  0,  0,  0,  0,  0, 10,  0,  0,  0,  0,  0,    
/*A0*/    9,  9,  9,  9,  0,  0,  0,  0,  1,  3,  0,  0,  0,  0,  0,  0,    
/*B0*/    1,  1,  1,  1,  1,  1,  1,  1,  3,  3,  3,  3,  3,  3,  3,  3,    
/*C0*/    6,  6,  2,  0,  5,  5,  6,  8,  4,  0,  2,  0,  0,  1,  0,  0,    
/*D0*/    5,  5,  5,  5,  1,  1, -1,  0,  0,  0,  0,  0,  0,  0,  0,  0,    
/*E0*/    1,  1,  1,  1,  1,  1,  1,  1,  3,  3, 10,  1,  0,  0,  0,  0,    
/*F0*/   99,  0, 99, 99,  0,  0,  5,  5,  0,  0,  0,  0,  0,  0,  5,  5
};

static DWORD Address16Table[] = {
/*        0   1   2   3   4   5   6   7   */
/*----------------------------------------*/
/*00*/    0,  0,  0,  0,  0,  0,  2,  0,
/*01*/    1,  1,  1,  1,  1,  1,  1,  1,
/*10*/    2,  2,  2,  2,  2,  2,  2,  2,
/*11*/    0,  0,  0,  0,  0,  0,  0,  0
};

static DWORD Address32Table[] = {
/*        0   1   2   3   4   5   6   7   */
/*----------------------------------------*/
/*00*/    0,  0,  0,  0,  1,  4,  0,  0,
/*01*/    1,  1,  1,  1,  2,  1,  1,  1,
/*10*/    4,  4,  4,  4,  5,  4,  4,  4,
/*11*/    0,  0,  0,  0,  0,  0,  0,  0
};

static DWORD Address64Table[] = {
/*        0   1   2   3   4   5   6   7   */
/*----------------------------------------*/
/*00*/    0,  0,  0,  0,  1,  8,  0,  0,
/*01*/    1,  1,  1,  1,  4,  1,  1,  1,
/*10*/    8,  8,  8,  8,  9,  8,  8,  8,
/*11*/    0,  0,  0,  0,  0,  0,  0,  0
};

static void ParseModRM(BYTE Byte, LPBYTE pMod, LPBYTE pRegOpcode, LPBYTE pRM)
{
  *pMod = Byte >> 6;
  *pRegOpcode = (Byte & 0x38) >> 3;
  *pRM = Byte & 0x07;
#if DEBUG
  printf("ModRM=(MOD=%x, RM=%x)\n", *pMod, *pRM);
#endif
}

static DWORD OperandSize(LPBYTE pCode, BOOL fAddressSizeOverride)
{
  BYTE Mod, RegOpcode, RM;
  ParseModRM(*pCode, &Mod, &RegOpcode, &RM);
  int iIndex = (Mod * 8) + RM;
#ifdef _AMD64_
  return (fAddressSizeOverride ? Address32Table[iIndex] : Address64Table[iIndex]) + 1;
#else
  return (fAddressSizeOverride ? Address16Table[iIndex] : Address32Table[iIndex]) + 1;
#endif
}

static DWORD InstructionSize(LPBYTE pCode)
{
  LPBYTE p = pCode;
  BOOL fEndOfInstruction = FALSE;
  BOOL fAddressSizeOverride = FALSE;
  BOOL fOperandSizeOverride = FALSE;
  int iOperandSize;
  BYTE REX = 0;

#if DEBUG
  printf("code(%08X)=", p);
  for (int i = 0; i < 16; i++)
  {
    printf("%02X ", p[i]);
  }
  printf("\n");
#endif

  while (!fEndOfInstruction)
  {
    // Check for lock and repeat prefixes.
    if ((*p == LOCK_PREFIX)  || 
        (*p == REPNE_PREFIX) || 
        (*p == REPE_PREFIX))
    {
      p++; continue;
    }

    // Check for segment override prefixes.
    if ((*p == CS_PREFIX) || 
        (*p == SS_PREFIX) ||
        (*p == DS_PREFIX) ||
        (*p == ES_PREFIX) ||
        (*p == FS_PREFIX) ||
        (*p == GS_PREFIX))
    {
      p++; continue;
    }

    // Check for operand-size override prefix.
    if (*p == OPERAND_PREFIX)
    {
      fOperandSizeOverride = TRUE; p++; continue;
    }

    // Check for address-size override prefix.
    if (*p == ADDRESS_PREFIX)
    {
      fAddressSizeOverride = TRUE; p++; continue;
    }

#ifdef _AMD64_
    // Check for REX prefix.
    if ((*p >= REX_PREFIX_LO) && (*p <= REX_PREFIX_HI))
    {
      REX = *p++; continue;
    }
    if (fOperandSizeOverride)
    {
      iOperandSize = (REX & REX_W_BIT) ? 4 : 2;
    }
    else
    {
      iOperandSize = (REX & REX_W_BIT) ? 8 : 4;
    }
#else
    iOperandSize = fOperandSizeOverride ? 2 : 4;
#endif

    // Check the opcode.
    switch (OpCodeTable[*p++])
    {
      case 0:   // no operands
        break;
      case 1:   // Ib (byte immediate data)
        p += 1;
        break;
      case 2:   // Iw (word immediate data)
        p += 2;
        break;
      case 3:   // Iv (word/dword immediate data)
        p += iOperandSize;
        break;
      case 4:   // Iw,Ib (word + byte immediate data)
        p += 3;
        break;
      case 5:   // Ex,Gx,Mx (ModR/M byte)
        p += OperandSize(p,fAddressSizeOverride);
        break;
      case 6:   // Ex,Gx,Mx + Ib (ModR/M byte + byte immediate data)
        p += OperandSize(p,fAddressSizeOverride) + 1;
        break;
      case 7:   // Ex,Gx,Mx + Iw (ModR/M byte + word immediate data)
        p += OperandSize(p,fAddressSizeOverride) + 2;
        break;
      case 8:   // Ex,Gx,Mx + Iv (ModR/M byte + word/dword immediate data)
        p += OperandSize(p,fAddressSizeOverride) + iOperandSize;
        break;
      case 9:   // Ox (word/dword offset)
        p += (fAddressSizeOverride ? 2 : 4);
        break;
      case 10:  // Ap (32-bit/48-bit pointer)
        p += (fAddressSizeOverride ? 4 : 6);
        break;
      default:  // ignore all others
        break;
    }
    fEndOfInstruction = TRUE;
  }

#if DEBUG
  printf("size=%d\n", p - pCode);
#endif

  return p - pCode;
}
