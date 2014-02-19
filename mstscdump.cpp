/**
 * mstscdump: MSTSC Packet Dump Utility
 * MSTSC Launch and Hook Process
 *
 * Copyright 2014 Mike McDonald <mikem@nogginware.com>
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

#include <intrin.h>
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

BOOL EnableSecurityRights(LPTSTR DesiredAccess, BOOL bOn)
{
	HANDLE hToken; 
	TOKEN_PRIVILEGES tkp; 
					
	/* Get a token for this process. */ 
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) 
	{
		printf("EnableSecurityRights - OpenProcessToken failed (lastError=0x%08x)", GetLastError());
		return FALSE;
	}

	/* Get the LUID for the desired privilege. */ 
	if (!LookupPrivilegeValue(NULL, DesiredAccess, &tkp.Privileges[0].Luid))
	{
		printf("EnableSecurityRights - LookupPrivilegeValue failed (lastError=0x%08x)", GetLastError());
		CloseHandle(hToken);
		return FALSE;
	}
	tkp.PrivilegeCount = 1;  /* one privilege to set    */ 
	tkp.Privileges[0].Attributes = bOn ? SE_PRIVILEGE_ENABLED : 0; 
					
	/* Get the desired privilege for this process. */ 					
	if (!AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof tkp, NULL, NULL)) //(PTOKEN_PRIVILEGES)
	{
		printf("EnableSecurityRights - AdjustTokenPrivileges failed (lastError=0x%08x)", GetLastError());
		CloseHandle(hToken);
		return FALSE;
	}

	CloseHandle(hToken);

	return TRUE;
}

BOOL InjectDll(DWORD dwProcessId, LPCSTR pszDllName)
{
	BOOL bRetCode = FALSE;
	HMODULE hModKernel32 = NULL;
	LPVOID pLoadLibraryA = NULL;
	HANDLE hProcess = NULL;
	HANDLE hThread = NULL;
	LPVOID pszArgs = NULL;
	DWORD cbArgs;

	if (dwProcessId == 0) return FALSE;
	if (pszDllName == NULL) return FALSE;

	try
	{
		hModKernel32 = GetModuleHandle("KERNEL32.DLL");
		pLoadLibraryA = GetProcAddress(hModKernel32, "LoadLibraryA");

		EnableSecurityRights(SE_DEBUG_NAME, TRUE);
		EnableSecurityRights(SE_TCB_NAME, TRUE);

		// Open the remote process.
		hProcess = OpenProcess(
			PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE,
			FALSE,
			dwProcessId);
		if (hProcess == NULL)
		{
			printf("OpenProcess failed (LastError=%d)\n", GetLastError());
			throw 0;
		}

		// Allocate the arguments in the remote process.
		cbArgs = lstrlen(pszDllName) + 1;
		pszArgs = VirtualAllocEx(hProcess, NULL, cbArgs, MEM_COMMIT, PAGE_READWRITE);
		if (pszArgs == NULL)
		{
			printf("VirtualAllocEx failed (LastError=%d)\n", GetLastError());
			throw 0;
		}
		WriteProcessMemory(hProcess, pszArgs, pszDllName, cbArgs, NULL);

		// Create the remote thread.
		hThread = CreateRemoteThread(
			hProcess,
			NULL,
			0,
			(LPTHREAD_START_ROUTINE)pLoadLibraryA,
			pszArgs,
			0,
			NULL);
		if (hThread == NULL)
		{
			printf("CreateRemoteThread failed (LastError=%d)\n", GetLastError());
			throw 0;
		}

		WaitForSingleObject(hThread, INFINITE);

		bRetCode = TRUE;
	}
	catch (...) {}

	// Clean up everything.
	if (hThread)
	{
		CloseHandle(hThread);
	}

	if (pszArgs)
	{
		VirtualFreeEx(hProcess, pszArgs, 0, MEM_RELEASE);
	}

	if (hProcess)
	{
		CloseHandle(hProcess);
	}

	return bRetCode;
}

static BOOL IsFile(char *arg)
{
	FILE *fp = fopen(arg, "rb");
	if (fp == NULL) return FALSE;
	fclose(fp);
	
	return TRUE;
}

void main(int argc, char **argv)
{
	char szCommandLine[2048];
	STARTUPINFO StartupInfo;
	PROCESS_INFORMATION ProcessInfo;
	BOOL fSuccess;

	ZeroMemory(szCommandLine, sizeof(szCommandLine));
	if ((argc == 1) || (argv[1][0] == '/') || IsFile(argv[1]))
	{
		strcpy(szCommandLine, "mstsc.exe ");
	}
	for (int i = 1; i < argc; i++)
	{
		strcat(szCommandLine, argv[i]);
		strcat(szCommandLine, " ");
	}

	ZeroMemory(&StartupInfo, sizeof(StartupInfo));
	StartupInfo.cb = sizeof(StartupInfo);

	ZeroMemory(&ProcessInfo, sizeof(ProcessInfo));

	fSuccess = CreateProcess(
		NULL,
		szCommandLine,
		NULL,
		NULL,
		FALSE,
		CREATE_SUSPENDED,
		NULL,
		NULL,
		&StartupInfo,
		&ProcessInfo);
	if (!fSuccess)
	{
		printf("Could not start application (LastError=%d)\n", GetLastError());
		exit(1);
	}
	InjectDll(ProcessInfo.dwProcessId, "mstschook.dll");
	ResumeThread(ProcessInfo.hThread);
	WaitForSingleObject(ProcessInfo.hProcess, INFINITE);
	CloseHandle(ProcessInfo.hProcess);
	CloseHandle(ProcessInfo.hThread);
}
