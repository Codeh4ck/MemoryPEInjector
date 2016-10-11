#pragma once
class Injector
{
public:
	Injector();
	~Injector();
	
	unsigned char *ReadFileBytes(const TCHAR *name)	
	void Inject(LPBYTE lpBuffer) const;
private:
	long LoadFunction(const TCHAR *szLib, char *szMod) const;
	PROCESS_INFORMATION *CreateNewProcess(DWORD id, TCHAR *szArgs, STARTUPINFO *si, PROCESS_INFORMATION *pi) const;
};

