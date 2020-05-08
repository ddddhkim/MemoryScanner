#pragma once
#include <Psapi.h>
#include <tlhelp32.h>



class PatternScanner {
public:

	typedef struct ptrNode {
		DWORD pid;
		LPVOID ptr;
		ptrNode* next;
	}pNode;


	PatternScanner(const wchar_t* ProcessName) {
		PROCESSENTRY32 proc;
		proc.dwSize = sizeof(PROCESSENTRY32);

		// Only Child Process id 
		/*
		DWORD expid = 0;
		GetWindowThreadProcessId(GetShellWindow(), &expid);
		*/


		HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		Process32First(snapshot, &proc);

		DWORD idx = 0;
		while (TRUE == Process32Next(snapshot, &proc)) {
			// Only Child Procee id
			//if (wcscmp(proc.szExeFile, ProcessName) == 0 && (proc.th32ParentProcessID != expid) && idx < 2)
			if (wcscmp(proc.szExeFile, ProcessName) == 0 && idx < 2)
				pid[idx++] = (DWORD)proc.th32ProcessID;
		}
	}


	pNode* GetLinkedList() {
		pNode* temp = (pNode*)malloc(sizeof(pNode));
		memset(temp, 0, sizeof(pNode));

		return temp;
	}

	
	void __fastcall FindPattern(pNode* link, BYTE* Pattern, const char* mask) {
		
		for (DWORD pidx = 0;  pidx < 2 && pid[pidx] != 0; pidx++) {

			MEMORY_BASIC_INFORMATION meminfo;
			HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid[pidx]);
			//printf("pid : %d\n", pid[pidx]);

			SYSTEM_INFO si;
			GetSystemInfo(&si);

			unsigned char* addr = 0;

			if (hProc) {
				while (addr < (unsigned char*)si.lpMaximumApplicationAddress) {

					if (VirtualQueryEx(hProc, addr, &meminfo, sizeof(meminfo)) == 0) {
						//printf("%s %s\n", "VirtualQueryEx Error: ", GetLastError());
						break;
					}

					//if ((meminfo.State == MEM_COMMIT) && ((meminfo.Protect & PAGE_GUARD) == 0) && ((meminfo.Protect == PAGE_NOACCESS) == 0)) {
					if (meminfo.State == MEM_COMMIT) {
						SIZE_T bytes_read;
						void* tempbuf = malloc(meminfo.RegionSize);

						ReadProcessMemory(hProc, meminfo.BaseAddress, tempbuf, meminfo.RegionSize, &bytes_read);

						if (bytes_read == meminfo.RegionSize) {
							for (DWORD64 idx = 0; idx < (meminfo.RegionSize - strlen(mask)); idx++) {
								for (int i = 0; i < strlen(mask); i++, idx++) {
									if (mask[i] != '?' && memcmp(((BYTE*)tempbuf + idx), &Pattern[i], 1) != 0) {
										idx -= i;
										break;
									}

									if (i == (strlen(mask) - 1) && ((memcmp(((BYTE*)tempbuf + idx), &Pattern[i], 1) == 0) || mask[i] == '?')) {
										link->pid = pid[pidx];
										link->ptr = (LPVOID)(((DWORD64)meminfo.BaseAddress) + idx - (strlen(mask) - 1));
										link->next = GetLinkedList();
										link = link->next;
									}
								}
							}
						}
					}
					addr = (unsigned char*)meminfo.BaseAddress + meminfo.RegionSize;
				}
			}

			CloseHandle(hProc);
		}
	}

	int __fastcall PatchPlace(DWORD pid, LPVOID Place, BYTE* PatchArray, size_t PatchSize) {
		HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
		
		if (hProc) {
			SIZE_T WriteByte;
			WriteProcessMemory(hProc, Place, PatchArray, PatchSize, &WriteByte);

			if (PatchSize == WriteByte)
				return 0;
		}


		return -1;
	}


private:
	DWORD protection = NULL;
	DWORD pid[2] = { 0, 0 }; // child process
};