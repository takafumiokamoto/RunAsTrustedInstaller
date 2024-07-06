#include <windows.h>
#include <string>
#include <comdef.h>
#include <tchar.h>
#include <TlHelp32.h>

/*
* 現在のプロセスにSeDebugPrivilegeを付与する。
* プロセスが管理者権限で実行されていない場合は権限の付与or確認ができないため失敗する。
* 処理が失敗した場合はgetLastError()でエラー内容が取得できる。
*
*/
DWORD SetDebugPrivilege() {
	HANDLE currentProcess = GetCurrentProcess();
	HANDLE accessToken;
	if (!OpenProcessToken(currentProcess, TOKEN_ADJUST_PRIVILEGES, &accessToken)) {
		printf("ユーザーにTOKEN_ADJUST_PRIVILEGESが付与されていません。管理者権限で実行してください。");
		return false;
	}
	LUID luid;
	// https://learn.microsoft.com/ja-jp/windows/win32/api/winbase/nf-winbase-lookupprivilegevaluew
	// SeDebugPrivilegeのLUIDを取得
	if (!LookupPrivilegeValueW(NULL, SE_DEBUG_NAME, &luid)) {
		// LUIDの取得に失敗
		return false;
	}
	//https://learn.microsoft.com/ja-jp/windows/win32/api/securitybaseapi/nf-securitybaseapi-adjusttokenprivileges
	TOKEN_PRIVILEGES tp;
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	if (!AdjustTokenPrivileges(accessToken, FALSE, &tp, NULL, (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL)) {
		return false;
	}
}


void PrintError(const char* msg, DWORD err) {
	if (err == -1) {
		printf(" [-] %s.", msg);
		return;
	}
	wchar_t* msgBuf = nullptr;
	FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, err, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (wchar_t*)&msgBuf, 0, NULL);
	_bstr_t b(msgBuf); const char* c = b;
	printf("[-] %s. err: %d %s", msg, err, c);
	LocalFree(msgBuf);
}

DWORD GetPidByName(const wchar_t* processName) {
	DWORD processId = 0;
	// 現在のプロセス全体のスナップショットを作成
	HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap != INVALID_HANDLE_VALUE) {
		PROCESSENTRY32 pe32;
		pe32.dwSize = sizeof(PROCESSENTRY32);
		if (Process32First(hProcessSnap, &pe32)) {
			do {
				// exeファイル名が引数のプロセス名を一致するかどうか
				if (_tcscmp(pe32.szExeFile, processName) == 0) {
					processId = pe32.th32ProcessID;
					break;
				}
			} while (Process32Next(hProcessSnap, &pe32));
		}
	}
	CloseHandle(hProcessSnap);
	return processId;
}

HANDLE GetProcessToken(DWORD pid) {

}

HANDLE DuplicateProcessToken(DWORD pid, TOKEN_TYPE tokenType) {
	// プロセスIDからアクセストークンを取得
	HANDLE hToken = GetProcessToken(pid);
	if (hToken == INVALID_HANDLE_VALUE) {
		return INVALID_HANDLE_VALUE;
	}

	SECURITY_IMPERSONATION_LEVEL seImpersonateLevel = SecurityImpersonation;
	HANDLE hNewToken = {};
	// duplicate the token
	if (!DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, NULL, seImpersonateLevel, tokenType, &hNewToken)) {
		PrintError("DuplicateTokenEx()", GetLastError());
		CloseHandle(hToken);
		return INVALID_HANDLE_VALUE;
	}
	CloseHandle(hToken);
	return hNewToken;
}

int wmain() {
	bool success = SetDebugPrivilege();
	if (!success) {
		PrintError("SetDebugPrivilege", GetLastError());
	}
	DWORD pid = GetPidByName(L"winlogon.exe");
	if (pid == 0) return -1;
	HANDLE hImpToken = DuplicateProcessToken(pid, TOKEN_TYPE::TokenImpersonation);
}