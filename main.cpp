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
bool SetDebugPrivilege() {
	HANDLE currentProcess = GetCurrentProcess();
	HANDLE accessToken;
	if (!OpenProcessToken(currentProcess, TOKEN_ADJUST_PRIVILEGES, &accessToken)) {
		printf("please try again as administrator");
		return false;
	}
	LUID luid;
	// https://learn.microsoft.com/ja-jp/windows/win32/api/winbase/nf-winbase-lookupprivilegevaluew
	// SeDebugPrivilegeのLUIDを取得
	if (!LookupPrivilegeValueW(NULL, SE_DEBUG_NAME, &luid)) {
		printf("Faild to obtain LUID");
		// LUIDの取得に失敗
		return false;
	}
	//https://learn.microsoft.com/ja-jp/windows/win32/api/securitybaseapi/nf-securitybaseapi-adjusttokenprivileges
	TOKEN_PRIVILEGES tp;
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	if (!AdjustTokenPrivileges(accessToken, FALSE, &tp, NULL, (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL)) {
		printf("Faild to adjust token privileges");
		return false;
	}
}

/*
* GetLastError()の内容をコンソール出力する。
*/
void PrintLastError() {
	auto err = GetLastError();
	wchar_t* msgBuf = nullptr;
	FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, err, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (wchar_t*)&msgBuf, 0, NULL);
	_bstr_t b(msgBuf); const char* c = b;
	printf("[-] err: %d %s", err, c);
	LocalFree(msgBuf);
}

/*
* 実行ファイル名からpidを取得する。
*/
DWORD GetPidByName(const wchar_t* processName) {
	DWORD processId = 0;
	// 現在のプロセス全体のスナップショットを作成
	HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap != INVALID_HANDLE_VALUE) {
		PROCESSENTRY32 pe32;
		pe32.dwSize = sizeof(PROCESSENTRY32);
		if (Process32First(hProcessSnap, &pe32)) {
			do {
				// exeファイル名が引数のプロセス名と一致するかどうか
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

/*
* pidに対応するtokenハンドラーを取得する。
*/
HANDLE GetProcessToken(DWORD pid) {
	HANDLE hCurrentProcess;
	if (pid != 0) {
		// pidに対応するプロセスのハンドルを取得
		hCurrentProcess = OpenProcess(PROCESS_QUERY_INFORMATION, TRUE, pid);
		if (hCurrentProcess == NULL) {
			// 失敗した場合
			PrintLastError();
			return INVALID_HANDLE_VALUE;
		}
	}
	else {
		hCurrentProcess = GetCurrentProcess();
	}
	HANDLE hToken;
	//	https://learn.microsoft.com/ja-jp/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocesstoken#parameters
	bool success = OpenProcessToken(hCurrentProcess, TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY, &hToken);
	if (!success) {
		PrintLastError();
		return INVALID_HANDLE_VALUE;
	}
	CloseHandle(hCurrentProcess);
	return hToken;

}

/*
* pidに対応するアクセストークンを複製する。
*/
HANDLE DuplicateProcessToken(DWORD pid, TOKEN_TYPE tokenType) {
	// プロセスIDからアクセストークンを取得
	HANDLE hToken = GetProcessToken(pid);
	if (hToken == INVALID_HANDLE_VALUE) {
		return INVALID_HANDLE_VALUE;
	}
	//https://learn.microsoft.com/ja-jp/windows-hardware/drivers/ddi/wdm/ne-wdm-_security_impersonation_level
	SECURITY_IMPERSONATION_LEVEL seImpersonateLevel = SecurityImpersonation;
	HANDLE hNewToken = {};
	//https://learn.microsoft.com/ja-jp/windows/win32/api/securitybaseapi/nf-securitybaseapi-duplicatetokenex
	// アクセストークンの複製
	if (!DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, NULL, seImpersonateLevel, tokenType, &hNewToken)) {
		PrintLastError();
		CloseHandle(hToken);
		return INVALID_HANDLE_VALUE;
	}
	CloseHandle(hToken);
	return hNewToken;
}


/*
* pidをキーにプロセスを停止する。
*/
bool TerminateProcessByPid(const DWORD pid) {
	if (pid == 0) {
		return false;
	}
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (hProcess == INVALID_HANDLE_VALUE) {
		return false;
	}
	if (!TerminateProcess(hProcess, 1)) {
		PrintLastError();
		return false;
	}
	return true;
}

/*
* main.
* - Systemで起動しているwinlogon.exeからアクセストークンを偽装トークンとして作成
* - 複製した偽装トークンを現在のスレッドに割り当てる
* - Systemに昇格したので、TrustedInstaller Serviceを起動する。
* - 起動したTrustedInstaller Serviceからプライマリアクセストークンを複製
* - 複製したプライマリアクセストークン(TrustedInstaller権限)を付与してcmd.exeを起動
*/
int main() {
	const LPCWSTR targetExecutable = L"C:\\Windows\\System32\\cmd.exe";
	bool success = SetDebugPrivilege();
	if (!success) {
		// 管理者権限で実行されていない
		PrintLastError();
		return -1;
	}
	DWORD pid = GetPidByName(L"winlogon.exe");
	if (pid == 0) return -1;
	//winlogon.exeのキーにアクセストークンを取得し偽装トークンとして複製する。
	HANDLE hImpersonationToken = DuplicateProcessToken(pid, TOKEN_TYPE::TokenImpersonation);
	if (hImpersonationToken == INVALID_HANDLE_VALUE) {
		printf("Faild to duplicate access token for winlogon.exe");
		return -1;
	}
	// https://learn.microsoft.com/ja-jp/windows/win32/api/processthreadsapi/nf-processthreadsapi-getcurrentthread
	HANDLE hCurrentThread = GetCurrentThread();
	// 複製した偽装トークンを現在のスレッドに割り当てる。
	success = SetThreadToken(&hCurrentThread, hImpersonationToken);
	if (!success) {
		PrintLastError();
		return -1;
	}
	CloseHandle(hCurrentThread);
	CloseHandle(hImpersonationToken);
	//https://learn.microsoft.com/ja-jp/windows/win32/api/winsvc/nf-winsvc-openservicew
	//https://learn.microsoft.com/ja-jp/windows/win32/api/winsvc/nf-winsvc-openscmanagerw
	SC_HANDLE hTrustedInstallerService = OpenServiceW(OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS), L"trustedinstaller", MAXIMUM_ALLOWED);
	if (hTrustedInstallerService == NULL) {
		// trustedinstaller serviceのハンドルを取得できなかった。
		PrintLastError();
		return -1;
	}
	SERVICE_STATUS_PROCESS ssp = {};
	DWORD pcbBytesNeeded;
	//https://learn.microsoft.com/ja-jp/windows/win32/api/winsvc/nf-winsvc-queryservicestatusex
	if (!QueryServiceStatusEx(hTrustedInstallerService, SC_STATUS_PROCESS_INFO, (BYTE*)&ssp, sizeof(ssp), &pcbBytesNeeded)) {
		PrintLastError();
		return -1;
	}
	if (ssp.dwCurrentState != SERVICE_RUNNING) {
		// trustedinstaller serviceが動作していなければ、立ち上げる。
		if (!StartService(hTrustedInstallerService, 0, NULL)) {
			PrintLastError();
			return -1;
		}
		// pidの更新
		if (!QueryServiceStatusEx(hTrustedInstallerService, SC_STATUS_PROCESS_INFO, (BYTE*)&ssp, sizeof(ssp), &pcbBytesNeeded)) {
			PrintLastError();
			return -1;
		}
		// 起動しているか再度チェックすると毎回コケるのはなぜ？
		//if (ssp.dwCurrentState != SERVICE_RUNNING) {
		//	// 起動に失敗していればエラー
		//	printf("Faild to start TrustedInstaller service");
		//	return -1;
		//}
	}
	CloseServiceHandle(hTrustedInstallerService);
	HANDLE hTruestedInstallerToken = DuplicateProcessToken(ssp.dwProcessId, TOKEN_TYPE::TokenPrimary);
	if (hTruestedInstallerToken == INVALID_HANDLE_VALUE) {
		printf("Faild to duplicate access token for TrustedInstaller");
		return -1;
	}
	// TrustedInstaller.exeも一緒に停止する。
	if (!TerminateProcessByPid(ssp.dwProcessId)) {
		printf("Faild to terminate TrustedInstaller-service pid:%d", pid);
		return -1;
	}
	STARTUPINFO si = {};
	PROCESS_INFORMATION pi = {};
	//https://learn.microsoft.com/ja-jp/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw
	success = CreateProcessWithTokenW(hTruestedInstallerToken, LOGON_NETCREDENTIALS_ONLY, targetExecutable, NULL, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi);
	if (!success) {
		PrintLastError();
		return -1;
	}
	if (!CloseHandle(hTruestedInstallerToken)) {
		PrintLastError();
		return -1;
	}
	return 0;
}