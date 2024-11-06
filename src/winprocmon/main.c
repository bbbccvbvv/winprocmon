#ifdef _WINDOWS
#define _CRTDBG_MAP_ALLOC
#include <crtdbg.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <ctype.h>
#include <stdbool.h>
#include <io.h>
#include <string.h>

#include <windows.h>
#include <psapi.h>
#include <time.h>
#include <TlHelp32.h>
#include <wbemidl.h>

#define WINPROCMON_ERROR_INVALID_COMMAND "invalid command"
#define WINPROCMON_ERROR_INVALID_FILE_PATH "invalid file path"
#define WINPROCMON_ERROR_INVALID_PID "invalid process id"
#define WINPROCMON_ERROR_INVALID_TIME "invalid time"
#define WINPROCMON_ERROR_INVALID_TOP_NUMBER "invalid top number"
#define WINPROCMON_ERROR_OPEN_FILE "fail to open file"
#define WINPROCMON_ERROR_CONFLICT_SINGLE_COMMAND "command cannot be used mixedly"
#define WINPROCMON_ERROR_CONFLICT_PID_AND_TOP_NUMBER "pid conflict with top number"

struct STRUCTPROCESSMSG {

    PROCESS_MEMORY_COUNTERS s_pmc;
    PROCESSENTRY32 s_pe;
};

struct STRUCTPROCESSMSG g_process_list[1000];
unsigned long g_pid, g_time, g_top_number;
char* g_file;
FILE* g_file_ptr;

int CompareByWorkingSet(const void* lh, const void* rh) {
    struct STRUCTPROCESSMSG lh_t = *(struct STRUCTPROCESSMSG*)lh;
    struct STRUCTPROCESSMSG rh_t = *(struct STRUCTPROCESSMSG*)rh;
    return rh_t.s_pmc.WorkingSetSize - lh_t.s_pmc.WorkingSetSize;
}

int EnumAllProcess(int in_pid) {
    // get snap of all process
    HANDLE hSnapshort = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshort == INVALID_HANDLE_VALUE)
    {
        printf("Call CreateToolhelp32Snapshot fail!\n");
        return 0;
    }

    // get thread list and get thread msg by Thread32First and Thread32Next from snap
    PROCESSENTRY32 stcProcessInfo;
    stcProcessInfo.dwSize = sizeof(stcProcessInfo);

    BOOL  bRet = Process32First(hSnapshort, &stcProcessInfo);
    int l_process_cnt = 0;

    while (bRet)
    {
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION |
            PROCESS_VM_READ,
            FALSE, stcProcessInfo.th32ProcessID);
        if (NULL != hProcess) {
            if (GetProcessMemoryInfo(hProcess, &(g_process_list[l_process_cnt].s_pmc), sizeof(g_process_list[l_process_cnt].s_pmc)))
            {
                g_process_list[l_process_cnt].s_pe = stcProcessInfo;
                if (stcProcessInfo.th32ProcessID == in_pid) {
                    g_process_list[0] = g_process_list[l_process_cnt];
                    if (NULL != hProcess) {
                        CloseHandle(hProcess);
                    }
                    return 1;
                }
                ++l_process_cnt;
            }
        }

        if (NULL != hProcess) {
            CloseHandle(hProcess);
        }
        bRet = Process32Next(hSnapshort, &stcProcessInfo);
    }
    CloseHandle(hSnapshort);
    return l_process_cnt;
}

void PrintVersionMsg() {
    printf("WinProcMon v1.00 - Windows Process Monitor\n");
    printf("Copyright (C) 2024 YangWeining\n");
    printf("\n");
}

void PrintHelpMsg() {
    /*printf("Process ID: %u\n", CoGetCurrentProcess());
    printf("\n");*/
    printf("usage: winprocmon [no argument] || [-h||--help||-v||--version] || [-f||--file file_path][-n||--number top_process_number][-t||--time time_seconds][-p||--pid specified_process_id]\n");
    printf("no argument    Print top 10 process's working set and pagefile order by working set per 10 seconds.\n");
    printf("-f, --file     Save process memory info to specified file.\n");
    printf("-h, --help     Get help for commamds.\n");
    printf("-n, --number   Number of top process need saving.\n");
    printf("-p, --pid      Pid of specified process need saving.\n");
    printf("-t, --time     Time(seconds) between two check.\n");
    printf("-v, --version  Show version number and quit.\n");
    printf("\n");
}

void HandleInvalidCommand(char *in_str, char *in_cmd) {
    printf("%s: %s\n", in_str, in_cmd);
    PrintHelpMsg();
}

void PrintCurrentTime() {
    time_t l_time;
    char l_time_char[26];
    time(&l_time);
    ctime_s(l_time_char, 26, &l_time);
    printf("Time:%s", l_time_char);
    if (g_file_ptr) {
        fprintf(g_file_ptr, "Time:%s", l_time_char);
    }
}

void PrintProcessMemoryMonitorMsg() {
    PrintCurrentTime();
}

void PromotePrivileges1() {
    HANDLE hToken;
    LUID DebugNameValue;
    TOKEN_PRIVILEGES Privileges;
    DWORD dwRet;

    if(!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        printf("PromotePrivileges1:OpenProcessToken error code:%d\n", GetLastError());
    }
    LookupPrivilegeValue(NULL, "SeDebugPrivilege", &DebugNameValue);
    Privileges.PrivilegeCount = 1;
    Privileges.Privileges[0].Luid = DebugNameValue;
    Privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!AdjustTokenPrivileges(hToken, FALSE, &Privileges, sizeof(Privileges), NULL, &dwRet)) {
        printf("PromotePrivileges1:AdjustTokenPrivileges error code:%d\n", GetLastError());
    }
    CloseHandle(hToken);
}


int PromotePrivileges() {
    // Get the Token 
    HANDLE hToken = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        return -1;
    }

    DWORD dwLen;
    bool bRes;

    // obtain dwLen
    bRes = GetTokenInformation(
        hToken,
        TokenPrivileges,
        NULL,
        0,
        &dwLen
    );

    BYTE *pBuffer = malloc(dwLen * sizeof(BYTE));
    if (NULL == pBuffer)
    {
        CloseHandle(hToken);
        return WBEM_E_OUT_OF_MEMORY;
    }

    bRes = GetTokenInformation(
        hToken,
        TokenPrivileges,
        pBuffer,
        dwLen,
        &dwLen
    );

    if (!bRes)
    {
        CloseHandle(hToken);
        free(pBuffer);
        pBuffer = NULL;
        return WBEM_E_ACCESS_DENIED;
    }

    // Iterate through all the privileges and enable them all
    // ====================================================== 
    TOKEN_PRIVILEGES* pPrivs = (TOKEN_PRIVILEGES*)pBuffer;
    for (DWORD i = 0; i < pPrivs->PrivilegeCount; i++)
    {
        pPrivs->Privileges[i].Attributes |= SE_PRIVILEGE_ENABLED;
    }
    // Store the information back in the token
    // ========================================= 
    bRes = AdjustTokenPrivileges(
        hToken,
        FALSE,
        pPrivs,
        0, NULL, NULL
    );

    free(pBuffer);
    pBuffer = NULL;
    CloseHandle(hToken);

    if (!bRes)
        return WBEM_E_ACCESS_DENIED;
    else
        return WBEM_S_NO_ERROR;
}

void StrToLower(const char* in_str, char* out_str, int length) {
    for (int i = 0; i < length; ++i) {
        out_str[i] = tolower(in_str[i]);
    }
    out_str[length] = '\0';
}

bool StringToUlong(const char* str_in, unsigned long* int_out) {
    int length = strlen(str_in);
    *int_out = 0;
    for (int i = 0; i < length; ++i) {
        if (!isdigit(str_in[i])) {
            return false;
        }
        (*int_out) = (*int_out) * 10 + str_in[i] - '0';
    }
    return true;
}

bool FilePathIsValid(char* path_in) {
    FILE* l_file = fopen(path_in, "a+");
    if (NULL == l_file) {
        printf("open file fail, error code:%d\n", GetLastError());
        return false;
    }
    fclose(l_file);
    return true;
}

void ProcessMonitor() {
    if (g_file && (NULL == g_file_ptr)) {
        fopen_s(&g_file_ptr, g_file, "a+");
        if (NULL == g_file_ptr) {
            HandleInvalidCommand(WINPROCMON_ERROR_OPEN_FILE, g_file);
            return;
        }
    }
    while (true) {
        int process_cnt = EnumAllProcess(g_pid);
        qsort(g_process_list, process_cnt, sizeof(g_process_list[0]), CompareByWorkingSet);
        PrintCurrentTime();
        printf("           PID        WorkingSet          PageFile    ProcessName\n");
        if (g_file_ptr) {
            fprintf(g_file_ptr, "           PID        WorkingSet          PageFile    ProcessName\n");
        }
        process_cnt = min(process_cnt, g_top_number);
        for (unsigned long i = 0; i < process_cnt; ++i) {
            printf("%14lu    %14lu    %14lu    %ls\n", g_process_list[i].s_pe.th32ProcessID, g_process_list[i].s_pmc.WorkingSetSize, g_process_list[i].s_pmc.PagefileUsage, g_process_list[i].s_pe.szExeFile);
            if (g_file_ptr) {
                fprintf(g_file_ptr, "%14lu    %14lu    %14lu    %ls\n", g_process_list[i].s_pe.th32ProcessID, g_process_list[i].s_pmc.WorkingSetSize, g_process_list[i].s_pmc.PagefileUsage, g_process_list[i].s_pe.szExeFile);
            }
        }
        printf("\n");
        Sleep(g_time * 1000);
    };

}

void InitGlobalVariable() {
    g_file = NULL;
    g_pid = -1;
    g_time = 10;
    g_top_number = 10;
    g_file_ptr = NULL;
}

void MainLoop(int argc, char* argv[]) {
    InitGlobalVariable();
    if (argc == 2) {
        int length = strlen(argv[1]);
        char* out_str = malloc((length + 1) * sizeof(char));
        StrToLower(argv[1], out_str, length);
        if (!strcmp(out_str, "-v") || !strcmp(out_str, "--version")) {
            PrintVersionMsg();
        }
        else {
            if (!strcmp(out_str, "-h") || !strcmp(out_str, "--help")) {
                PrintHelpMsg();
            }
            else {
                HandleInvalidCommand(WINPROCMON_ERROR_INVALID_COMMAND, argv[1]);
            }
        }
        free(out_str);
    }
    else if (argc % 2) {
        bool l_cmd_error = false, l_pid_enable = false, l_top_number_enable = false;
        for (int i = 1; i < argc; i += 2) {
            int length = strlen(argv[i]);
            char* out_str = malloc((length + 1) * sizeof(char));
            char* l_error_msg = NULL, * l_error_cmd = NULL;
            StrToLower(argv[i], out_str, length);
            if (!strcmp(out_str, "-p") || !strcmp(out_str, "--pid")) {
                if (l_top_number_enable) {
                    l_cmd_error = true;
                    l_error_msg = WINPROCMON_ERROR_CONFLICT_PID_AND_TOP_NUMBER;
                    l_error_cmd = argv[i];
                } else {
                    unsigned long l_pid = 0;
                    if (StringToUlong(argv[i + 1], &l_pid)) {
                        g_pid = l_pid;
                        l_pid_enable = true;
                    }
                    else {
                        l_cmd_error = true;
                        l_error_msg = WINPROCMON_ERROR_INVALID_PID;
                        l_error_cmd = argv[i + 1];
                    }
                }
            }
            else if (!strcmp(out_str, "-f") || !strcmp(out_str, "--file")) {
                if (FilePathIsValid(argv[i + 1])) {
                    g_file = argv[i + 1];
                } else {
                    l_cmd_error = true;
                    l_error_msg = WINPROCMON_ERROR_INVALID_FILE_PATH;
                    l_error_cmd = argv[i + 1];
                }
            }
            else if (!strcmp(out_str, "-t") || !strcmp(out_str, "--time")) {
                unsigned long l_time = 0;
                if (StringToUlong(argv[i + 1], &l_time)) {
                    g_time = l_time;
                }
                else {
                    l_cmd_error = true;
                    l_error_msg = WINPROCMON_ERROR_INVALID_TIME;
                    l_error_cmd = argv[i + 1];
                }
            }
            else if (!strcmp(out_str, "-n") || !strcmp(out_str, "--number")) {
                if (l_pid_enable) {
                    l_cmd_error = true;
                    l_error_msg = WINPROCMON_ERROR_CONFLICT_PID_AND_TOP_NUMBER;
                    l_error_cmd = argv[i];
                } else {
                    unsigned long l_number = 0;
                    if (StringToUlong(argv[i + 1], &l_number)) {
                        g_top_number = l_number;
                        l_top_number_enable = true;
                    }
                    else {
                        l_cmd_error = true;
                        l_error_msg = WINPROCMON_ERROR_INVALID_TOP_NUMBER;
                        l_error_cmd = argv[i + 1];
                    }
                }
            }
            else {
                if (!strcmp(out_str, "-h") || !strcmp(out_str, "--help") || !strcmp(out_str, "-v") || !strcmp(out_str, "--version")) {
                    l_cmd_error = true;
                    l_error_msg = WINPROCMON_ERROR_CONFLICT_SINGLE_COMMAND;
                    l_error_cmd = argv[i];
                } else {
                    l_cmd_error = true;
                    l_error_msg = WINPROCMON_ERROR_INVALID_COMMAND;
                    l_error_cmd = argv[i];
                }
            }
            free(out_str);
            if (l_cmd_error) {
                HandleInvalidCommand(l_error_msg, l_error_cmd);
                return;
            }
        }
        ProcessMonitor();
    }
}

int main(int argc, char* argv[]) {
    #ifdef _WINDOWS
        _CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF;
    #endif
    PromotePrivileges1();
    MainLoop(argc, argv);
    if (g_file_ptr) {
        fclose(g_file_ptr);
    }
    return 0;
}