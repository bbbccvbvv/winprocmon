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
#include <locale.h>

#include <windows.h>
#include <psapi.h>
#include <time.h>
#include <TlHelp32.h>
#include <wbemidl.h>

#define DEBUG_ENABLE true
#define DLV 1024

#define WINPROCMON_ERROR_INVALID_COMMAND "invalid command"
#define WINPROCMON_ERROR_INVALID_FILE_PATH "invalid file path"
#define WINPROCMON_ERROR_INVALID_PID "invalid process id"
#define WINPROCMON_ERROR_INVALID_TIME "invalid time"
#define WINPROCMON_ERROR_INVALID_TOP_NUMBER "invalid top number"
#define WINPROCMON_ERROR_OPEN_FILE "fail to open file"
#define WINPROCMON_ERROR_CONFLICT_SINGLE_COMMAND "command cannot be used mixedly"
#define WINPROCMON_ERROR_CONFLICT_PID_AND_TOP_NUMBER "pid conflict with top number"
#define WINPROCMON_ERROR_MONITOR_TARGET_PROCESS "fail to monitor specified process "

struct STRUCTPROCESSMSG {

    PROCESS_MEMORY_COUNTERS s_pmc;
    PROCESSENTRY32 s_pe;
};

struct STRUCTPROCESSMSG g_process_list[1000];
unsigned long g_pid, g_time, g_top_number;
char* g_file;
FILE* g_file_ptr;


void PrintSystemMemoryInfo();

void PrintDebugMsg(const char* msg_in, int errorcode_in) {
    if (DEBUG_ENABLE) {
        printf("%s %d\n", msg_in, errorcode_in);
    }
}

int CompareByWorkingSet(const void* lh, const void* rh) {
    struct STRUCTPROCESSMSG lh_t = *(struct STRUCTPROCESSMSG*)lh;
    struct STRUCTPROCESSMSG rh_t = *(struct STRUCTPROCESSMSG*)rh;
    return rh_t.s_pmc.WorkingSetSize - lh_t.s_pmc.WorkingSetSize;
}

int EnumAllProcess(int in_pid) {
    bool l_target_process = false;
    if (in_pid > -1) {
        l_target_process = true;
    }
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
        //PROCESS_SUSPEND_RESUME | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SET_LIMITED_INFORMATION
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, stcProcessInfo.th32ProcessID);
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
        } else {
                //printf("pid:%d,error code:%d, name:%ls\n", stcProcessInfo.th32ProcessID,  GetLastError(), stcProcessInfo.szExeFile);
            }

        if (NULL != hProcess) {
            CloseHandle(hProcess);
        }
        bRet = Process32Next(hSnapshort, &stcProcessInfo);
    }
    CloseHandle(hSnapshort);
    if (l_target_process) {

        return 0;
    }
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
    printf("-p, --pid      Pid of specified process need saving(pid must bigger than 3).\n");
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

BOOL PromotePrivileges(DWORD dwPid) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPid);
    if (hProcess == NULL) {
        return FALSE;
    }

    // get current process token
    HANDLE hToken;
    if (!OpenProcessToken(hProcess, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        CloseHandle(hProcess);
        return FALSE;
    }

    // promote PromotePrivileges
    TOKEN_PRIVILEGES tp;
    LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid);
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL);

    CloseHandle(hToken);
    CloseHandle(hProcess);

    return TRUE;
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
        

        process_cnt = min(process_cnt, g_top_number);
        if (process_cnt == 0) {
            printf("%s:%d", WINPROCMON_ERROR_MONITOR_TARGET_PROCESS, g_pid);
            return;
        }
        PrintCurrentTime();
        PrintSystemMemoryInfo();
        printf("           PID     WorkingSet(B)       PageFile(B)    ProcessName\n");
        if (g_file_ptr) {
            fprintf(g_file_ptr, "           PID        WorkingSet          PageFile    ProcessName\n");
            fflush(g_file_ptr);
        }
        for (unsigned long i = 0; i < process_cnt; ++i) {
            printf("%14lu    %14lu    %14lu    %s\n", g_process_list[i].s_pe.th32ProcessID, g_process_list[i].s_pmc.WorkingSetSize, g_process_list[i].s_pmc.PagefileUsage, g_process_list[i].s_pe.szExeFile);
            if (g_file_ptr) {
                fprintf(g_file_ptr, "%14lu    %14lu    %14lu    %s\n", g_process_list[i].s_pe.th32ProcessID, g_process_list[i].s_pmc.WorkingSetSize, g_process_list[i].s_pmc.PagefileUsage, g_process_list[i].s_pe.szExeFile);
                fflush(g_file_ptr);
            }
        }
        printf("\n");
        if (g_file_ptr) {
            fprintf(g_file_ptr, "\n");
            fflush(g_file_ptr);
        }
        Sleep(g_time * 1000);
    };

}

void PrintSystemMemoryInfo()
{
    /*MEMORYSTATUSEX mem_stat;
    ZeroMemory(&mem_stat, sizeof(mem_stat));
    mem_stat.dwLength = sizeof(mem_stat);//必须执行这一步
    GlobalMemoryStatusEx(&mem_stat); //取得内存状态
    printf("内存利用率        %u\%\t\n", mem_stat.dwMemoryLoad);
    printf("物理内存：        %uKB\t\n", mem_stat.ullTotalPhys / DLV);
    printf("可用物理内存：      %uKB\t\n", mem_stat.ullAvailPhys / DLV);
    printf("总共页文件大小：    %uKB\t\n", mem_stat.ullTotalPageFile / DLV);
    printf("空闲页文件大小：    %uKB\n", mem_stat.ullAvailPageFile / DLV);
    printf("虚拟内存大小：    %uKB\t\n", mem_stat.ullTotalVirtual / DLV);
    printf("空闲虚拟内存大小：%uKB\t\n", mem_stat.ullAvailVirtual / DLV);
    printf("空闲拓展内存大小：%uKB\t\n", mem_stat.ullAvailExtendedVirtual / DLV);*/

    PERFORMANCE_INFORMATION pi;
    GetPerformanceInfo(&pi, sizeof(pi));
    DWORDLONG page_size = pi.PageSize;
    printf("CommitTotal        :%12uKB ", pi.CommitTotal * page_size / DLV);
    printf("CommitLimit        :%12uKB ", pi.CommitLimit * page_size / DLV);
    printf("CommitPeak         :%12uKB\n", pi.CommitPeak * page_size / DLV);
    printf("PhysicalMemoryTotal:%12uKB ", pi.PhysicalTotal * page_size / DLV);
    printf("PhysicalMemoryAval :%12uKB ", pi.PhysicalAvailable * page_size / DLV);
    printf("SystemCache        :%12uKB\n", page_size * pi.SystemCache / DLV);
    printf("KernelTotal        :%12uKB ", pi.KernelTotal * page_size / DLV);
    printf("KernelPaged        :%12uKB ", pi.KernelPaged * page_size / DLV);
    printf("KernelNonpaged     :%12uKB\n", pi.KernelNonpaged * page_size / DLV);
    //printf("Page Size              %uKB\t\n", pi.PageSize / DLV);
    printf("HandleCount        :%12u   ", pi.HandleCount);
    printf("ProcessCount       :%12u   ", pi.ProcessCount);
    printf("ThreadCount        :%12u\n", pi.ThreadCount);
    if (g_file_ptr) {
        fprintf(g_file_ptr, "CommitTotal        :%12uKB ", pi.CommitTotal * page_size / DLV);
        fprintf(g_file_ptr, "CommitLimit        :%12uKB ", pi.CommitLimit * page_size / DLV);
        fprintf(g_file_ptr, "CommitPeak         :%12uKB\n", pi.CommitPeak * page_size / DLV);
        fprintf(g_file_ptr, "PhysicalMemoryTotal:%12uKB ", pi.PhysicalTotal * page_size / DLV);
        fprintf(g_file_ptr, "PhysicalMemoryAval :%12uKB ", pi.PhysicalAvailable * page_size / DLV);
        fprintf(g_file_ptr, "SystemCache        :%12uKB\n", page_size * pi.SystemCache / DLV);
        fprintf(g_file_ptr, "KernelTotal        :%12uKB ", pi.KernelTotal * page_size / DLV);
        fprintf(g_file_ptr, "KernelPaged        :%12uKB ", pi.KernelPaged * page_size / DLV);
        fprintf(g_file_ptr, "KernelNonpaged     :%12uKB\n", pi.KernelNonpaged * page_size / DLV);
        fprintf(g_file_ptr, "HandleCount        :%12u   ", pi.HandleCount);
        fprintf(g_file_ptr, "ProcessCount       :%12u   ", pi.ProcessCount);
        fprintf(g_file_ptr, "ThreadCount        :%12u\n", pi.ThreadCount);
        fflush(g_file_ptr);
    }

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
                        if (l_pid < 4) {
                            l_cmd_error = true;
                            l_error_msg = WINPROCMON_ERROR_INVALID_PID;
                            l_error_cmd = argv[i + 1];
                        }
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
    
    setlocale(LC_ALL, "");

    PromotePrivileges(GetCurrentProcessId());
    MainLoop(argc, argv);
    if (g_file_ptr) {
        fclose(g_file_ptr);
    }
    //PrintSystemMemoryInfo();
    return 0;
}