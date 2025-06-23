#pragma once
#include <ntifs.h>

#define SystemModuleInformation 11
#define POOL_TAG 'oamL'
#define ImageFileName 0x5A8 // EPROCESS::ImageFileName
#define ActiveThreads 0x5F0 // EPROCESS::ActiveThreads
#define ThreadListHead 0x5E0 // EPROCESS::ThreadListHead
#define ActiveProcessLinks 0x448 // EPROCESS::ActiveProcessLinks

extern "C" {
    NTKERNELAPI NTSTATUS IoCreateDriver(PUNICODE_STRING DriverName,
        PDRIVER_INITIALIZE InitializationFunction);

    NTKERNELAPI NTSTATUS MmCopyVirtualMemory(PEPROCESS SourceProcess, PVOID SourceAddress,
        PEPROCESS TargetProcess, PVOID TargetAddress,
        SIZE_T BufferSize, KPROCESSOR_MODE PreviousMode,
        PSIZE_T ReturnSize);

    NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(ULONG InfoClass, PVOID Buffer, ULONG Length, PULONG ReturnLength);
    NTKERNELAPI PPEB NTAPI PsGetProcessPeb(PEPROCESS Process);
}

void debug_print(PCSTR text) {
#ifndef DEBUG
    UNREFERENCED_PARAMETER(text);
#endif // DEBUG

    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, text));
}

template <typename str_type, typename str_type_2>
__forceinline bool crt_strcmp(str_type str, str_type_2 in_str, bool two)
{
    if (!str || !in_str)
        return false;

    wchar_t c1, c2;
#define to_lower(c_char) ((c_char >= 'A' && c_char <= 'Z') ? (c_char + 32) : c_char)

    do
    {
        c1 = *str++; c2 = *in_str++;
        c1 = to_lower(c1); c2 = to_lower(c2);

        if (!c1 && (two ? !c2 : 1))
            return true;

    } while (c1 == c2);

    return false;
}

// Structure for reading memory from a process (matches usermode)
typedef struct _Request
{
    HANDLE process_id;
    PVOID target;
    PVOID buffer;
    SIZE_T size;
} Request, * PRequest;

// Structure for getting pid by name (matches usermode PID_PACK)
typedef struct _PID_PACK
{
    UINT32 pid;
    WCHAR name[1024];
} PID_PACK, * P_PID_PACK;

// Structure for getting module address base (matches usermode MODULE_PACK)
typedef struct _MODULE_PACK_KM {
    UINT32 pid;
    UINT64 baseAddress;
    SIZE_T size;
    WCHAR moduleName[1024];
} MODULE_PACK_KM, * PMODULE_PACK_KM;


typedef struct _SYSTEM_MODULE {
    ULONG_PTR Reserved[2];
    PVOID Base;
    ULONG Size;
    ULONG Flags;
    USHORT Index;
    USHORT Unknown;
    USHORT LoadCount;
    USHORT ModuleNameOffset;
    CHAR ImageName[256];
} SYSTEM_MODULE, * PSYSTEM_MODULE;

typedef struct _SYSTEM_MODULE_INFORMATION {
    ULONG_PTR ulModuleCount;
    SYSTEM_MODULE Modules[1];
} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;

#undef SystemModuleInformation

typedef enum _SYSTEM_INFORMATION_CLASS
{
    SystemInformationClassMin = 0,
    SystemBasicInformation = 0,
    SystemProcessorInformation = 1,
    SystemPerformanceInformation = 2,
    SystemTimeOfDayInformation = 3,
    SystemPathInformation = 4,
    SystemNotImplemented1 = 4,
    SystemProcessInformation = 5,
    SystemProcessesAndThreadsInformation = 5,
    SystemCallCountInfoInformation = 6,
    SystemCallCounts = 6,
    SystemDeviceInformation = 7,
    SystemConfigurationInformation = 7,
    SystemProcessorPerformanceInformation = 8,
    SystemProcessorTimes = 8,
    SystemFlagsInformation = 9,
    SystemGlobalFlag = 9,
    SystemCallTimeInformation = 10,
    SystemNotImplemented2 = 10,
    SystemModuleInformation = 11,
    SystemLocksInformation = 12,
    SystemLockInformation = 12,
    SystemStackTraceInformation = 13,
    SystemNotImplemented3 = 13,
    SystemPagedPoolInformation = 14,
    SystemNotImplemented4 = 14,
    SystemNonPagedPoolInformation = 15,
    SystemNotImplemented5 = 15,
    SystemHandleInformation = 16,
    SystemObjectInformation = 17,
    SystemPageFileInformation = 18,
    SystemPagefileInformation = 18,
    SystemVdmInstemulInformation = 19,
    SystemInstructionEmulationCounts = 19,
    SystemVdmBopInformation = 20,
    SystemInvalidInfoClass1 = 20,
    SystemFileCacheInformation = 21,
    SystemCacheInformation = 21,
    SystemPoolTagInformation = 22,
    SystemInterruptInformation = 23,
    SystemProcessorStatistics = 23,
    SystemDpcBehaviourInformation = 24,
    SystemDpcInformation = 24,
    SystemFullMemoryInformation = 25,
    SystemNotImplemented6 = 25,
    SystemLoadImage = 26,
    SystemUnloadImage = 27,
    SystemTimeAdjustmentInformation = 28,
    SystemTimeAdjustment = 28,
    SystemSummaryMemoryInformation = 29,
    SystemNotImplemented7 = 29,
    SystemNextEventIdInformation = 30,
    SystemNotImplemented8 = 30,
    SystemEventIdsInformation = 31,
    SystemNotImplemented9 = 31,
    SystemCrashDumpInformation = 32,
    SystemExceptionInformation = 33,
    SystemCrashDumpStateInformation = 34,
    SystemKernelDebuggerInformation = 35,
    SystemContextSwitchInformation = 36,
    SystemRegistryQuotaInformation = 37,
    SystemLoadAndCallImage = 38,
    SystemPrioritySeparation = 39,
    SystemPlugPlayBusInformation = 40,
    SystemNotImplemented10 = 40,
    SystemDockInformation = 41,
    SystemNotImplemented11 = 41,
    SystemInvalidInfoClass2 = 42,
    SystemProcessorSpeedInformation = 43,
    SystemInvalidInfoClass3 = 43,
    SystemCurrentTimeZoneInformation = 44,
    SystemTimeZoneInformation = 44,
    SystemLookasideInformation = 45,
    SystemSetTimeSlipEvent = 46,
    SystemCreateSession = 47,
    SystemDeleteSession = 48,
    SystemInvalidInfoClass4 = 49,
    SystemRangeStartInformation = 50,
    SystemVerifierInformation = 51,
    SystemAddVerifier = 52,
    SystemSessionProcessesInformation = 53,
    SystemInformationClassMax
} SYSTEM_INFORMATION_CLASS;

typedef struct _SYSTEM_THREAD_INFORMATION {
    LARGE_INTEGER KernelTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER CreateTime;
    ULONG WaitTime;
    PVOID StartAddress;
    CLIENT_ID ClientId;
    KPRIORITY Priority;
    LONG BasePriority;
    ULONG ContextSwitches;
    ULONG ThreadState;
    KWAIT_REASON WaitReason;
} SYSTEM_THREAD_INFORMATION, * PSYSTEM_THREAD_INFORMATION;

typedef struct _SYSTEM_PROCESS_INFORMATION {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER WorkingSetPrivateSize;
    ULONG HardFaultCount;
    ULONG NumberOfThreadsHighWatermark;
    ULONGLONG CycleTime;
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    KPRIORITY BasePriority;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;
    ULONG HandleCount;
    ULONG SessionId;
    ULONG_PTR UniqueProcessKey;
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG PageFaultCount;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    SIZE_T QuotaPeakPagedPoolUsage;
    SIZE_T QuotaPagedPoolUsage;
    SIZE_T QuotaPeakNonPagedPoolUsage;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
    LARGE_INTEGER ReadOperationCount;
    LARGE_INTEGER WriteOperationCount;
    LARGE_INTEGER OtherOperationCount;
    LARGE_INTEGER ReadTransferCount;
    LARGE_INTEGER WriteTransferCount;
    LARGE_INTEGER OtherTransferCount;
    SYSTEM_THREAD_INFORMATION Threads[1];
} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;


typedef struct _PEB_LDR_DATA {
    ULONG Length;
    UCHAR Initialized;
    PVOID SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    USHORT LoadCount;
    USHORT TlsIndex;
    union {
        LIST_ENTRY HashLinks;
        struct {
            PVOID SectionPointer;
            ULONG CheckSum;
        }Info;
    };
    union {
        ULONG TimeDateStamp;
        PVOID LoadedImports;
    };
    PVOID EntryPointActivationContext;
    PVOID PatchInformation;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB {
    UCHAR InheritedAddressSpace;
    UCHAR ReadImageFileExecOptions;
    UCHAR BeingDebugged;
    UCHAR BitField;
    PVOID Mutant;
    PVOID ImageBaseAddress;
    PPEB_LDR_DATA Ldr;
    // ... other fields truncated for brevity
} PEB, * PPEB;

// Kernel-mode safe wide char to ANSI conversion
NTSTATUS WideCharToAnsi(PWCHAR WideString, PCHAR AnsiString, ULONG AnsiStringLength)
{
    UNICODE_STRING unicodeString;
    ANSI_STRING ansiString;
    NTSTATUS status;

    RtlInitUnicodeString(&unicodeString, WideString);

    ansiString.Buffer = AnsiString;
    ansiString.Length = 0;
    ansiString.MaximumLength = (USHORT)AnsiStringLength;

    status = RtlUnicodeStringToAnsiString(&ansiString, &unicodeString, FALSE);

    if (NT_SUCCESS(status)) {
        // Null-terminate the string
        if (ansiString.Length < AnsiStringLength) {
            AnsiString[ansiString.Length] = '\0';
        }
    }

    return status;
}

PVOID GetProcessModuleBase(HANDLE processId, const char* moduleName) {
    PEPROCESS targetProcess = nullptr;
    NTSTATUS status = PsLookupProcessByProcessId(processId, &targetProcess);

    if (!NT_SUCCESS(status) || !targetProcess) {
        return nullptr;
    }

    // Attach to the target process
    KAPC_STATE apcState;
    KeStackAttachProcess(targetProcess, &apcState);

    PVOID moduleBase = nullptr;

    __try {
        // Get PEB
        PPEB peb = PsGetProcessPeb(targetProcess);
        if (!peb) {
            __leave;
        }

        // Get loader data
        PPEB_LDR_DATA ldrData = peb->Ldr;
        if (!ldrData) {
            __leave;
        }

        // Walk the module list
        PLIST_ENTRY listHead = &ldrData->InLoadOrderModuleList;
        PLIST_ENTRY listEntry = listHead->Flink;

        while (listEntry != listHead) {
            PLDR_DATA_TABLE_ENTRY ldrEntry = CONTAINING_RECORD(listEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

            if (ldrEntry->BaseDllName.Buffer && ldrEntry->BaseDllName.Length > 0) {
                // Convert Unicode to ANSI for comparison
                char ansiName[256] = { 0 };
                UNICODE_STRING unicodeName = ldrEntry->BaseDllName;
                ANSI_STRING ansiString;
                ansiString.Buffer = ansiName;
                ansiString.Length = 0;
                ansiString.MaximumLength = sizeof(ansiName);

                if (NT_SUCCESS(RtlUnicodeStringToAnsiString(&ansiString, &unicodeName, FALSE))) {
                    if (_stricmp(ansiName, moduleName) == 0) {
                        moduleBase = ldrEntry->DllBase;
                        break;
                    }
                }
            }

            listEntry = listEntry->Flink;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        moduleBase = nullptr;
    }

    KeUnstackDetachProcess(&apcState);
    ObDereferenceObject(targetProcess);

    return moduleBase;
}

HANDLE GetPID(const wchar_t* process_name)
{
    ULONG length = 0;
    NTSTATUS status = ZwQuerySystemInformation(SystemProcessInformation, NULL, 0, &length);

    if (status != STATUS_INFO_LENGTH_MISMATCH)
        return NULL;

    //PVOID buffer = ExAllocatePoolWithTag(NonPagedPool, length, 'proc');
    PVOID buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, length, 'proc');
    if (!buffer)
        return NULL;

    status = ZwQuerySystemInformation(SystemProcessInformation, buffer, length, &length);
    if (!NT_SUCCESS(status)) {
        ExFreePool(buffer);
        return NULL;
    }

    PSYSTEM_PROCESS_INFORMATION process_info = (PSYSTEM_PROCESS_INFORMATION)buffer;

    while (TRUE)
    {
        if (process_info->ImageName.Buffer && process_info->ImageName.Length > 0) {
            // Compare full name (case-insensitive)
            if (_wcsicmp(process_info->ImageName.Buffer, process_name) == 0) {
                HANDLE pid = process_info->UniqueProcessId;
                ExFreePool(buffer);
                return pid;
            }
        }

        if (process_info->NextEntryOffset == 0)
            break;

        process_info = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)process_info + process_info->NextEntryOffset);
    }

    ExFreePool(buffer);
    return NULL;
}

