#pragma once
#include <ntifs.h>
#include <ntddk.h>

typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR  FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES
{
	ULONG NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;

#ifdef __cplusplus
extern "C"
{
#endif

	NTSTATUS
		NTAPI ZwQuerySystemInformation(
			IN ULONG SystemInformationClass,
			IN OUT PVOID SystemInformation,
			IN ULONG SystemInformationLength,
			OUT PULONG ReturnLength);

	PVOID
		NTAPI
		RtlFindExportedRoutineByName(
			_In_ PVOID ImageBase,
			_In_ PCCH RoutineName);

	NTSTATUS
		NTAPI
		MmCopyVirtualMemory(
			PEPROCESS SourceProcess,
			PVOID SourceAddress,
			PEPROCESS TargetProcess,
			PVOID TargetAddress,
			SIZE_T BufferSize,
			KPROCESSOR_MODE PreviousMode,
			PSIZE_T ReturnSize);

#ifdef __cplusplus
}
#endif

enum operator_type
{
	type_get_version,
	type_fast_memory_read,
	type_fast_memory_write,
	type_memory_read,
	type_memory_write,
	type_process_information,
	type_allocate_memory,
	type_free_memory,
	type_suspend_process,
	type_resume_process,
	type_create_thread
};

typedef struct _share_memory_
{
	operator_type type;
	long result;
	unsigned int version;
	unsigned int process_id;

	unsigned long long address;
	unsigned long long buffer;
	unsigned int buffer_size;

	unsigned long long function_routine;
	unsigned long long function_argument;
	unsigned int thread_id;
}share_memory, * pshare_memory;
