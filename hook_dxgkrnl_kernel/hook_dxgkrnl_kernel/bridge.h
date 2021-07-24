#pragma once
#include <ntifs.h>
#include <ntdef.h>
#include <ntddk.h>

namespace AddressRange
{
	inline BOOLEAN IsUserAddress(PVOID Address)
	{
		return reinterpret_cast<SIZE_T>(Address) < (static_cast<SIZE_T>(1) << (8 * sizeof(SIZE_T) - 1));
	}

	inline BOOLEAN IsKernelAddress(PVOID Address)
	{
		return reinterpret_cast<SIZE_T>(Address) >= (static_cast<SIZE_T>(1) << (8 * sizeof(SIZE_T) - 1));
	}
}

namespace Importer {
	_IRQL_requires_max_(PASSIVE_LEVEL)
		PVOID NTAPI GetKernelProcAddress(LPCWSTR SystemRoutineName);
}

namespace Mdl {
	_IRQL_requires_max_(APC_LEVEL)
		PMDL AllocMdlAndLockPages(
			PVOID Address,
			ULONG Size,
			KPROCESSOR_MODE AccessMode = KernelMode,
			LOCK_OPERATION Operation = IoReadAccess,
			OPTIONAL PEPROCESS Process = NULL
		);

	_IRQL_requires_max_(APC_LEVEL)
		VOID UnlockPagesAndFreeMdl(PMDL Mdl);

	_IRQL_requires_max_(APC_LEVEL)
		NTSTATUS MapMdl(
			IN PMDL Mdl,
			OUT PVOID* MappedMemory, // Receives the bease address of mapped memory
			OPTIONAL PEPROCESS SrcProcess, // Set NULL to use the address space of current process
			OPTIONAL PEPROCESS DestProcess, // Set NULL to use the address space of current process
			BOOLEAN NeedProbeAndLock,
			KPROCESSOR_MODE MapToAddressSpace = KernelMode,
			ULONG Protect = PAGE_READWRITE,
			MEMORY_CACHING_TYPE CacheType = MmNonCached,
			OPTIONAL PVOID UserRequestedAddress = NULL
		);

	_IRQL_requires_max_(APC_LEVEL)
		VOID UnmapMdl(IN PMDL Mdl, IN PVOID MappedMemory, BOOLEAN NeedUnlock);

	// Result type of MapMemory function:
	using MAPPING_INFO = struct {
		PMDL Mdl;
		PVOID BaseAddress;
	};
	using PMAPPING_INFO = MAPPING_INFO*;

	_IRQL_requires_max_(APC_LEVEL)
		NTSTATUS MapMemory(
			OUT PMAPPING_INFO MappingInfo,
			OPTIONAL PEPROCESS SrcProcess,
			OPTIONAL PEPROCESS DestProcess,
			IN PVOID VirtualAddress, // Address in SrcProcess to map in the DestProcess
			ULONG Size,
			KPROCESSOR_MODE MapToAddressSpace = KernelMode,
			ULONG Protect = PAGE_READWRITE,
			MEMORY_CACHING_TYPE CacheType = MmNonCached,
			OPTIONAL PVOID UserRequestedAddress = NULL
		);

	_IRQL_requires_max_(APC_LEVEL)
		VOID UnmapMemory(IN PMAPPING_INFO MappingInfo);
}

namespace PhysicalMemory
{
	_IRQL_requires_max_(APC_LEVEL)
		PVOID64 GetPhysicalAddress(PVOID VirtualAddress, OPTIONAL PEPROCESS Process = NULL);
}

namespace VirtualMemory
{
	_IRQL_requires_max_(DISPATCH_LEVEL)
		BOOLEAN IsPagePresent(PVOID Address);

	_IRQL_requires_max_(DISPATCH_LEVEL)
		BOOLEAN IsMemoryRangePresent(PVOID Address, SIZE_T Size);

	_IRQL_requires_max_(APC_LEVEL)
		BOOLEAN SecureProcessMemory(
			PEPROCESS Process,
			__in_data_source(USER_MODE) PVOID UserAddress,
			SIZE_T Size,
			ULONG ProtectRights, // PAGE_***
			OUT PHANDLE SecureHandle
		);

	_IRQL_requires_max_(APC_LEVEL)
		BOOLEAN SecureMemory(
			__in_data_source(USER_MODE) PVOID UserAddress,
			SIZE_T Size,
			ULONG ProtectRights, // PAGE_***
			OUT PHANDLE SecureHandle
		);

	_IRQL_requires_max_(APC_LEVEL)
		VOID UnsecureProcessMemory(PEPROCESS Process, HANDLE SecureHandle);

	_IRQL_requires_max_(APC_LEVEL)
		VOID UnsecureMemory(HANDLE SecureHandle);

	BOOLEAN CopyMemory(
		PVOID Dest,
		PVOID Src,
		SIZE_T Size,
		BOOLEAN Intersects = FALSE,
		OPTIONAL BOOLEAN CheckBuffersPresence = FALSE
	);
}

namespace Processes
{
	namespace Descriptors
	{
		_IRQL_requires_max_(APC_LEVEL)
			PEPROCESS GetEPROCESS(HANDLE ProcessId);

		_IRQL_requires_max_(PASSIVE_LEVEL)
			NTSTATUS OpenProcess(
				HANDLE ProcessId,
				OUT PHANDLE hProcess,
				ACCESS_MASK AccessMask = PROCESS_ALL_ACCESS,
				ULONG Attributes = OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE
			);
	}

	namespace MemoryManagement
	{
		_IRQL_requires_max_(APC_LEVEL)
			NTSTATUS OperateProcessMemory(
				PEPROCESS Process,
				PVOID BaseAddress,
				PVOID Buffer,
				ULONG Size,
				ULONG Operation);

		_IRQL_requires_max_(APC_LEVEL)
			NTSTATUS ReadProcessMemory(
				PEPROCESS Process,
				IN PVOID BaseAddress, // In the target process or kernel address
				OUT PVOID Buffer, // User or kernel address in the current process
				ULONG Size
			);

		_IRQL_requires_max_(APC_LEVEL)
			NTSTATUS WriteProcessMemory(
				PEPROCESS Process,
				OUT PVOID BaseAddress, // In the target process or kernel address
				IN PVOID Buffer, // User or kernel address in the current process
				ULONG Size
			);

		_IRQL_requires_max_(PASSIVE_LEVEL)
			NTSTATUS AllocateVirtualMemory(HANDLE hProcess, SIZE_T Size, ULONG Protect, IN OUT PVOID* BaseAddress);

		_IRQL_requires_max_(PASSIVE_LEVEL)
			NTSTATUS FreeVirtualMemory(HANDLE hProcess, PVOID BaseAddress);
	}

	namespace Information
	{
		_IRQL_requires_max_(PASSIVE_LEVEL)
			NTSTATUS QueryInformationProcess(
				HANDLE hProcess,
				PROCESSINFOCLASS ProcessInformationClass,
				OUT PVOID ProcessInformation,
				ULONG ProcessInformationLength,
				OUT PULONG ReturnLength
			);
	}

	namespace Threads
	{
		using _UserThreadRoutine = NTSTATUS(NTAPI*)(PVOID Argument);

		_IRQL_requires_max_(PASSIVE_LEVEL)
			NTSTATUS CreateUserThread(
				HANDLE hProcess,
				IN _UserThreadRoutine StartAddress,
				IN PVOID Argument,
				BOOLEAN CreateSuspended,
				OUT PHANDLE hThread,
				OUT PCLIENT_ID ClientId
			);

		_IRQL_requires_max_(APC_LEVEL)
			NTSTATUS SuspendProcess(IN PEPROCESS Process);

		_IRQL_requires_max_(APC_LEVEL)
			NTSTATUS ResumeProcess(IN PEPROCESS Process);
	}
}

// 读取内存
NTSTATUS FASTCALL KbReadProcessMemory(void* ptr);

// 写入内存
NTSTATUS FASTCALL KbWriteProcessMemory(void* ptr);

// 快速读取
NTSTATUS FASTCALL KbReadProcessMemoryFast(void* ptr);

// 快速写入
NTSTATUS FASTCALL KbWriteProcessMemoryFast(void* ptr);

// 查询信息
NTSTATUS FASTCALL KbQueryInformationProcess(void* ptr);

// 申请内存
NTSTATUS FASTCALL KbAllocUserMemory(void* ptr);

// 释放内存
NTSTATUS FASTCALL KbFreeUserMemory(void* ptr);

// 暂停进程
NTSTATUS FASTCALL KbSuspendProcess(void* ptr);

// 恢复进程
NTSTATUS FASTCALL KbResumeProcess(void* ptr);

// 创建线程
NTSTATUS FASTCALL KbCreateUserThread(void* ptr);
