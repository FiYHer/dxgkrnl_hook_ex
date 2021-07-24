#include "imports.h"
#include "bridge.h"

namespace Importer {
	_IRQL_requires_max_(PASSIVE_LEVEL)
		PVOID NTAPI GetKernelProcAddress(LPCWSTR SystemRoutineName) {
		UNICODE_STRING Name;
		RtlInitUnicodeString(&Name, SystemRoutineName);
		return MmGetSystemRoutineAddress(&Name);
	}
}

namespace Mdl {
	_IRQL_requires_max_(APC_LEVEL)
		PMDL AllocMdlAndLockPages(
			PVOID Address,
			ULONG Size,
			KPROCESSOR_MODE AccessMode,
			LOCK_OPERATION Operation,
			OPTIONAL PEPROCESS Process
		) {
		if (!Address || !Size) return NULL;
		PMDL Mdl = IoAllocateMdl(Address, Size, FALSE, FALSE, NULL);
		if (!Mdl) return NULL;
		__try {
			if (Process && Process != PsGetCurrentProcess())
				MmProbeAndLockProcessPages(Mdl, Process, AccessMode, Operation);
			else
				MmProbeAndLockPages(Mdl, AccessMode, Operation);
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			IoFreeMdl(Mdl);
			return NULL;
		}
		return Mdl;
	}

	_IRQL_requires_max_(APC_LEVEL)
		VOID UnlockPagesAndFreeMdl(PMDL Mdl) {
		if (!Mdl) return;
		MmUnlockPages(Mdl);
		IoFreeMdl(Mdl);
	}

	_IRQL_requires_max_(APC_LEVEL)
		NTSTATUS MapMdl(
			IN PMDL Mdl,
			OUT PVOID* MappedMemory,
			OPTIONAL PEPROCESS SrcProcess,
			OPTIONAL PEPROCESS DestProcess,
			BOOLEAN NeedProbeAndLock,
			KPROCESSOR_MODE MapToAddressSpace,
			ULONG Protect,
			MEMORY_CACHING_TYPE CacheType,
			OPTIONAL PVOID UserRequestedAddress
		) {
		if (!MappedMemory) return STATUS_INVALID_PARAMETER;
		*MappedMemory = NULL;

		if (UserRequestedAddress) {
			if (
				(MapToAddressSpace == KernelMode && AddressRange::IsUserAddress(UserRequestedAddress)) ||
				(MapToAddressSpace == UserMode && AddressRange::IsKernelAddress(UserRequestedAddress))
				) return STATUS_INVALID_PARAMETER_6; // Access mode is incompatible with UserRequestAddress!
		}

		BOOLEAN IsLocked = FALSE;
		BOOLEAN IsAttached = FALSE;
		KAPC_STATE ApcState;
		__try {
			PEPROCESS CurrentProcess = PsGetCurrentProcess();

			// Lock and prepare pages in target process:
			if (NeedProbeAndLock) {
				if (!SrcProcess || SrcProcess == CurrentProcess)
					MmProbeAndLockPages(Mdl, KernelMode, IoReadAccess);
				else
					MmProbeAndLockProcessPages(Mdl, SrcProcess, KernelMode, IoReadAccess);
				IsLocked = TRUE;
			}

			if (DestProcess && DestProcess != CurrentProcess) {
				KeStackAttachProcess(DestProcess, &ApcState);
				IsAttached = TRUE;
			}

			// Map prepared pages to current process:
			PVOID Mapping = MmMapLockedPagesSpecifyCache(
				Mdl,
				MapToAddressSpace,
				CacheType,
				MapToAddressSpace == UserMode ? UserRequestedAddress : NULL,
				FALSE,
				NormalPagePriority
			);

			MmProtectMdlSystemAddress(Mdl, Protect);

			if (IsAttached) KeUnstackDetachProcess(&ApcState);
			*MappedMemory = Mapping;
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			if (IsAttached) KeUnstackDetachProcess(&ApcState);
			if (IsLocked) MmUnlockPages(Mdl);
			return STATUS_UNSUCCESSFUL;
		}

		return STATUS_SUCCESS;
	}

	_IRQL_requires_max_(APC_LEVEL)
		VOID UnmapMdl(IN PMDL Mdl, IN PVOID MappedMemory, BOOLEAN NeedUnlock) {
		MmUnmapLockedPages(MappedMemory, Mdl);
		if (NeedUnlock) MmUnlockPages(Mdl);
	}

	_IRQL_requires_max_(APC_LEVEL)
		NTSTATUS MapMemory(
			OUT PMAPPING_INFO MappingInfo,
			OPTIONAL PEPROCESS SrcProcess,
			OPTIONAL PEPROCESS DestProcess,
			IN PVOID VirtualAddress,
			ULONG Size,
			KPROCESSOR_MODE MapToAddressSpace,
			ULONG Protect,
			MEMORY_CACHING_TYPE CacheType,
			OPTIONAL PVOID UserRequestedAddress
		) {
		if (!Size || !MappingInfo) return STATUS_INVALID_PARAMETER;

		*MappingInfo = {};

		MappingInfo->Mdl = IoAllocateMdl(VirtualAddress, Size, FALSE, FALSE, NULL);
		if (!MappingInfo->Mdl) return STATUS_MEMORY_NOT_ALLOCATED;

		NTSTATUS Status = MapMdl(
			MappingInfo->Mdl,
			&MappingInfo->BaseAddress,
			SrcProcess,
			DestProcess,
			TRUE,
			MapToAddressSpace,
			Protect,
			CacheType,
			UserRequestedAddress
		);

		if (!NT_SUCCESS(Status)) {
			if (Status == STATUS_INVALID_PARAMETER_6)
				Status = STATUS_INVALID_PARAMETER_7; // Do it corresponding to current prototype
			IoFreeMdl(MappingInfo->Mdl);
			*MappingInfo = {};
		}

		return Status;
	}

	_IRQL_requires_max_(APC_LEVEL)
		VOID UnmapMemory(IN PMAPPING_INFO MappingInfo) {
		MmUnmapLockedPages(MappingInfo->BaseAddress, MappingInfo->Mdl);
		MmUnlockPages(MappingInfo->Mdl);
		IoFreeMdl(MappingInfo->Mdl);
	}
}

namespace PhysicalMemory
{
	_IRQL_requires_max_(APC_LEVEL)
		PVOID64 GetPhysicalAddress(PVOID VirtualAddress, OPTIONAL PEPROCESS Process) {
		if (!Process || Process == PsGetCurrentProcess()) {
			return MmIsAddressValid(VirtualAddress)
				? reinterpret_cast<PVOID64>(MmGetPhysicalAddress(VirtualAddress).QuadPart)
				: NULL;
		}
		return NULL;
	}
}

namespace VirtualMemory
{
	_IRQL_requires_max_(DISPATCH_LEVEL)
		BOOLEAN IsPagePresent(PVOID Address) {
		return PhysicalMemory::GetPhysicalAddress(Address) || MmIsAddressValid(Address);
	}

	_IRQL_requires_max_(DISPATCH_LEVEL)
		BOOLEAN IsMemoryRangePresent(PVOID Address, SIZE_T Size) {
		PVOID PageCounter = ALIGN_DOWN_POINTER_BY(Address, PAGE_SIZE);
		do {
			if (!IsPagePresent(PageCounter)) return FALSE;
			PageCounter = reinterpret_cast<PVOID>(reinterpret_cast<SIZE_T>(PageCounter) + PAGE_SIZE);
		} while (reinterpret_cast<SIZE_T>(PageCounter) < reinterpret_cast<SIZE_T>(Address) + Size);
		return TRUE;
	}

	_IRQL_requires_max_(APC_LEVEL)
		BOOLEAN SecureMemory(
			__in_data_source(USER_MODE) PVOID UserAddress,
			SIZE_T Size,
			ULONG ProtectRights,
			OUT PHANDLE SecureHandle
		) {
		if (!SecureHandle || !Size || AddressRange::IsKernelAddress(UserAddress))
			return FALSE;
		*SecureHandle = MmSecureVirtualMemory(UserAddress, Size, ProtectRights);
		return *SecureHandle != NULL;
	}

	_IRQL_requires_max_(APC_LEVEL)
		BOOLEAN SecureProcessMemory(
			PEPROCESS Process,
			__in_data_source(USER_MODE) PVOID UserAddress,
			SIZE_T Size,
			ULONG ProtectRights,
			OUT PHANDLE SecureHandle
		) {
		if (!Process || !SecureHandle) return FALSE;
		if (Process == PsGetCurrentProcess())
			return SecureMemory(UserAddress, Size, ProtectRights, SecureHandle);

		HANDLE hSecure = NULL;
		KAPC_STATE ApcState;
		KeStackAttachProcess(Process, &ApcState);
		BOOLEAN Result = SecureMemory(UserAddress, Size, ProtectRights, &hSecure);
		KeUnstackDetachProcess(&ApcState);

		*SecureHandle = hSecure;
		return Result;
	}

	_IRQL_requires_max_(APC_LEVEL)
		VOID UnsecureProcessMemory(PEPROCESS Process, HANDLE SecureHandle) {
		if (!Process) return;
		if (Process == PsGetCurrentProcess())
			return UnsecureMemory(SecureHandle);
		if (SecureHandle) {
			KAPC_STATE ApcState;
			KeStackAttachProcess(Process, &ApcState);
			MmUnsecureVirtualMemory(SecureHandle);
			KeUnstackDetachProcess(&ApcState);
		}
	}

	_IRQL_requires_max_(APC_LEVEL)
		VOID UnsecureMemory(HANDLE SecureHandle) {
		if (SecureHandle) MmUnsecureVirtualMemory(SecureHandle);
	}

	BOOLEAN CopyMemory(PVOID Dest, PVOID Src, SIZE_T Size, BOOLEAN Intersects, OPTIONAL BOOLEAN CheckBuffersPresence) {
		if (CheckBuffersPresence) {
			if (AddressRange::IsKernelAddress(Src) && !IsMemoryRangePresent(Src, Size)) return FALSE;
			if (AddressRange::IsKernelAddress(Dest) && !IsMemoryRangePresent(Dest, Size)) return FALSE;
		}

		switch (Size) {
			case sizeof(UCHAR) : {
				*reinterpret_cast<PUCHAR>(Dest) = *reinterpret_cast<PUCHAR>(Src);
				break;
			}
			case sizeof(USHORT) : {
				*reinterpret_cast<PUSHORT>(Dest) = *reinterpret_cast<PUSHORT>(Src);
				break;
			}
			case sizeof(ULONG) : {
				*reinterpret_cast<PULONG>(Dest) = *reinterpret_cast<PULONG>(Src);
				break;
			}
#ifdef _AMD64_
			case sizeof(ULONGLONG) : {
				*reinterpret_cast<PULONGLONG>(Dest) = *reinterpret_cast<PULONGLONG>(Src);
				break;
			}
#endif
			default: {
				if (Intersects) {
					RtlMoveMemory(
						reinterpret_cast<PVOID>(Dest),
						reinterpret_cast<PVOID>(Src),
						Size
					);
				}
				else {
					RtlCopyMemory(
						reinterpret_cast<PVOID>(Dest),
						reinterpret_cast<PVOID>(Src),
						Size
					);
				}
			}
		}
		return TRUE;
	}
}

namespace Processes
{
	namespace Descriptors
	{
		_IRQL_requires_max_(APC_LEVEL)
			PEPROCESS GetEPROCESS(HANDLE ProcessId) {
			PEPROCESS Process;
			return NT_SUCCESS(PsLookupProcessByProcessId(ProcessId, &Process))
				? Process
				: NULL;
		}

		_IRQL_requires_max_(PASSIVE_LEVEL)
			NTSTATUS OpenProcess(
				HANDLE ProcessId,
				OUT PHANDLE hProcess,
				ACCESS_MASK AccessMask,
				ULONG Attributes
			) {
			CLIENT_ID ClientId;
			ClientId.UniqueProcess = ProcessId;
			ClientId.UniqueThread = 0;

			OBJECT_ATTRIBUTES ObjectAttributes;
			InitializeObjectAttributes(&ObjectAttributes, NULL, Attributes, NULL, NULL);

			return ZwOpenProcess(hProcess, AccessMask, &ObjectAttributes, &ClientId);
		}
	}

	namespace MemoryManagement
	{
		_IRQL_requires_max_(PASSIVE_LEVEL)
			NTSTATUS AllocateVirtualMemory(HANDLE hProcess, SIZE_T Size, ULONG Protect, IN OUT PVOID* BaseAddress) {
			return ZwAllocateVirtualMemory(hProcess, BaseAddress, 0, &Size, MEM_COMMIT, Protect);
		}

		_IRQL_requires_max_(PASSIVE_LEVEL)
			NTSTATUS FreeVirtualMemory(HANDLE hProcess, PVOID BaseAddress) {
			SIZE_T RegionSize = 0;
			return ZwFreeVirtualMemory(hProcess, &BaseAddress, &RegionSize, MEM_RELEASE);
		}

		_IRQL_requires_max_(APC_LEVEL)
			NTSTATUS OperateProcessMemory(
				PEPROCESS Process,
				PVOID BaseAddress,
				PVOID Buffer,
				ULONG Size,
				ULONG Operation
			) {
			if (!Process) return STATUS_INVALID_PARAMETER_1;
			if (!BaseAddress) return STATUS_INVALID_PARAMETER_2;
			if (!Buffer) return STATUS_INVALID_PARAMETER_3;
			if (!Size) return STATUS_INVALID_PARAMETER_4;

			if (AddressRange::IsKernelAddress(BaseAddress)) {
				if (!VirtualMemory::IsMemoryRangePresent(BaseAddress, Size))
					return STATUS_MEMORY_NOT_ALLOCATED;
			}

			if (AddressRange::IsKernelAddress(Buffer)) {
				if (!VirtualMemory::IsMemoryRangePresent(Buffer, Size))
					return STATUS_MEMORY_NOT_ALLOCATED;
			}

			// Attempt to lock process memory from freeing:
			HANDLE hProcessSecure = NULL;
			if (AddressRange::IsUserAddress(BaseAddress)) {
				if (!VirtualMemory::SecureProcessMemory(Process, BaseAddress, Size, PAGE_READONLY, &hProcessSecure))
					return STATUS_NOT_LOCKED;
			}

			// Attempt to lock buffer memory if it is usermode memory:
			HANDLE hBufferSecure = NULL;
			if (AddressRange::IsUserAddress(Buffer)) {
				if (!VirtualMemory::SecureMemory(Buffer, Size, PAGE_READWRITE, &hBufferSecure)) {
					if (hProcessSecure) VirtualMemory::UnsecureProcessMemory(Process, hProcessSecure);
					return STATUS_NOT_LOCKED;
				}
			}

			// Attempt to map process memory:
			Mdl::MAPPING_INFO ProcessMapping = {};
			NTSTATUS Status = Mdl::MapMemory(
				&ProcessMapping,
				Process,
				NULL,
				BaseAddress,
				Size
			);

			if (!NT_SUCCESS(Status)) {
				if (hProcessSecure) VirtualMemory::UnsecureProcessMemory(Process, hProcessSecure);
				if (hBufferSecure) VirtualMemory::UnsecureMemory(hBufferSecure);
				return STATUS_NOT_MAPPED_VIEW;
			}

			// Attempt to map buffer memory:
			Mdl::MAPPING_INFO BufferMapping = {};
			Status = Mdl::MapMemory(
				&BufferMapping,
				NULL,
				NULL,
				Buffer,
				Size
			);

			if (!NT_SUCCESS(Status)) {
				Mdl::UnmapMemory(&ProcessMapping);
				if (hProcessSecure) VirtualMemory::UnsecureProcessMemory(Process, hProcessSecure);
				if (hBufferSecure) VirtualMemory::UnsecureMemory(hBufferSecure);
				return STATUS_NOT_MAPPED_VIEW;
			}

			switch (Operation) {
			case 1:
				VirtualMemory::CopyMemory(BufferMapping.BaseAddress, ProcessMapping.BaseAddress, Size);
				break;
			case 2:
				VirtualMemory::CopyMemory(ProcessMapping.BaseAddress, BufferMapping.BaseAddress, Size);
				break;
			}
			Status = STATUS_SUCCESS;

			Mdl::UnmapMemory(&BufferMapping);
			Mdl::UnmapMemory(&ProcessMapping);
			if (hProcessSecure) VirtualMemory::UnsecureProcessMemory(Process, hProcessSecure);
			if (hBufferSecure) VirtualMemory::UnsecureMemory(hBufferSecure);

			return Status;
		}

		_IRQL_requires_max_(APC_LEVEL)
			NTSTATUS ReadProcessMemory(
				PEPROCESS Process,
				IN PVOID BaseAddress,
				OUT PVOID Buffer,
				ULONG Size
			) {
			return OperateProcessMemory(Process, BaseAddress, Buffer, Size, 1);
		}

		_IRQL_requires_max_(APC_LEVEL)
			NTSTATUS WriteProcessMemory(
				PEPROCESS Process,
				OUT PVOID BaseAddress,
				IN PVOID Buffer,
				ULONG Size
			) {
			return OperateProcessMemory(Process, BaseAddress, Buffer, Size, 2);
		}
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
			) {
			using _ZwQueryInformationProcess = NTSTATUS(NTAPI*)(
				HANDLE hProcess,
				PROCESSINFOCLASS ProcessInformationClass,
				IN PVOID ProcessInformation,
				ULONG ProcessInformationLength,
				OUT PULONG ReturnLength
				);
			static auto _QueryInformationProcess =
				static_cast<_ZwQueryInformationProcess>(Importer::GetKernelProcAddress(L"ZwQueryInformationProcess"));
			return _QueryInformationProcess
				? _QueryInformationProcess(
					hProcess,
					ProcessInformationClass,
					ProcessInformation,
					ProcessInformationLength,
					ReturnLength
				)
				: STATUS_NOT_IMPLEMENTED;
		}
	}

	namespace Threads
	{
		_IRQL_requires_max_(APC_LEVEL)
			NTSTATUS SuspendProcess(IN PEPROCESS Process) {
			using _PsSuspendProcess = NTSTATUS(NTAPI*)(
				IN PEPROCESS Process
				);
			static auto _SuspendProcess =
				static_cast<_PsSuspendProcess>(Importer::GetKernelProcAddress(L"PsSuspendProcess"));
			return _SuspendProcess
				? _SuspendProcess(Process)
				: STATUS_NOT_IMPLEMENTED;
		}

		_IRQL_requires_max_(APC_LEVEL)
			NTSTATUS ResumeProcess(IN PEPROCESS Process) {
			using _PsResumeProcess = NTSTATUS(NTAPI*)(
				IN PEPROCESS Process
				);
			static auto _SuspendProcess =
				static_cast<_PsResumeProcess>(Importer::GetKernelProcAddress(L"PsResumeProcess"));
			return _SuspendProcess
				? _SuspendProcess(Process)
				: STATUS_NOT_IMPLEMENTED;
		}

		_IRQL_requires_max_(PASSIVE_LEVEL)
			NTSTATUS CreateUserThread(
				HANDLE hProcess,
				IN _UserThreadRoutine StartAddress,
				IN PVOID Argument,
				BOOLEAN CreateSuspended,
				OUT PHANDLE hThread,
				OUT PCLIENT_ID ClientId
			) {
			using _RtlCreateUserThread = NTSTATUS(NTAPI*)(
				IN HANDLE               ProcessHandle,
				IN PSECURITY_DESCRIPTOR SecurityDescriptor,
				IN BOOLEAN              CreateSuspended,
				IN ULONG                StackZeroBits,
				IN OUT PULONG           StackReserved,
				IN OUT PULONG           StackCommit,
				IN PVOID                StartAddress,
				IN PVOID                StartParameter,
				OUT PHANDLE             ThreadHandle,
				OUT PCLIENT_ID          ClientID
				);
			static auto _CreateUserThread =
				static_cast<_RtlCreateUserThread>(Importer::GetKernelProcAddress(L"RtlCreateUserThread"));
			return _CreateUserThread
				? _CreateUserThread(
					hProcess,
					NULL,
					CreateSuspended,
					0,
					NULL,
					NULL,
					StartAddress,
					Argument,
					hThread,
					ClientId
				)
				: STATUS_NOT_IMPLEMENTED;
		}
	}
}

NTSTATUS FASTCALL KbReadProcessMemory(void* ptr)
{
	pshare_memory share = (pshare_memory)ptr;
	if (share == nullptr) return STATUS_UNSUCCESSFUL;
	if (share->process_id == 0) return STATUS_UNSUCCESSFUL;
	if (share->address == 0)  return STATUS_UNSUCCESSFUL;
	if (share->buffer == 0)  return STATUS_UNSUCCESSFUL;
	if (share->buffer_size == 0)  return STATUS_UNSUCCESSFUL;

	HANDLE ProcessId = reinterpret_cast<HANDLE>(share->process_id);
	PEPROCESS Process = Processes::Descriptors::GetEPROCESS(ProcessId);
	if (!Process) return STATUS_UNSUCCESSFUL;

	NTSTATUS Status = Processes::MemoryManagement::ReadProcessMemory(
		Process,
		reinterpret_cast<PVOID>(share->address),
		reinterpret_cast<PVOID>(share->buffer),
		share->buffer_size);

	ObDereferenceObject(Process);

	return Status;
}

NTSTATUS FASTCALL KbWriteProcessMemory(void* ptr)
{
	pshare_memory share = (pshare_memory)ptr;
	if (share == nullptr) return STATUS_UNSUCCESSFUL;
	if (share->process_id == 0) return STATUS_UNSUCCESSFUL;
	if (share->address == 0)  return STATUS_UNSUCCESSFUL;
	if (share->buffer == 0)  return STATUS_UNSUCCESSFUL;
	if (share->buffer_size == 0)  return STATUS_UNSUCCESSFUL;

	HANDLE ProcessId = reinterpret_cast<HANDLE>(share->process_id);
	PEPROCESS Process = Processes::Descriptors::GetEPROCESS(ProcessId);
	if (!Process) return STATUS_UNSUCCESSFUL;

	PVOID Address = reinterpret_cast<PVOID>(share->address);
	ULONG Size = (ULONG)share->buffer_size;

	NTSTATUS Status = Processes::MemoryManagement::WriteProcessMemory(
		Process,
		Address,
		reinterpret_cast<PVOID>(share->buffer),
		Size
	);

	ObDereferenceObject(Process);

	return Status;
}

NTSTATUS FASTCALL KbReadProcessMemoryFast(void* ptr)
{
	pshare_memory share = (pshare_memory)ptr;
	if (share == nullptr) return STATUS_UNSUCCESSFUL;
	if (share->address == 0) return STATUS_UNSUCCESSFUL;
	if (share->buffer == 0) return STATUS_UNSUCCESSFUL;
	if (share->process_id == 0)  return STATUS_UNSUCCESSFUL;
	if (share->buffer_size == 0) return STATUS_UNSUCCESSFUL;

	PEPROCESS SourceProcess;
	NTSTATUS Status = PsLookupProcessByProcessId((HANDLE)share->process_id, &SourceProcess);
	if (Status != STATUS_SUCCESS) return STATUS_UNSUCCESSFUL;

	SIZE_T Result;
	PEPROCESS TargetProcess = PsGetCurrentProcess();

	Status = MmCopyVirtualMemory(SourceProcess, (PVOID)share->address, TargetProcess, (PVOID)share->buffer, share->buffer_size, KernelMode, &Result);

	ObDereferenceObject(SourceProcess);

	return Status;
}

NTSTATUS FASTCALL KbWriteProcessMemoryFast(void* ptr)
{
	pshare_memory share = (pshare_memory)ptr;
	if (share == nullptr) return STATUS_UNSUCCESSFUL;
	if (share->address == 0) return STATUS_UNSUCCESSFUL;
	if (share->buffer == 0) return STATUS_UNSUCCESSFUL;
	if (share->process_id == 0)  return STATUS_UNSUCCESSFUL;
	if (share->buffer_size == 0) return STATUS_UNSUCCESSFUL;

	PEPROCESS SourceProcess;
	NTSTATUS Status = PsLookupProcessByProcessId((HANDLE)share->process_id, &SourceProcess);
	if (Status != STATUS_SUCCESS) return STATUS_UNSUCCESSFUL;

	SIZE_T Result;
	PEPROCESS TargetProcess = PsGetCurrentProcess();

	Status = MmCopyVirtualMemory(SourceProcess, (PVOID)share->buffer, TargetProcess, (PVOID)share->address, share->buffer_size, KernelMode, &Result);

	ObDereferenceObject(SourceProcess);

	return Status;
}

NTSTATUS FASTCALL KbQueryInformationProcess(void* ptr)
{
	pshare_memory share = (pshare_memory)ptr;
	if (share == nullptr) return STATUS_UNSUCCESSFUL;
	if (share->process_id == 0) return STATUS_UNSUCCESSFUL;
	if (share->buffer == 0) return STATUS_UNSUCCESSFUL;
	if (share->buffer_size == 0) return STATUS_UNSUCCESSFUL;

	HANDLE hProcess;
	NTSTATUS Status = Processes::Descriptors::OpenProcess(reinterpret_cast<HANDLE>(share->process_id), &hProcess);
	if (Status != STATUS_SUCCESS) return Status;

	ULONG Res = 0;
	Processes::Information::QueryInformationProcess(
		hProcess,
		static_cast<PROCESSINFOCLASS>(ProcessBasicInformation),
		reinterpret_cast<PVOID>(share->buffer),
		share->buffer_size,
		&Res);

	ZwClose(hProcess);

	return Status;
}

NTSTATUS FASTCALL KbAllocUserMemory(void* ptr)
{
	pshare_memory share = (pshare_memory)ptr;
	if (share == nullptr) return STATUS_UNSUCCESSFUL;
	if (share->process_id == 0) return STATUS_UNSUCCESSFUL;
	if (share->buffer_size == 0) return STATUS_UNSUCCESSFUL;

	HANDLE hProcess = NULL;
	NTSTATUS Status = Processes::Descriptors::OpenProcess(reinterpret_cast<HANDLE>(share->process_id), &hProcess);
	if (!NT_SUCCESS(Status)) return STATUS_UNSUCCESSFUL;

	SIZE_T Size = share->buffer_size;
	PVOID Addr = 0;
	Status = ZwAllocateVirtualMemory(hProcess, &Addr, 0, &Size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	if (hProcess) ZwClose(hProcess);
	share->address = share->buffer = reinterpret_cast<unsigned long long>(Addr);
	return Status;
}

NTSTATUS FASTCALL KbFreeUserMemory(void* ptr)
{
	pshare_memory share = (pshare_memory)ptr;
	if (share == nullptr) return STATUS_UNSUCCESSFUL;
	if (share->process_id == 0) return STATUS_UNSUCCESSFUL;
	if (share->address == 0)  return STATUS_UNSUCCESSFUL;

	HANDLE hProcess = 0;
	NTSTATUS Status = Processes::Descriptors::OpenProcess(reinterpret_cast<HANDLE>(share->process_id), &hProcess);
	if (!NT_SUCCESS(Status)) return STATUS_UNSUCCESSFUL;

	Status = Processes::MemoryManagement::FreeVirtualMemory(
		hProcess,
		reinterpret_cast<PVOID>(share->address));

	if (hProcess) ZwClose(hProcess);

	return Status;
}

NTSTATUS FASTCALL KbSuspendProcess(void* ptr)
{
	pshare_memory share = (pshare_memory)ptr;
	if (share == nullptr) return STATUS_UNSUCCESSFUL;
	if (share->process_id == 0) return STATUS_UNSUCCESSFUL;

	PEPROCESS Process = Processes::Descriptors::GetEPROCESS(reinterpret_cast<HANDLE>(share->process_id));
	if (!Process) return STATUS_UNSUCCESSFUL;

	NTSTATUS Status = Processes::Threads::SuspendProcess(Process);

	ObDereferenceObject(Process);

	return Status;
}

NTSTATUS FASTCALL KbResumeProcess(void* ptr)
{
	pshare_memory share = (pshare_memory)ptr;
	if (share == nullptr) return STATUS_UNSUCCESSFUL;
	if (share->process_id == 0) return STATUS_UNSUCCESSFUL;

	PEPROCESS Process = Processes::Descriptors::GetEPROCESS(reinterpret_cast<HANDLE>(share->process_id));
	if (!Process) return STATUS_UNSUCCESSFUL;

	NTSTATUS Status = Processes::Threads::ResumeProcess(Process);

	ObDereferenceObject(Process);

	return Status;
}

NTSTATUS FASTCALL KbCreateUserThread(void* ptr)
{
	pshare_memory share = (pshare_memory)ptr;
	if (share == nullptr) return STATUS_NOT_FOUND;
	if (share->process_id == 0) return STATUS_NOT_FOUND;
	if (share->function_routine == 0) return STATUS_NOT_FOUND;
	if (share->function_argument == 0) return STATUS_NOT_FOUND;

	HANDLE hProcess = 0;
	NTSTATUS Status = Processes::Descriptors::OpenProcess(reinterpret_cast<HANDLE>(share->process_id), &hProcess);
	if (!NT_SUCCESS(Status)) return STATUS_NOT_FOUND;

	HANDLE hThread = NULL;
	CLIENT_ID ClientId = {};
	Status = Processes::Threads::CreateUserThread(
		hProcess,
		reinterpret_cast<Processes::Threads::_UserThreadRoutine>(share->function_routine),
		reinterpret_cast<PVOID>(share->function_argument),
		FALSE,
		&hThread,
		&ClientId);

	share->thread_id = reinterpret_cast<unsigned int>(ClientId.UniqueThread);

	if (hProcess) ZwClose(hProcess);

	return Status;
}