#include "imports.h"
#include "dxgkrnl_hook.h"
#include "bridge.h"

namespace _dxhook
{
	void* get_system_module_base(const char* module_name)
	{
		if (module_name == nullptr) return nullptr;

		unsigned unsigned long count = 0;
		NTSTATUS status = ZwQuerySystemInformation(11, 0, count, &count);
		if (count == 0) return nullptr;

		const unsigned long tag = 'VMON';
		PRTL_PROCESS_MODULES modules = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(NonPagedPool, count, tag);
		if (modules == nullptr) return nullptr;

		status = ZwQuerySystemInformation(11, modules, count, &count);
		if (!NT_SUCCESS(status))
		{
			ExFreePoolWithTag(modules, tag);
			return nullptr;
		}

		PRTL_PROCESS_MODULE_INFORMATION module = modules->Modules;
		void* module_base = nullptr;
		for (unsigned long i = 0; i < modules->NumberOfModules; i++)
		{
			if (strcmp((const char*)module[i].FullPathName, module_name) == 0)
			{
				module_base = module[i].ImageBase;
				break;
			}
		}

		ExFreePoolWithTag(modules, tag);
		return module_base;
	}

	void* get_system_module_export(const char* module_name, const char* routine_name)
	{
		void* base = get_system_module_base(module_name);
		if (base == nullptr) return nullptr;
		else return RtlFindExportedRoutineByName(base, routine_name);
	}

	bool write_to_read_only_memory(void* address, void* buffer, size_t size)
	{
		bool ret = false;
		PMDL mdl = IoAllocateMdl(address, size, FALSE, FALSE, NULL);
		if (mdl)
		{
			MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);
			void* mapp = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmNonCached, NULL, FALSE, NormalPagePriority);
			if (mapp)
			{
				NTSTATUS status = MmProtectMdlSystemAddress(mdl, PAGE_READWRITE);
				if (NT_SUCCESS(status))
				{
					RtlCopyMemory(mapp, buffer, size);
					ret = true;
				}
				MmUnmapLockedPages(mapp, mdl);
			}
			MmUnlockPages(mdl);
			IoFreeMdl(mdl);
		}

		return ret;
	}

	void start_hook(void* function_address)
	{
		if (function_address == nullptr) return;

		void** dxgk_routine = reinterpret_cast<void**>(get_system_module_export("\\SystemRoot\\System32\\drivers\\dxgkrnl.sys", "NtOpenCompositionSurfaceSectionInfo"));
		if (dxgk_routine == nullptr) return;
		DbgPrintEx(0, 0, "[%s] NtOpenCompositionSurfaceSectionInfo address %p \n", __FUNCTION__, dxgk_routine);

		unsigned int i = 0;
		const unsigned char* byte_ptr = (const unsigned char*)dxgk_routine;
		for (i = 0; i < 0x200; i++)
		{
			if (byte_ptr[i] == 195 && byte_ptr[i + 1] == 204 && byte_ptr[i + 2] == 204)
				break;
		}

		if (i == 0x200) return;
		void** routine_ret = (void**)(byte_ptr + i);
		DbgPrintEx(0, 0, "[%s] Position %p \n", __FUNCTION__, routine_ret);

		unsigned char asms[] =
		{
			0x48,0xb8,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,// mov,rax,xxx
			0x49,0x8b,0x4b,0x08,// mov rcx, qword ptr ds:[r11+0x8]
			0xff,0xe0,// jmp rax
			0xc3// ret
		};

		uintptr_t ptr = reinterpret_cast<uintptr_t>(function_address);
		memcpy((void*)((unsigned long long)asms + 2 * sizeof(unsigned char)), &ptr, sizeof(void*));
		write_to_read_only_memory(routine_ret, &asms, sizeof(asms));

		DbgPrintEx(0, 0, "[%s] Hook Finish \n", __FUNCTION__);
	}

	long handler(void* ptr)
	{
		pshare_memory share = (pshare_memory)ptr;
		if (share)
		{
			switch (share->type)
			{
			case type_get_version:
				share->version = 100;
				share->result = STATUS_SUCCESS;
				break;
			case type_fast_memory_read:
				share->result = KbReadProcessMemoryFast(ptr);
				break;
			case type_fast_memory_write:
				share->result = KbWriteProcessMemoryFast(ptr);
				break;
			case type_memory_read:
				share->result = KbReadProcessMemory(ptr);
				break;
			case type_memory_write:
				share->result = KbWriteProcessMemory(ptr);
				break;
			case type_process_information:
				share->result = KbQueryInformationProcess(ptr);
				break;
			case type_allocate_memory:
				share->result = KbAllocUserMemory(ptr);
				break;
			case type_free_memory:
				share->result = KbFreeUserMemory(ptr);
				break;
			case type_suspend_process:
				share->result = KbSuspendProcess(ptr);
				break;
			case type_resume_process:
				share->result = KbResumeProcess(ptr);
				break;
			case type_create_thread:
				share->result = KbCreateUserThread(ptr);
				break;
			}
		}

		return STATUS_SUCCESS;
	}
}