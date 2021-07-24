#pragma once
#pragma warning(disable : 4311 4302)
#include <Windows.h>
#include <TlHelp32.h>
#include <winternl.h>
#include <stdint.h>
#include <stdio.h>

namespace _device
{
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

	HMODULE m_user32 = 0;
	HMODULE m_win32u = 0;
	unsigned int m_process_id = 0;

	bool attach_process(const wchar_t* name)
	{
		HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (snap == INVALID_HANDLE_VALUE) return false;

		PROCESSENTRY32W proc{ 0 };
		proc.dwSize = sizeof(proc);

		if (Process32FirstW(snap, &proc))
		{
			do
			{
				if (wcscmp(proc.szExeFile, name) == 0)
				{
					m_process_id = proc.th32ProcessID;
					CloseHandle(snap);
					return true;
				}
			} while (Process32NextW(snap, &proc));
		}

		CloseHandle(snap);
		return false;
	}
	bool attach_process(unsigned int process_id)
	{
		m_process_id = process_id;
		return true;
	}

	template<typename ... A>
	uint64_t call_hook(const A ... arguments)
	{
		void* control_function = GetProcAddress(m_win32u, "NtOpenCompositionSurfaceSectionInfo");
		if (control_function)
		{
			const auto control = static_cast<uint64_t(__stdcall*)(A...)>(control_function);
			if (control)
				return control(arguments ...);
		}
		return 10;
	}

	unsigned int get_version()
	{
		share_memory share{};
		memset(&share, 0, sizeof(share));
		share.type = type_get_version;
		call_hook(&share, NULL, NULL, 0);
		return share.version;
	}

	bool initialize()
	{
		m_user32 = LoadLibraryA("user32.dll");
		m_win32u = LoadLibraryA("win32u.dll");
		if (m_user32 == 0 || m_win32u == 0) return false;
		if (get_version()) return true;

		// mapping driver or load driver code .......

		return get_version();
	}

	bool read_fast_ex(unsigned long long address, unsigned long long buffer, unsigned int size)
	{
		share_memory share{};
		memset(&share, 0, sizeof(share));
		share.type = type_fast_memory_read;
		share.process_id = m_process_id;
		share.address = address;
		share.buffer = buffer;
		share.buffer_size = size;

		call_hook(&share, NULL, NULL, 0);
		return buffer;
	}

	bool write_fast_ex(unsigned long long address, unsigned long long value, unsigned int size)
	{
		share_memory share{};
		memset(&share, 0, sizeof(share));
		share.type = type_fast_memory_write;
		share.process_id = m_process_id;
		share.address = address;
		share.buffer = value;
		share.buffer_size = size;

		call_hook(&share, NULL, NULL, 0);
		return share.result == 0;
	}

	template <typename type>
	type read(unsigned long long address)
	{
		type buffer{};

		share_memory share{};
		memset(&share, 0, sizeof(share));
		share.type = type_memory_read;
		share.process_id = m_process_id;
		share.address = address;
		share.buffer = (unsigned long long) & buffer;
		share.buffer_size = sizeof(buffer);

		call_hook(&share, NULL, NULL, 0);
		return buffer;
	}

	template <typename type>
	bool write(unsigned long long address, type value)
	{
		share_memory share{};
		memset(&share, 0, sizeof(share));
		share.type = type_memory_write;
		share.process_id = m_process_id;
		share.address = address;
		share.buffer = (unsigned long long) & value;
		share.buffer_size = sizeof(value);

		call_hook(&share, NULL, NULL, 0);
		return share.result == 0;
	}

	bool read_ex(unsigned long long address, unsigned long long buffer, unsigned int size)
	{
		share_memory share{};
		memset(&share, 0, sizeof(share));
		share.type = type_memory_read;
		share.process_id = m_process_id;
		share.address = address;
		share.buffer = buffer;
		share.buffer_size = size;

		call_hook(&share, NULL, NULL, 0);
		return share.result == 0;
	}

	bool write_ex(unsigned long long address, unsigned long long value, unsigned int size)
	{
		share_memory share{};
		memset(&share, 0, sizeof(share));
		share.type = type_memory_write;
		share.process_id = m_process_id;
		share.address = address;
		share.buffer = value;
		share.buffer_size = size;

		call_hook(&share, NULL, NULL, 0);
		return share.result == 0;
	}

	void* write_string(unsigned long long address, void* str, unsigned int size)
	{
		share_memory share{};
		memset(&share, 0, sizeof(share));
		share.type = type_memory_write;
		share.process_id = m_process_id;
		share.address = address;
		share.buffer = (unsigned long long)str;
		share.buffer_size = size;

		call_hook(&share, NULL, NULL, 0);
		return str;
	}

	PROCESS_BASIC_INFORMATION get_process_information()
	{
		PROCESS_BASIC_INFORMATION basic{ 0 };
		share_memory share{};
		memset(&share, 0, sizeof(share));
		share.type = type_process_information;
		share.process_id = m_process_id;
		share.buffer = (unsigned long long) & basic;
		share.buffer_size = sizeof(basic);
		call_hook(&share, NULL, NULL, 0);
		return basic;
	}

	unsigned long long get_process_base_address()
	{
		PROCESS_BASIC_INFORMATION basic = get_process_information();
		if (basic.PebBaseAddress)
		{
			PEB peb = read<PEB>((unsigned long long)basic.PebBaseAddress);
			return (unsigned long long)peb.Reserved3[1];
		}

		return 0;
	}

	unsigned long long get_module_base_address(const wchar_t* name, unsigned int& size)
	{
		if (name == nullptr || wcslen(name) == 0) return 0;

		PROCESS_BASIC_INFORMATION pbi = get_process_information();
		if (pbi.PebBaseAddress == 0) return 0;

		PEB peb = read<PEB>((unsigned long long)pbi.PebBaseAddress);
		if (peb.Ldr == 0) return 0;

		PEB_LDR_DATA ldr = read<PEB_LDR_DATA>((unsigned long long)peb.Ldr);
		if (ldr.InMemoryOrderModuleList.Flink == 0) return 0;

		wchar_t str[0x100]{ 0 };
		wcscpy(str, name);
		_wcsupr(str);

		unsigned long long base = 0;
		LDR_DATA_TABLE_ENTRY entry{ 0 };
		LIST_ENTRY en{ 0 };
		struct _LIST_ENTRY* next = ldr.InMemoryOrderModuleList.Flink;
		do
		{
			if (next == 0) break;
			entry = read<LDR_DATA_TABLE_ENTRY>((unsigned long long)next);
			if (entry.DllBase == 0) break;
			if (entry.FullDllName.Buffer == 0) break;

			wchar_t buffer[0x100]{ 0 };
			read_ex((unsigned long long)entry.FullDllName.Buffer, (unsigned long long)buffer, entry.FullDllName.Length * 2);

			if (wcscmp(_wcsupr(buffer), str) == 0)
			{
				base = (unsigned long long)entry.Reserved2[0];
				size = (unsigned int)entry.DllBase;
				break;
			}

			en = read<LIST_ENTRY>((unsigned long long)next);
			if (en.Flink == 0) break;
			next = en.Flink;
		} while (next != ldr.InMemoryOrderModuleList.Flink);

		return base;
	}

	unsigned long long allocate_memory(unsigned int size)
	{
		share_memory share{};
		memset(&share, 0, sizeof(share));
		share.type = type_allocate_memory;
		share.process_id = m_process_id;
		share.buffer_size = size;
		call_hook(&share, NULL, NULL, 0);
		return share.address;
	}

	bool free_memory(unsigned long long address)
	{
		if (address == 0) return false;

		share_memory share{};
		memset(&share, 0, sizeof(share));
		share.type = type_free_memory;
		share.process_id = m_process_id;
		share.address = share.buffer = address;
		call_hook(&share, NULL, NULL, 0);
		return share.result == 0;
	}

	bool suspend_process()
	{
		share_memory share{};
		memset(&share, 0, sizeof(share));
		share.type = type_suspend_process;
		share.process_id = m_process_id;
		call_hook(&share, NULL, NULL, 0);
		return share.result == 0;
	}

	bool resume_process()
	{
		share_memory share{};
		memset(&share, 0, sizeof(share));
		share.type = type_resume_process;
		share.process_id = m_process_id;
		call_hook(&share, NULL, NULL, 0);
		return share.result == 0;
	}

	unsigned int create_thread(unsigned long long function, unsigned long long argment)
	{
		share_memory share{};
		memset(&share, 0, sizeof(share));
		share.type = type_create_thread;
		share.process_id = m_process_id;
		share.function_routine = function;
		share.function_argument = argment;
		call_hook(&share, NULL, NULL, 0);
		return share.thread_id;
	}
}