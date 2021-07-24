#pragma once
#include <ntddk.h>

namespace _dxhook
{
	// ��ȡϵͳģ���ַ
	void* get_system_module_base(const char* module_name);

	// ��ȡϵͳģ�鵼��������ַ
	void* get_system_module_export(const char* module_name, const char* routine_name);

	// д��ֻ���ڴ��ַ
	bool write_to_read_only_memory(void* address, void* buffer, size_t size);

	// ��ʼ�ҹ�
	void start_hook(void* function_address);

	// ������
	long handler(void* ptr);
}