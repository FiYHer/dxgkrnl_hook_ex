#pragma once
#include <ntddk.h>

namespace _dxhook
{
	// 获取系统模块基址
	void* get_system_module_base(const char* module_name);

	// 获取系统模块导出函数地址
	void* get_system_module_export(const char* module_name, const char* routine_name);

	// 写入只读内存地址
	bool write_to_read_only_memory(void* address, void* buffer, size_t size);

	// 开始挂钩
	void start_hook(void* function_address);

	// 处理者
	long handler(void* ptr);
}