#include "device.hpp"
#include <stdio.h>

void simple()
{
	system("pause");
	system("start regedit.exe");

	bool status = _device::initialize();
	printf("[+] initialize result is %d \n", status);
	if (!status) return;

	status = _device::attach_process(L"regedit.exe");
	printf("[+] attach_process result is : %d \n", status);
	if (!status) return;

	unsigned int version = _device::get_version();
	if (version) printf("[+] version is : %d \n", version);

	unsigned long long base = _device::get_process_base_address();
	if (base) printf("[+] process base address is : %llx \n", base);

	unsigned int size = 0;
	unsigned long long module_base = _device::get_module_base_address(L"regedit.exe", size);
	if (module_base) printf("[+] main module base is : %llx \n", module_base);

	IMAGE_DOS_HEADER dos{ 0 };
	_device::read_fast_ex(module_base, (unsigned long long) & dos, sizeof(dos));
	printf("[+] read fast ex is : %d \n", dos.e_magic);

	memset(&dos, 0, sizeof(dos));
	_device::read_ex(module_base, (unsigned long long) & dos, sizeof(dos));
	printf("[+] read ex is : %d \n", dos.e_magic);

	memset(&dos, 0, sizeof(dos));
	dos = _device::read<IMAGE_DOS_HEADER>(module_base);
	printf("[+] read is : %d \n", dos.e_magic);

	unsigned long long memory = _device::allocate_memory(0x100);
	if (memory) printf("[+] allocate memory is : %llx \n", memory);

	_device::suspend_process();
	_device::resume_process();
}

int main(int argc, char* argv[])
{
	simple();

	system("pause");
	return 0;
}