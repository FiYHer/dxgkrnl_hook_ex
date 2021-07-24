#include "dxgkrnl_hook.h"

VOID
Load()
{
	DbgPrintEx(0, 0, "[%s] Load Driver \n", __FUNCTION__);
	_dxhook::start_hook(_dxhook::handler);
}

EXTERN_C
NTSTATUS
DriverEntry(
	PDRIVER_OBJECT driver,
	PUNICODE_STRING reg)
{
	UNREFERENCED_PARAMETER(driver);
	UNREFERENCED_PARAMETER(reg);
	return STATUS_SUCCESS;
}