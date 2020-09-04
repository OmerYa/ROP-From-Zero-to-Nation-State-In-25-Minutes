
// Standard Include's
#include <iostream>

// Local Include's
#include "WritingTechniques.h"
#include "PinjectraPacket.h"
#include "DynamicPayloads.h"

class WriteProcessMemory_SetThreadContext :
	public ComplexMemoryWriter
{
public:
	// Constructor & Destructor
	WriteProcessMemory_SetThreadContext(DynamicPayload* rop_chain_gen) :
		m_rop_chain_gen(rop_chain_gen) { }

	~WriteProcessMemory_SetThreadContext();

	// Methods
	PINJECTRA_PACKET* eval_and_write(TARGET_PROCESS* target, TStrDWORD64Map& params);

protected:
	// Members
	DynamicPayload* m_rop_chain_gen;
};
#pragma once
