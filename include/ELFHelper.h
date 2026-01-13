#pragma once

#include "ELF.h"

class ELFHelper
{
public:
	static bool IsELF(unsigned char* base);
	static bool Is32(unsigned char* base);
	static bool Is64(unsigned char* base);
	static uint64_t GetFileOffset(unsigned char* base, uint64_t va);
};

