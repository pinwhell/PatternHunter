#pragma once

#include "IBinaryFormat.h"

class ELF64BinaryFormat : public IBinaryFormat
{
public:
	bool MakeCapstoneHelper(CapstoneHelperProvider* pProvider, ICapstoneHelper** outHelper) override;
};
