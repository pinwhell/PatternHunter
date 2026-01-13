#include "ELF64BinaryFormat.h"
#include "Arch/ARM64/Arm64CapstoneHelperFactory.h"

bool ELF64BinaryFormat::MakeCapstoneHelper(CapstoneHelperProvider* pProvider, ICapstoneHelper** outHelper)
{
	if (outHelper == nullptr)
		return false;

	*outHelper = pProvider->getInstance(std::make_unique<Arm64CapstoneHelperFactory>());

	return *outHelper != nullptr;
}
