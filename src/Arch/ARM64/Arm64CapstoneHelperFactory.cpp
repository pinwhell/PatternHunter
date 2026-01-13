#include "Arch/ARM64/Arm64CapstoneHelperFactory.h"
#include "Arch/ARM64/Arm64CapstoneHelper.h"

Arm64CapstoneHelperFactory::Arm64CapstoneHelperFactory()
{
}

ICapstoneHelper* Arm64CapstoneHelperFactory::MakeHelper()
{
    return new Arm64CapstoneHelper();
}
