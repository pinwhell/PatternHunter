#pragma once
#include "ICapstoneHelperFactory.h"

class Arm64CapstoneHelperFactory : public ICapstoneHelperFactory
{
public:
    Arm64CapstoneHelperFactory();
    ICapstoneHelper* MakeHelper() override;
};
