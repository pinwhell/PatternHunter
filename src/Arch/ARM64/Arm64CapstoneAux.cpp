#include "Arch/ARM64/Arm64CapstoneAux.h"

#include <capstone/capstone.h>

uint16_t Arm64CapstoneAux::GetLValueRegType(cs_insn* pInst)
{
    return pInst->detail->aarch64.operands[0].reg;
}

uint16_t Arm64CapstoneAux::GetRValueRegType(cs_insn* pInst)
{
    return pInst->detail->aarch64.operands[1].reg;
}

bool Arm64CapstoneAux::RegisterPresent(cs_insn* pInst, uint16_t reg)
{
    // Implementation needed based on RegisterPresent usage in ARM32 but adapted for ARM64 operands
    for (int i = 0; i != pInst->detail->aarch64.op_count; i++)
    {
        if (pInst->detail->aarch64.operands[i].reg == reg)
            return true;
    }
    return false;
}

bool Arm64CapstoneAux::HeuristicReturn(cs_insn* pInst)
{
    if (pInst->id == AArch64_INS_RET)
        return true;

    return false;
}
