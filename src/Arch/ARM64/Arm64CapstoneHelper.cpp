#include "Arch/ARM64/Arm64CapstoneHelper.h"
#include "Arch/ARM64/Arm64CapstoneAux.h"
#include <capstone/capstone.h>

Arm64CapstoneHelper::Arm64CapstoneHelper()
{
	setArch(CS_ARCH_AARCH64);
	setMode(CS_MODE_ARM); // AArch64 uses 32-bit fixed instruction length, often referred to as ARM mode in contexts but capstone handles AArch64 specifically. 
    // Correction: Capstone CS_MODE_ARM is 0, CS_MODE_LITTLE_ENDIAN is 0. 
    // For AARCH64, mode usually defaults to little endian. 
    setMode(CS_MODE_LITTLE_ENDIAN); 
}

bool Arm64CapstoneHelper::PCRelInstAddrRebaseRoot()
{
	// AArch64 uses heavy PC-rel addressing (ADRP), so rebasing is often key.
    // Return true if we want the engine to attempt to rebase generic PC-rel logic? 
    // For now false to follow ARM32 pattern, but will likely need logic.
	return false; 
}

bool Arm64CapstoneHelper::InterpretDispInst(cs_insn* pInst, uintptr_t& outDisp)
{
    // Implementation for InterpretDispInst (LDR/STR with immediate offsets)
    // TODO: Implement specific AArch64 operand checks
	return false;
}

bool Arm64CapstoneHelper::InterpretDispPCRelativeInst(cs_insn* pInstBegin, cs_insn* pInstEnd, uintptr_t& outDisp)
{
    // Implementation for ADRP + LDR/ADD pair resolution
    // TODO: Implement
	return false;
}

bool Arm64CapstoneHelper::GetCallDestinationInst(cs_insn* pInst, uintptr_t& outDest)
{
    if (pInst->id == AArch64_INS_BL || pInst->id == AArch64_INS_B)
    {
         if(pInst->detail->aarch64.op_count > 0 && pInst->detail->aarch64.operands[0].type == AArch64_OP_IMM)
         {
             outDest = pInst->detail->aarch64.operands[0].imm;
             return true;
         }
    }
	return false;
}

bool Arm64CapstoneHelper::IsIntructionReturnRelated(cs_insn* pInst)
{
	return Arm64CapstoneAux::HeuristicReturn(pInst);
}

bool Arm64CapstoneHelper::IsIntructionPrologRelated(cs_insn* pInst)
{
    // STP x29, x30, [sp, #-N]! is typical prolog
    if (pInst->id == AArch64_INS_STP)
    {
        // Check if registers are FP(x29) and LR(x30)
        // Simplified check:
        // return Arm64CapstoneAux::IsProlog(pInst); // Need to implement helper
    }
	return false;
}

bool Arm64CapstoneHelper::ContainsNonSolidOp(cs_insn* pInst, uint32_t* outResult, uint32_t toIgnoreNonSolidFlag, InstructionWildcardStrategy* pInstructionWildcard)
{
    // Logic to detect wildcards (offsets, immediates)
    // Needs robust implementation for ADRP, LDR, ADD, etc.
    // Just a placeholder return false for now to allow compilation
    
    // Example basic check structure (similar to ARM32 but adapted)
    /*
    cs_aarch64* pArmInst = &(pInst->detail->aarch64);
    // Loop operands...
    */
    
	return false; 
}
