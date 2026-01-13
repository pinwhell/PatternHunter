#include "Arch/ARM64/Arm64CapstoneHelper.h"
#include "Arch/ARM64/Arm64CapstoneAux.h"
#include <capstone/capstone.h>

Arm64CapstoneHelper::Arm64CapstoneHelper()
{
	setArch(CS_ARCH_AARCH64);
	setMode(CS_MODE_ARM);
}

bool Arm64CapstoneHelper::PCRelInstAddrRebaseRoot()
{
	return false; 
}

bool Arm64CapstoneHelper::InterpretDispInst(cs_insn* pInst, uintptr_t& outDisp)
{    
    switch (pInst->id)
    {
    // Load Register (variants)
    case AArch64_INS_LDR:
    case AArch64_INS_LDRB:
    case AArch64_INS_LDRH:
    case AArch64_INS_LDRSB:
    case AArch64_INS_LDRSH:
    case AArch64_INS_LDRSW:
    // Store Register (variants)
    case AArch64_INS_STR:
    case AArch64_INS_STRB:
    case AArch64_INS_STRH:
    // Load/Store Pair
    case AArch64_INS_LDP:
    case AArch64_INS_LDPSW:
    case AArch64_INS_STP:
    {
        cs_aarch64* a64 = &pInst->detail->aarch64;
        // Memory operands are typically the last operand in asm syntax: LDR x0, [x1, #10]
        // Capstone stores operands in order. We look for type MEM.
        for (int i = 0; i < a64->op_count; i++)
        {
            if (a64->operands[i].type == AArch64_OP_MEM)
            {
                outDisp = (uintptr_t)a64->operands[i].mem.disp;
                return true;
            }
        }
    } break;

    // Arithmetic with Immediate (treated as displacement for pattern purposes sometimes)
    case AArch64_INS_ADD:
    case AArch64_INS_SUB:
    {
         cs_aarch64* a64 = &pInst->detail->aarch64;
         // ADD x0, x1, #imm
         // Look for the last operand being IMM
         if (a64->op_count > 0 && a64->operands[a64->op_count - 1].type == AArch64_OP_IMM)
         {
             outDisp = (uintptr_t)a64->operands[a64->op_count - 1].imm;
             return true;
         }
    } break;
    }

	return false;
}

bool Arm64CapstoneHelper::InterpretDispPCRelativeInst(cs_insn* pInstBegin, cs_insn* pInstEnd, uintptr_t& outDisp)
{
    // AArch64 PC-relative addressing is typically ADRP + ADD/LDR.
    // 1. ADRP Rd, #imm (Page base)
    // 2. ADD Rd, Rd, #imm (Page offset) OR LDR Rd, [Rd, #imm]

    if (pInstBegin->id == AArch64_INS_ADRP)
    {
        cs_aarch64* a64 = &pInstBegin->detail->aarch64;
        if (a64->op_count > 0 && a64->operands[0].type == AArch64_OP_REG && a64->operands[1].type == AArch64_OP_IMM)
        {
            int targetReg = a64->operands[0].reg;
            
            // ADRP: PageAlign(PC) + Imm 
            uint64_t pc = pInstBegin->address;
            uint64_t page = (pc & ~0xFFF) + a64->operands[1].imm; 
            
            // Scan forward for the consumer logic (ADD or LDR)
            for (cs_insn* pNext = pInstBegin + 1; pNext < pInstEnd; pNext++)
            {
                // Check for ADD Rd, Rd, #imm
                if (pNext->id == AArch64_INS_ADD)
                {
                    cs_aarch64* nextA64 = &pNext->detail->aarch64;
                    if (nextA64->op_count >= 3 && 
                        nextA64->operands[0].reg == targetReg && 
                        nextA64->operands[1].reg == targetReg && 
                        nextA64->operands[2].type == AArch64_OP_IMM)
                    {
                        outDisp = page + nextA64->operands[2].imm;
                        return true;
                    }
                }
                // Check for LDR Rt, [Rd, #imm]
                else if (pNext->id == AArch64_INS_LDR)
                {
                    cs_aarch64* nextA64 = &pNext->detail->aarch64;
                    if (nextA64->op_count >= 2 && 
                        nextA64->operands[1].type == AArch64_OP_MEM && 
                        nextA64->operands[1].mem.base == targetReg)
                    {
                        outDisp = page + nextA64->operands[1].mem.disp;
                        return true;
                    }
                }
                
                // TODO: Stop if the register is overwritten/clobbered before usage.
            }
            
            outDisp = page;
            return true;
        }
    }
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
    // STP x29, x30, [sp, #-N]! is the standard Frame Pointer setup
    if (pInst->id == AArch64_INS_STP)
    {
        cs_aarch64* a64 = &pInst->detail->aarch64;
        
        // STP Xt1, Xt2, [Xn, #imm]!
        // Expecting 3 operands: Reg, Reg, Mem (with writeback)
        if (a64->op_count == 3 &&
            a64->operands[0].type == AArch64_OP_REG && a64->operands[0].reg == AArch64_REG_X29 &&
            a64->operands[1].type == AArch64_OP_REG && a64->operands[1].reg == AArch64_REG_X30 &&
            a64->operands[2].type == AArch64_OP_MEM && a64->operands[2].mem.base == AArch64_REG_SP)
        {
            return true;
        }
    }
    
    // SUB SP, SP, #N (Allocating stack space)
    if (pInst->id == AArch64_INS_SUB)
    {
         cs_aarch64* a64 = &pInst->detail->aarch64;
         if (a64->op_count >= 3 && 
             a64->operands[0].type == AArch64_OP_REG && a64->operands[0].reg == AArch64_REG_SP &&
             a64->operands[1].type == AArch64_OP_REG && a64->operands[1].reg == AArch64_REG_SP &&
             a64->operands[2].type == AArch64_OP_IMM)
         {
             return true;
         }
    }
	return false;
}

bool Arm64CapstoneHelper::ContainsNonSolidOp(cs_insn* pInst, uint32_t* outResult, uint32_t toIgnoreNonSolidFlag, InstructionWildcardStrategy* pInstructionWildcard)
{
    // Implementation for ARM64: Wildcard relocatable addresses and branch targets.
    cs_aarch64* a64 = &(pInst->detail->aarch64);
    
    // ADRP (Address of Page: PC-relative)
    if (pInst->id == AArch64_INS_ADRP)
    {
        if (pInstructionWildcard)
        {
           // Wildcard all 4 bytes as the immediate is fragmented across the instruction.
           pInstructionWildcard->mTechnique.mWildcardedOffsets.clear();
           pInstructionWildcard->mSize = pInst->size; 
           for(int k=0; k<4; k++) pInstructionWildcard->mTechnique.mWildcardedOffsets.insert(k);
        }
        if(outResult) *outResult = NS_IMMDISP; 
        return true; 
    }

    // Unconditional Branches (B, BL)
    // Offset is imm26 (bits 0-25).
    // This bleeds into Byte 3 (bits 24-25).
    // Changing offset can change Byte 3 (e.g., 0x94 vs 0x97).
    // Must wildcard Bytes 0-3 to be robust.
    if ((pInst->id == AArch64_INS_B || pInst->id == AArch64_INS_BL) && 
        a64->op_count > 0 && 
        a64->operands[0].type == AArch64_OP_IMM)
    {
         if (pInstructionWildcard)
         {
              pInstructionWildcard->mTechnique.mWildcardedOffsets.clear();
              pInstructionWildcard->mSize = pInst->size;
              for(int k=0; k<4; k++) pInstructionWildcard->mTechnique.mWildcardedOffsets.insert(k);
         }
         if(outResult) *outResult = NS_IMMDISP;
         return true;
    }

    // Compare & Branch (CBZ, CBNZ)
    // Offset is imm19 (bits 5-23).
    // Fits strictly in Bytes 0, 1, 2. Byte 3 is safe Opcode.
    // Wildcard Bytes 0-2.
    if (pInst->id == AArch64_INS_CBNZ || pInst->id == AArch64_INS_CBZ)
    {
        for (int i = 0; i < a64->op_count; i++)
        {
            if (a64->operands[i].type == AArch64_OP_IMM)
            {
                 if (pInstructionWildcard)
                 {
                      pInstructionWildcard->mTechnique.mWildcardedOffsets.clear();
                      pInstructionWildcard->mSize = pInst->size;
                      pInstructionWildcard->mTechnique.mWildcardedOffsets.insert(0);
                      pInstructionWildcard->mTechnique.mWildcardedOffsets.insert(1);
                      pInstructionWildcard->mTechnique.mWildcardedOffsets.insert(2);
                 }
                 if(outResult) *outResult = NS_IMMDISP;
                 return true;
            }
        }
    }

    // LDR/STR with immediate offsets (Label access or PAGEOFF)
    // Relocation affects Offset (Bytes 1-2).
    // Register reallocation affects Base Reg (Bytes 0-1).
    // Example: STRB W8, [X20, #imm] vs STRB W8, [X19, #imm2]
    // To match consistently, we must wildcard Bytes 0, 1, and 2.
    // This preserves Opcode (Byte 3).
    // Includes LDR, LDRB, LDRH, LDRSW, STR, STRB, STRH.
    if ((pInst->id == AArch64_INS_LDR || pInst->id == AArch64_INS_LDRB || pInst->id == AArch64_INS_LDRH || pInst->id == AArch64_INS_LDRSW ||
         pInst->id == AArch64_INS_STR || pInst->id == AArch64_INS_STRB || pInst->id == AArch64_INS_STRH) &&
         a64->op_count > 0)
    {
         // Find if any operand is IMM (offset)
         bool hasImmOffset = false;
         for (int i = 0; i < a64->op_count; i++) 
         {
             // Capstone might show LDR x0, [x1, #imm] as MEM with disp.
             // OR LDR x0, #imm (Literal).
             if (a64->operands[i].type == AArch64_OP_MEM && a64->operands[i].mem.disp != 0) hasImmOffset = true;
             if (a64->operands[i].type == AArch64_OP_IMM) hasImmOffset = true;
         }

         if(hasImmOffset)
         {
             // Wildcard Bytes 0-2.
             if (pInstructionWildcard)
             {
                  pInstructionWildcard->mTechnique.mWildcardedOffsets.clear();
                  pInstructionWildcard->mSize = pInst->size;
                  pInstructionWildcard->mTechnique.mWildcardedOffsets.insert(0);
                  pInstructionWildcard->mTechnique.mWildcardedOffsets.insert(1);
                  pInstructionWildcard->mTechnique.mWildcardedOffsets.insert(2);
             }
             if(outResult) *outResult = NS_IMMDISP;
             return true;
         }
    }

    // Conditional Branch (B.cond)
    // Wildcard Bytes 0-2 to cover the 19-bit offset.
    // Note: This masks the Condition Code (bits 0-3 in Byte 0), so BEQ matches BNE.
    if (pInst->id == AArch64_INS_B && a64->cc != AArch64CC_Invalid)
    {
         if (pInstructionWildcard)
         {
              pInstructionWildcard->mTechnique.mWildcardedOffsets.clear();
              pInstructionWildcard->mSize = pInst->size;
              pInstructionWildcard->mTechnique.mWildcardedOffsets.insert(0);
              pInstructionWildcard->mTechnique.mWildcardedOffsets.insert(1);
              pInstructionWildcard->mTechnique.mWildcardedOffsets.insert(2);
         }
         if(outResult) *outResult = NS_IMMDISP;
         return true;
    }

    // Bit Test & Branch (TBZ, TBNZ)
    // Wildcard Bytes 0-2 to cover the interleaved 14-bit offset.
    // Note: Masks valid Register (bits 0-4) and partial Test Bit index.
    if (pInst->id == AArch64_INS_TBZ || pInst->id == AArch64_INS_TBNZ)
    {
         if (pInstructionWildcard)
         {
              pInstructionWildcard->mTechnique.mWildcardedOffsets.clear();
              pInstructionWildcard->mSize = pInst->size;
              pInstructionWildcard->mTechnique.mWildcardedOffsets.insert(0);
              pInstructionWildcard->mTechnique.mWildcardedOffsets.insert(1);
              pInstructionWildcard->mTechnique.mWildcardedOffsets.insert(2);
         }
         if(outResult) *outResult = NS_IMMDISP;
         return true;
    }

    // Arithmetic with Immediate (ADD/SUB)
    // Used in ADRL (ADRP + ADD) and likely address calculations.
    // Imm12 (bits 10-21) spans Byte 1 and Byte 2.
    // We wildcard Bytes 1 and 2 Usefully preserves Byte 0 (Rd + Rn low) and Byte 3 (Opcode).
    if ((pInst->id == AArch64_INS_ADD || pInst->id == AArch64_INS_SUB) &&
         a64->op_count > 0 && a64->operands[a64->op_count - 1].type == AArch64_OP_IMM)
    {
         if (pInstructionWildcard)
         {
              pInstructionWildcard->mTechnique.mWildcardedOffsets.clear();
              pInstructionWildcard->mSize = pInst->size;
              pInstructionWildcard->mTechnique.mWildcardedOffsets.insert(1);
              pInstructionWildcard->mTechnique.mWildcardedOffsets.insert(2);
         }
         if(outResult) *outResult = NS_IMMDISP;
         return true;
    }

    // MOV with Immediate (alias for MOVZ, MOVN, ORR)
    // Compiler flips between MOVZ (0x52...) and ORR (0x32...) based on optimization.
    // Example: MOV W8, #1 can be 28 00 80 52 (MOVZ) or E8 03 00 32 (ORR).
    // These have completely different opcodes. To match both, we must wildcard the whole instruction.
    // This is "noisy" but necessary if we want to validly match "Set Register to Constant" across builds.
    if ((pInst->id == AArch64_INS_MOV || pInst->id == AArch64_INS_MOVZ || pInst->id == AArch64_INS_MOVN || pInst->id == AArch64_INS_ORR) && 
        a64->op_count > 0 && 
        a64->operands[a64->op_count - 1].type == AArch64_OP_IMM)
    {
         if (pInstructionWildcard)
         {
              pInstructionWildcard->mTechnique.mWildcardedOffsets.clear();
              pInstructionWildcard->mSize = pInst->size;
              // Wildcard EVERYTHING (Bytes 0-3) because Opcode changes drastically (MOVZ vs ORR).
              for(int k=0; k<4; k++) pInstructionWildcard->mTechnique.mWildcardedOffsets.insert(k);
         }
         if(outResult) *outResult = NS_IMMDISP;
         return true;
    }

    return false;
}
