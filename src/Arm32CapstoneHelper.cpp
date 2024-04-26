#include "Arm32CapstoneHelper.h"
#include "CapstoneAux.h"

Arm32CapstoneHelper::Arm32CapstoneHelper()
{
	setArch(CS_ARCH_ARM);
	setMode(CS_MODE_ARM);
}

bool Arm32CapstoneHelper::PCRelInstAddrRebaseRoot()
{
	return false;
}

bool Arm32CapstoneHelper::InterpretDispInst(cs_insn* pInst, uintptr_t& outDisp)
{
    switch (pInst->id)
    {

    case ARM_INS_LDR:
    case ARM_INS_LDRH:
    case ARM_INS_LDRD:
    case ARM_INS_LDRB:
    case ARM_INS_LDRBT:
    case ARM_INS_LDREXB:
    {
        if (ArmCapstoneAux::GetRValueRegType(pInst) == ARM_REG_PC) return TryInterpretDispPCRelative(pInst, outDisp);
        else outDisp = pInst->detail->arm.operands[pInst->detail->arm.op_count - 1].mem.disp;
    } break;

    case ARM_INS_STR:
    case ARM_INS_STRH:
    case ARM_INS_STRB:
    case ARM_INS_STRD:
    case ARM_INS_STRBT:
    case ARM_INS_STREXB:
    {
        outDisp = pInst->detail->arm.operands[pInst->detail->arm.op_count - 1].mem.disp;
    } break;

    case ARM_INS_VLDR:
    case ARM_INS_VSTR:
    {
        outDisp = pInst->detail->arm.operands[pInst->detail->arm.op_count - 1].mem.disp;
    } break;

    case ARM_INS_ADD:
    {
        outDisp = pInst->detail->arm.operands[pInst->detail->arm.op_count - 1].imm;
    }break;

    case ARM_INS_MOV:
    case ARM_INS_MOVW:
    case ARM_INS_MOVT:
    {
        auto op = pInst->detail->arm.operands[pInst->detail->arm.op_count - 1];

        if (op.type == ARM_OP_IMM)
        {
            outDisp = op.imm;
            break;
        }
    }

    case ARM_INS_MVN:
    {
        auto op = pInst->detail->arm.operands[pInst->detail->arm.op_count - 1];

        if (op.type == ARM_OP_IMM)
        {
            outDisp = ~(op.imm);
            break;
        }
    }

    default:
        return false;
    }

    return true;
}

bool Arm32CapstoneHelper::InterpretDispPCRelativeInst(cs_insn* pInstBegin, cs_insn* pInstEnd, uintptr_t& outDisp)
{
    uint16_t regPcRelOffHolderType = ArmCapstoneAux::GetLValueRegType(pInstBegin);
    uintptr_t targetPcRelOff = ArmCapstoneAux::ResolvePCRelative((unsigned char*)pInstBegin->address, pInstBegin->detail->arm.operands[pInstBegin->detail->arm.op_count - 1].mem.disp);

    for (auto* pCurrInst = pInstBegin + 1; pCurrInst < pInstEnd; pCurrInst++)
    {

        switch (pCurrInst->id) {

        case ARM_INS_LDR:
        case ARM_INS_STR:
        {
            if (pCurrInst->detail->arm.operands[1].mem.base == ARM_REG_PC &&
                pCurrInst->detail->arm.operands[1].mem.index == regPcRelOffHolderType)
            {
                outDisp = (uintptr_t(pCurrInst->address) + 0x8 + targetPcRelOff) - uintptr_t(mpBase);

                return true;
            }
        }break;

        case ARM_INS_ADD:
        {
            if ((pCurrInst->detail->arm.operands[1].reg == ARM_REG_PC &&
                pCurrInst->detail->arm.operands[2].reg == regPcRelOffHolderType) ||
                (pCurrInst->detail->arm.operands[2].reg == ARM_REG_PC &&
                    pCurrInst->detail->arm.operands[1].reg == regPcRelOffHolderType))
            {
                outDisp = (uintptr_t(pCurrInst->address) + 0x8 + targetPcRelOff) - uintptr_t(mpBase);

                return true;
            }
        }break;

        }
    }

    return false;
}

bool Arm32CapstoneHelper::GetCallDestinationInst(cs_insn* pInst, uintptr_t& outDest)
{
    switch (pInst->id)
    {
    case ARM_INS_BL:
    case ARM_INS_B:
    {
        outDest = pInst->detail->arm.operands[0].imm;
        return true;
    }

    }
    return pInst->address;

    return false;
}

bool Arm32CapstoneHelper::IsIntructionReturnRelated(cs_insn* pInst)
{
    return ArmCapstoneAux::HeuristicReturn(pInst);
}

bool Arm32CapstoneHelper::IsIntructionPrologRelated(cs_insn* pInst)
{
    return ArmCapstoneAux::HeuristicProlog(pInst);
}

#define MKWILDCARD(type, ...) {type, { __VA_ARGS__ }},

std::unordered_map<arm_insn, WildcardTechnique> gImmDispWilcarding{
    MKWILDCARD(ARM_INS_ADD, 0)
    MKWILDCARD(ARM_INS_SUB, 0)

    MKWILDCARD(ARM_INS_MOV, 0, 1, 2)
    MKWILDCARD(ARM_INS_MOVW, 0, 1, 2)

    MKWILDCARD(ARM_INS_BL, 0, 1, 2)
    MKWILDCARD(ARM_INS_B, 0, 1, 2)

    MKWILDCARD(ARM_INS_LDR, 0, 1)
    MKWILDCARD(ARM_INS_LDRB, 0, 1)

    MKWILDCARD(ARM_INS_STR, 0, 1)

    MKWILDCARD(ARM_INS_CMP, 0, 1)
    MKWILDCARD(ARM_INS_TST, 0, 1)
};

std::unordered_map<arm_insn, WildcardTechnique> gRegWilcarding{
    MKWILDCARD(ARM_INS_ADD, 1, 2)
    MKWILDCARD(ARM_INS_SUB, 1, 2)

    MKWILDCARD(ARM_INS_MOV, 1)
    MKWILDCARD(ARM_INS_MOVW, 1)

    MKWILDCARD(ARM_INS_BL)
    MKWILDCARD(ARM_INS_B)

    MKWILDCARD(ARM_INS_LDR, 1, 2)
    MKWILDCARD(ARM_INS_LDRB, 1, 2)

    MKWILDCARD(ARM_INS_STR, 1, 2)

    MKWILDCARD(ARM_INS_CMP, 3)
    MKWILDCARD(ARM_INS_TST, 3)
};

WildcardTechnique GetImmDispWildcardTechArmIsnt(arm_insn type)
{
    if (gImmDispWilcarding.find(type) == gImmDispWilcarding.end())
        return WildcardTechnique();

    return gImmDispWilcarding[type];
}

WildcardTechnique GetRegWildcardTechArmIsnt(arm_insn type)
{
    if (gRegWilcarding.find(type) == gRegWilcarding.end())
        return WildcardTechnique();

    return gRegWilcarding[type];
}

bool Arm32CapstoneHelper::ContainsNonSolidOp(cs_insn* pInst, uint32_t* outResult, uint32_t toIgnoreNonSolidFlag, InstructionWildcardStrategy* pInstWildcardStrategy)
{
    cs_arm* pArmInst = &(pInst->detail->arm);

    if (pInstWildcardStrategy)
    {
        *pInstWildcardStrategy = InstructionWildcardStrategy();

        pInstWildcardStrategy->mSize = pInst->size;
    }

    if (pArmInst->op_count < 1)
        return false;

    uint32_t alredyFoundNonSolid = 0;

    for (int i = 0; i < pArmInst->op_count; i++)
    {
        cs_arm_op* currOp = pArmInst->operands + i;

        /*If called want to check for given nonsolid, and it hasnt alredy been found*/
        if ((toIgnoreNonSolidFlag & NS_IMMDISP) && ((alredyFoundNonSolid & NS_IMMDISP) == 0))
        {
            do {

                if ((currOp->type == ARM_OP_MEM && currOp->mem.disp != 0 ||
                    currOp->type == ARM_OP_IMM) == false)
                    break;
                
                alredyFoundNonSolid |= NS_IMMDISP;

                if (pInstWildcardStrategy)
                    pInstWildcardStrategy->mTechnique += GetImmDispWildcardTechArmIsnt((arm_insn)pInst->id);

                continue;
            } while (false);
        }

        /*If called want to check for given nonsolid, and it hasnt alredy been found*/
        if ((toIgnoreNonSolidFlag & NS_REG) && ((alredyFoundNonSolid & NS_REG) == 0))
        {
            if (currOp->type == ARM_OP_REG)
            {
                alredyFoundNonSolid |= NS_REG;

                if (pInstWildcardStrategy)
                    pInstWildcardStrategy->mTechnique += GetRegWildcardTechArmIsnt((arm_insn)pInst->id);

                continue;
            }
        }
    }

    if (outResult)
        *outResult = alredyFoundNonSolid;

    return alredyFoundNonSolid != 0;
}
