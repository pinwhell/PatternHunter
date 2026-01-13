#pragma once
#include "ICapstoneHelper.h"

class Arm64CapstoneHelper : public ICapstoneHelper
{
public:
	Arm64CapstoneHelper();

	bool PCRelInstAddrRebaseRoot() override;

	bool InterpretDispInst(cs_insn* pInst, uintptr_t& outDisp) override;
	bool InterpretDispPCRelativeInst(cs_insn* pInst, cs_insn* pInstEnd, uintptr_t& outDisp) override;
	bool GetCallDestinationInst(cs_insn* pInst, uintptr_t& outDest) override;
	bool IsIntructionReturnRelated(cs_insn* pInst) override;
	bool IsIntructionPrologRelated(cs_insn* pInst) override;
	bool ContainsNonSolidOp(cs_insn* pInst, uint32_t* outResult = nullptr, uint32_t toIgnoreNonSolidFlag = NS_IMMDISP, InstructionWildcardStrategy* pInstructionWildcard = nullptr) override;
};
