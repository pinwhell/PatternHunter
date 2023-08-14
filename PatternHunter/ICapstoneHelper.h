#pragma once

#include <capstone/capstone.h>
#include <functional>
#include <unordered_set>
#include <vector>
#include <ostream>

#define NS_IMMDISP (1 << 1)
#define NS_REG  (1 << 2)

struct WildcardTechnique {
	/*a hashset about what bytes of the instruction should be wildcarded*/
	std::unordered_set<uint64_t> mWildcardedOffsets;

	/*a way to combine two wildcarding methods*/
	/*Ex. you may want to combine a NS_IMM Wildcardding with a NS_REG wildcarding*/
	WildcardTechnique operator+(const WildcardTechnique& rhs);

	WildcardTechnique();
	WildcardTechnique(std::initializer_list<uint64_t> initList);

	/*Combine another technique with us*/
	void operator+=(const WildcardTechnique& rhs);

	bool IsOffsetWildcard(size_t offset) const;
};

struct InstructionWildcardStrategy {
	/*In Reference to the start of the buffer containing the sequence of instructions bytes*/
	uint64_t mOffset;

	/*Instruction Size*/
	size_t mSize;

	/*A Variable Describing how to wildcard the instruciton*/
	WildcardTechnique mTechnique;
};

struct InstructionSequenceWildcardBook {
	/*A list of description of instruction wildcarding methods*/
	std::vector<InstructionWildcardStrategy> mBook;

	bool IsOffsetWildcard(size_t offset);
};

std::ostream& operator<<(std::ostream& os, const InstructionWildcardStrategy& instWildcardingStrat);

class ICapstoneHelper
{
private:
	csh mHandle = 0x0;

	cs_arch mArch;
	cs_mode mMode;

protected:

	const unsigned char* mpBase;
	size_t mBaseSize;

public:
	ICapstoneHelper();
	virtual ~ICapstoneHelper();

	virtual bool Init();

	void setArch(cs_arch arch);
	void setMode(cs_mode mode);

	virtual bool PCRelInstAddrRebaseRoot() = 0;

	bool TryGetCallDestination(const unsigned char* pInst, uintptr_t& outDest);
	virtual bool GetCallDestinationInst(cs_insn* pInst, uintptr_t& outDest) = 0;
	virtual bool IsIntructionReturnRelated(cs_insn* pInst) = 0;
	virtual bool IsIntructionPrologRelated(cs_insn* pInst) = 0;

	bool TryInterpretDisp(const unsigned char* pInst, uintptr_t& outDisp);
	bool TryInterpretDispPCRelative(cs_insn* pInst, uintptr_t& outDisp);
	virtual bool InterpretDispInst(cs_insn* pInst, uintptr_t& outDisp) = 0;
	virtual bool InterpretDispPCRelativeInst(cs_insn* pInst, cs_insn* pInstEnd, uintptr_t& outDisp) = 0;

	bool TryComputeParagraphSize(const unsigned char* pInst, uintptr_t& outSize);

	void setBaseAddress(unsigned char* base);
	void setBaseSize(size_t sz);

	void ForEachInstructionAbs(const unsigned char* startAt, std::function<bool(cs_insn* pInst)> callback);
	void ForEachInstructionRel(uint64_t baseOffset, std::function<bool(cs_insn* pInst)> callback);

	virtual bool ContainsNonSolidOp(cs_insn* pInst, uint32_t* outResult = nullptr, uint32_t toIgnoreNonSolidFlag = NS_IMMDISP, InstructionWildcardStrategy* pInstructionWildcard = nullptr);
};

