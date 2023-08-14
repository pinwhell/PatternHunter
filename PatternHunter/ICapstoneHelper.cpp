#include "ICapstoneHelper.h"

ICapstoneHelper::ICapstoneHelper()
{
    setMode(CS_MODE_LITTLE_ENDIAN);
}

ICapstoneHelper::~ICapstoneHelper()
{
    if (mHandle != 0x0)
        cs_close(&mHandle);
}

bool ICapstoneHelper::Init()
{
    if (cs_open(mArch, mMode, &mHandle) != CS_ERR_OK)
        return false;

    if (cs_option(mHandle, CS_OPT_DETAIL, CS_OPT_ON) != CS_ERR_OK)
        return false;

    return true;
}

void ICapstoneHelper::setArch(cs_arch arch)
{
    mArch = arch;
}

void ICapstoneHelper::setMode(cs_mode mode)
{
    mMode = mode;
}

bool ICapstoneHelper::TryGetCallDestination(const unsigned char* pInst, uintptr_t& outDest)
{
    cs_insn* pDisasmdInst = nullptr;
    uintptr_t count = 0;
    bool result = false;

    if ((count = cs_disasm(mHandle, pInst, 0x4, (uint64_t)(pInst), 0, &pDisasmdInst)) != 0 && pDisasmdInst) // Refactor code size in the future
    {
        result = GetCallDestinationInst(pDisasmdInst, outDest);
        cs_free(pDisasmdInst, count);
    }

    return result;
}


bool ICapstoneHelper::TryInterpretDisp(const unsigned char* pInst, uintptr_t& outDisp)
{
    cs_insn* pDisasmdInst = nullptr;
    uintptr_t count = 0;
    bool result = false;

    if ((count = cs_disasm(mHandle, pInst, 0x4, (uint64_t)(pInst), 0, &pDisasmdInst)) != 0 && pDisasmdInst)
    {
        result = InterpretDispInst(pDisasmdInst, outDisp);
        cs_free(pDisasmdInst, count);
    }

    return result;
}

bool ICapstoneHelper::TryInterpretDispPCRelative(cs_insn* pInst, uintptr_t& outDisp)
{
    cs_insn* pDisasmdInst = nullptr;
    uintptr_t count = 0;
    bool result = false;

    if ((count = cs_disasm(mHandle, (uint8_t*)pInst->address, 0x50, PCRelInstAddrRebaseRoot() ? (pInst->address - uintptr_t(mpBase)) : pInst->address, 0, &pDisasmdInst)) != 0 && pDisasmdInst)
    {
        result = InterpretDispPCRelativeInst(pDisasmdInst, pDisasmdInst + count, outDisp);
        cs_free(pDisasmdInst, count);
    }

    return result;
}

bool ICapstoneHelper::TryComputeParagraphSize(const unsigned char* pInst, uintptr_t& outSize)
{
    cs_insn pDisasmdInst{ 0 };
    cs_detail pDisasmdDetail{ 0 };
    pDisasmdInst.detail = &pDisasmdDetail;
    uintptr_t count = 0;
    bool result = false;
    uint64_t addr = (uint64_t)pInst;
    const unsigned char* pCurrInst = pInst;
    size_t szRem = ((size_t)mpBase + mBaseSize) - addr;

    bool bIsFirstProlog = true;

    while (cs_disasm_iter(mHandle, (const uint8_t**)&pCurrInst, &szRem, (uint64_t*)&addr, &pDisasmdInst))
    {
        result = true;

        outSize = (pDisasmdInst.address + pDisasmdInst.size) - (uint64_t)pInst;

        if (IsIntructionPrologRelated(&pDisasmdInst))
        {
            // if is not the first prolog it means a new one is starting
            // Maybe the function we are evaluating somehow got control out but without any return instructiuno signs
            if(bIsFirstProlog == false)
                break;

            bIsFirstProlog = false;
        }

        if (IsIntructionReturnRelated(&pDisasmdInst))
            break;
    }

    return result;
}

void ICapstoneHelper::setBaseAddress(unsigned char* base)
{
    mpBase = base;
}

void ICapstoneHelper::setBaseSize(size_t sz)
{
    mBaseSize = sz;
}

void ICapstoneHelper::ForEachInstructionAbs(const unsigned char* startAt, std::function<bool(cs_insn* pInst)> callback)
{
    cs_insn pDisasmdInst{ 0 };
    cs_detail pDisasmdDetail{ 0 };

    uint64_t addr = (uint64_t)startAt;
    const unsigned char* pCurrInst = startAt;
    size_t szRem = ((size_t)mpBase + mBaseSize) - addr;

    pDisasmdInst.detail = &pDisasmdDetail;

    while (cs_disasm_iter(mHandle, (const uint8_t**)&pCurrInst, &szRem, (uint64_t*)&addr, &pDisasmdInst))
    {
        if (callback(&pDisasmdInst) == false)
            break;
    }
}

void ICapstoneHelper::ForEachInstructionRel(uint64_t baseOffset, std::function<bool(cs_insn* pInst)> callback)
{
    ForEachInstructionAbs(mpBase + baseOffset, callback);
}

bool ICapstoneHelper::ContainsNonSolidOp(cs_insn* pInst, uint32_t* outResult, uint32_t toIgnoreNonSolidFlag, InstructionWildcardStrategy* p)
{
    return false;
}

WildcardTechnique WildcardTechnique::operator+(const WildcardTechnique& rhs)
{
    WildcardTechnique result;

    result += *this;
    result += rhs;

    return result;
}

WildcardTechnique::WildcardTechnique()
{
}

WildcardTechnique::WildcardTechnique(std::initializer_list<uint64_t> initList) : mWildcardedOffsets(initList) {}

void WildcardTechnique::operator+=(const WildcardTechnique& rhs)
{
    for (auto curr : rhs.mWildcardedOffsets)
        mWildcardedOffsets.insert(curr);
}

bool WildcardTechnique::IsOffsetWildcard(size_t offset) const 
{
    return mWildcardedOffsets.count(offset) > 0;
}

std::ostream& operator<<(std::ostream& os, const InstructionWildcardStrategy& instWildcardingStrat) {
    os << "{";

    std::vector<unsigned char> mask(instWildcardingStrat.mSize, 0);

    for (uint64_t instOffset : instWildcardingStrat.mTechnique.mWildcardedOffsets)
        mask[instOffset] = 1;

    for (int i = 0; i < mask.size(); i++)
    {
        os << (int)mask[i];

        if (i + 1 < mask.size())
            os << ",";
    }

    os << "}";

    return os;
}

bool InstructionSequenceWildcardBook::IsOffsetWildcard(size_t offset)
{
    for (const auto& instWildcardDesc : mBook)
    {
        if (instWildcardDesc.mOffset - offset < instWildcardDesc.mSize)
        {
            if (instWildcardDesc.mTechnique.IsOffsetWildcard(instWildcardDesc.mOffset - offset) == true)
                return true;
        }
    }
    return false;
}
