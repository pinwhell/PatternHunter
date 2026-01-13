#include <iostream>

#include <cxxopts.hpp>
#include "BinaryFormatClassifier.h"
#include "FileHelper.h"
#include "ELFHelper.h"
#include <iomanip>
#include <sstream>
#include <TBS.hpp>

class PatternGeneration {
public:

	void setPatternBuff(const unsigned char* mPatternEntry, size_t patternSize);
	void setInstWildcardDescBook(InstructionSequenceWildcardBook& book);

	std::string GenerateCLiteralPattern();
	std::string GeneratePatternMask();
	std::string GeneratePatternWithMask();
private:
	std::vector<unsigned char> mPatternBuff;
	InstructionSequenceWildcardBook mInstWildcardDescBook;
};

int main(int argc, const char* argv[])
{
	cxxopts::Options options("Pattern Hunter", "Find Solid Patterns");

	options.allow_unrecognised_options();

	options.add_options()
		("f,file", "File to perform the pattern creation at", cxxopts::value<std::string>())
		("o,offset", "File offset at which the pattern creation will be performed", cxxopts::value<uint64_t>())
		("i,instructions", "Ammount of instruciton to process in the pattern creation", cxxopts::value<uint64_t>())
		("v,verbose", "Show more Info", cxxopts::value<bool>()->default_value("false"))
		("x,force", "Disable stoping at return related instrucitons", cxxopts::value<bool>()->default_value("false"))
		("a,va", "Treat offset as Virtual Address", cxxopts::value<bool>()->default_value("false"));

	auto result = options.parse(argc, argv);

	if (result.count("file") != 1 ||
		result.count("offset") != 1 ||
		result.count("instructions") != 1)
	{
		std::cout << options.help() << std::endl;
		return 1;
	}

	bool bVerbose = result["verbose"].as<bool>();
	bool bForce = result["force"].as<bool>();
	bool bIsVA = result["va"].as<bool>();

	std::vector<unsigned char> file;

	if (FileHelper::ReadFileBinary(result["file"].as<std::string>(), file) == false)
		return 1;

	uint64_t offset = result["offset"].as<uint64_t>();
	uint64_t instructions = result["instructions"].as<uint64_t>();

	if (bIsVA)
	{
		offset = ELFHelper::GetFileOffset(file.data(), offset);
		if (offset == (uint64_t)-1)
		{
			std::cout << "Invalid Virtual Address or unable to convert to File Offset" << std::endl;
			return 1;
		}
		if (bVerbose) std::cout << "Converted VA to Offset: 0x" << std::hex << offset << std::endl;
	}

	if (offset > file.size())
	{
		std::cout << "Offset out of range" << std::endl;
		return 1;
	}

	if (instructions > file.size())
	{
		std::cout << "Instruction Count out of range" << std::endl;
		return 1;
	}
	
	std::unique_ptr<IBinaryFormat> bin;

	if (BinaryFormatClassifier::Classify(file.data(), bin) == false)
		return 1;

	CapstoneHelperProvider capstoneHelperProvider;
	ICapstoneHelper* binCapstoneHelper;

	if (bin->MakeCapstoneHelper(&capstoneHelperProvider, &binCapstoneHelper) == false || binCapstoneHelper->Init() == false)
	{
		std::cout << "Unable to Initialize Capstone, Check File Type." << std::endl;
		return 1;
	}

	binCapstoneHelper->setBaseAddress(file.data());
	binCapstoneHelper->setBaseSize(file.size());

	size_t currInstCount = 0;
	size_t totalPatternSize = 0;

	InstructionSequenceWildcardBook wildcardBook;

	binCapstoneHelper->ForEachInstructionRel(offset, [&](cs_insn* pInst) {
	if (currInstCount++ >= instructions)
		return false;

	uint32_t foundNonSolid = 0;

	InstructionWildcardStrategy currInsWildcardStrategy;

	bool bIsNotSolidInst = binCapstoneHelper->ContainsNonSolidOp(pInst, &foundNonSolid, NS_IMMDISP, &currInsWildcardStrategy);

	if (bIsNotSolidInst == true)
	{
		currInsWildcardStrategy.mOffset = totalPatternSize;

		if (currInsWildcardStrategy.mTechnique.mWildcardedOffsets.size() == 0)
			std::cout << "\'" << pInst->mnemonic << "\'" << " Potentially Unimplemented\n";

		wildcardBook.mBook.push_back(currInsWildcardStrategy);
	}

	if(bVerbose)
		std::cout << "0x" << std::hex << pInst->address - (uint64_t)file.data() << ": " << std::left << std::setw(6) << pInst->mnemonic << " " << std::left << std::setw(18) << pInst->op_str;

	if (bIsNotSolidInst == true && bVerbose)
		std::cout << currInsWildcardStrategy;

	if(bVerbose)
		std::cout << std::endl;

	totalPatternSize += pInst->size;

	return binCapstoneHelper->IsIntructionReturnRelated(pInst) == false || bForce;
		});

	if(bVerbose)
		std::cout << "Full Pattern Size: 0x" << std::hex << totalPatternSize << std::endl;

	PatternGeneration patternGeneration;

	patternGeneration.setPatternBuff(file.data() + offset, totalPatternSize);
	patternGeneration.setInstWildcardDescBook(wildcardBook);

	//std::cout << patternGeneration.GenerateCLiteralPattern() << std::endl;
	//std::cout << patternGeneration.GeneratePatternMask() << std::endl;

	std::string patternResult = patternGeneration.GeneratePatternWithMask();

	TBS::Pattern::Results resultScan;

	std::cout << patternResult << std::endl;

	std::cout << "Checking Uniqueness...\n";

	TBS::Light::Scan(file.data(), file.data() + file.size(), resultScan, patternResult.c_str());

	if(resultScan.size() < 1)
		std::cout << "Pattern Not Found\n";
	else if(resultScan.size() > 1)
		std::cout << "Pattern With " << resultScan.size() << " Results\n";
	else
		std::cout << "Pattern Unique!\n";

	return 0;
}

void PatternGeneration::setPatternBuff(const unsigned char* mPatternEntry, size_t patternSize)
{
	mPatternBuff = std::vector<unsigned char>(mPatternEntry, mPatternEntry + patternSize);
}

void PatternGeneration::setInstWildcardDescBook(InstructionSequenceWildcardBook& book)
{
	mInstWildcardDescBook = book;
}

std::string ByteToByteStr(unsigned char byte)
{
	std::stringstream ss;

	ss << std::uppercase << std::setw(2) << std::setfill('0') << std::hex << (size_t)byte;

	return ss.str();
}

std::string PatternGeneration::GenerateCLiteralPattern()
{
	if (mPatternBuff.size() < 1)
		return "";

	std::string result = "";

	for (int i = 0; i < mPatternBuff.size(); i++)
	{
		result += "\\x" + (mInstWildcardDescBook.IsOffsetWildcard(i) ? "00" : ByteToByteStr(mPatternBuff[i]));
	}

	return result;
}

std::string PatternGeneration::GeneratePatternMask()
{
	if (mPatternBuff.size() < 1)
		return "";

	std::string mask(mPatternBuff.size(), 'x');

	for (const auto& instWildcardDesc : mInstWildcardDescBook.mBook)
	{
		for (size_t instWildcardOff : instWildcardDesc.mTechnique.mWildcardedOffsets)
		{
			mask[instWildcardDesc.mOffset + instWildcardOff] = '?';
		}
	}

	return mask;
}

std::string PatternGeneration::GeneratePatternWithMask()
{
	if (mPatternBuff.size() < 1)
		return "";

	std::string result = "";

	for (int i = 0; i < mPatternBuff.size(); i++)
	{
		result += (mInstWildcardDescBook.IsOffsetWildcard(i) ? "?" : ByteToByteStr(mPatternBuff[i]));

		if (i + 1 < mPatternBuff.size())
			result += " ";
	}

	return result;
}
