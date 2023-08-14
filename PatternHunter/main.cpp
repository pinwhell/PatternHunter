#include <iostream>

#include <cxxopts.hpp>

#include "BinaryFormatClassifier.h"
#include "FileHelper.h"
#include <iomanip>

int main(int argc, const char* argv[])
{
	cxxopts::Options options("Pattern Hunter", "Find Solid Patterns");

	options.allow_unrecognised_options();

	options.add_options()
		("f,file", "File to perform the pattern creation at", cxxopts::value<std::string>())
		("o,offset", "File offset at which the pattern creation will be performed", cxxopts::value<uint64_t>())
		("i,instructions", "Ammount of instruciton to process in the pattern creation", cxxopts::value<uint64_t>());

	auto result = options.parse(argc, argv);

	if (result.count("file") != 1 ||
		result.count("offset") != 1 ||
		result.count("instructions") != 1)
	{
		std::cout << options.help() << std::endl;
		return 1;
	}

	std::vector<unsigned char> file;

	if (FileHelper::ReadFileBinary(result["file"].as<std::string>(), file) == false)
		return 1;

	uint64_t offset = result["offset"].as<uint64_t>();
	uint64_t instructions = result["instructions"].as<uint64_t>();

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

	bool bIsNotSolidInst = binCapstoneHelper->ContainsNonSolidOp(pInst, &foundNonSolid, NS_IMM, &currInsWildcardStrategy);

	if (bIsNotSolidInst == true)
	{
		currInsWildcardStrategy.mOffset = totalPatternSize;
		wildcardBook.mBook.push_back(currInsWildcardStrategy);
	}

	std::cout << "0x" << std::hex << pInst->address - (uint64_t)file.data() << ": " << std::left << std::setw(6) << pInst->mnemonic << " " << std::left << std::setw(18) << pInst->op_str;

	if (bIsNotSolidInst == true)
	{
		std::cout << currInsWildcardStrategy;
	}

	std::cout << std::endl;

	totalPatternSize += pInst->size;

	return binCapstoneHelper->IsIntructionReturnRelated(pInst) == false;
		});

	std::cout << "Full Pattern Size: 0x" << std::hex << totalPatternSize << std::endl;

	return 0;
}