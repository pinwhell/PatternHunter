#include "ELFHelper.h"
#include <string.h>

bool ELFHelper::IsELF(unsigned char* base)
{
	if (base == nullptr)
		return false;

	return !memcmp(base, ELFMAG, SELFMAG);
}

bool ELFHelper::Is32(unsigned char* _base)
{
	union {
		Elf32_Ehdr* pElfBase;
		unsigned char* base;
	};

	base = _base;

	return pElfBase->e_ident[EI_CLASS] == ELFCLASS32;
}

bool ELFHelper::Is64(unsigned char* _base)
{
	union {
		Elf64_Ehdr* pElfBase;
		unsigned char* base;
	};

	base = _base;

	return pElfBase->e_ident[EI_CLASS] == ELFCLASS64;
}

uint64_t ELFHelper::GetFileOffset(unsigned char* base, uint64_t va)
{
	// Mask out the LSB (Thumb bit) just in case, as we mostly look for code/instruction starts.
	// For data it's usually aligned too, so this is generally safe for this tool's purpose.
	va &= ~1;

	if (!IsELF(base)) return -1;

	if (Is32(base))
	{
		Elf32_Ehdr* elfHdr = (Elf32_Ehdr*)base;
		Elf32_Phdr* pHdrs = (Elf32_Phdr*)(base + elfHdr->e_phoff);

		for (int i = 0; i < elfHdr->e_phnum; i++)
		{
			if (pHdrs[i].p_type == PT_LOAD)
			{
				if (va >= pHdrs[i].p_vaddr && va < (pHdrs[i].p_vaddr + pHdrs[i].p_filesz))
				{
					return va - pHdrs[i].p_vaddr + pHdrs[i].p_offset;
				}
			}
		}
	}
	else if (Is64(base))
	{
		Elf64_Ehdr* elfHdr = (Elf64_Ehdr*)base;
		Elf64_Phdr* pHdrs = (Elf64_Phdr*)(base + elfHdr->e_phoff);

		for (int i = 0; i < elfHdr->e_phnum; i++)
		{
			if (pHdrs[i].p_type == PT_LOAD)
			{
				if (va >= pHdrs[i].p_vaddr && va < (pHdrs[i].p_vaddr + pHdrs[i].p_filesz))
				{
					return va - pHdrs[i].p_vaddr + pHdrs[i].p_offset;
				}
			}
		}
	}

	return -1;
}
