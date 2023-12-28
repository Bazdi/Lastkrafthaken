#pragma once
#define WIN32_LEAN_AND_MEAN
#include <string>
#include <vector>
#include <Windows.h>
#include <psapi.h>

namespace lkh::Pattern {
	inline uintptr_t find(const uintptr_t pModuleBaseAddress, const char* sSignature, const bool relative = false, const int32_t offset = 0, const int32_t nSelectResultIndex = 0)
	{
		if (!pModuleBaseAddress) return 0;

		static auto patternToByte = [](const char* pattern)
			{
				auto       bytes = std::vector<int8_t>{};
				const auto start = const_cast<char*>(pattern);
				const auto end = const_cast<char*>(pattern) + strlen(pattern);

				for (auto current = start; current < end; ++current)
				{
					if (*current == '?')
					{
						++current;
						if (*current == '?')
							++current;
						bytes.push_back(-1);
					}
					else {
						bytes.push_back((int8_t)strtoul(current, &current, 16));
					}
				}
				return bytes;
			};

		const auto dosHeader = (PIMAGE_DOS_HEADER)pModuleBaseAddress;
		const auto ntHeaders = (PIMAGE_NT_HEADERS)((uint8_t*)pModuleBaseAddress + dosHeader->e_lfanew);

		const auto sizeOfImage = ntHeaders->OptionalHeader.SizeOfImage;
		const auto patternBytes = patternToByte(sSignature);

		const auto s = (uint32_t)patternBytes.size();
		const auto d = patternBytes.data();

		size_t nFoundResults = 0;

		const auto moduleBase = (int8_t*)pModuleBaseAddress;
		auto current = (int8_t*)pModuleBaseAddress;
		const auto end = (int8_t*)pModuleBaseAddress + sizeOfImage;
		MEMORY_BASIC_INFORMATION region = { };

		while (VirtualQuery(current, &region, sizeof region))
		{
			if (current > end)
			{
				break;
			}

			if (current < moduleBase)
			{
				current += region.RegionSize;
				continue;
			}

			if (region.Protect == 0 || (region.Protect & PAGE_NOACCESS) || (region.Protect & PAGE_GUARD))
			{
				current += region.RegionSize;
				continue;
			}

			const auto regionSize = static_cast<uint32_t>(region.RegionSize);
			if (regionSize <= s)
			{
				current += region.RegionSize;
				continue;
			}

			//printf("Scanning in page 0x%llx (%d)\n", (uintptr_t)current, regionSize);

			for (auto i = 0ul; i < regionSize - s; ++i)
			{
				bool found = true;

				for (auto j = 0ul; j < s; ++j)
				{
					if (current[i + j] != d[j] && d[j] != -1)
					{
						found = false;
						break;
					}
				}

				if (found)
				{
					if (nSelectResultIndex != 0)
					{
						if (nFoundResults < nSelectResultIndex)
						{
							nFoundResults++;                                   // Skip Result To Get nSelectResultIndex.
							found = false;                                     // Make sure we can loop again.
						}
						else
						{
							auto address = reinterpret_cast<uintptr_t>(&current[i]);
							if (relative)
								address = ((address + offset + 4) + *(int32_t*)(address + offset));
							return address;  // Result By Index.
						}
					}
					else
					{
						auto address = reinterpret_cast<uintptr_t>(&current[i]);
						if (relative)
							address = ((address + offset + 4) + *(int32_t*)(address + offset));
						return address;      // Default/First Result.
					}
				}
			}

			current += region.RegionSize;
		}

		return 0;
	}

	inline uintptr_t find(HMODULE module, const char* sSignature, const bool relative = false, const int32_t offset = 0, const int32_t nSelectResultIndex = 0)
	{
		return find(reinterpret_cast<uintptr_t>(module), sSignature, relative, offset, nSelectResultIndex);
	}

	inline uintptr_t find(const char* sSignature, const bool relative = false, const int32_t offset = 0, const int32_t nSelectResultIndex = 0)
	{
		return find(GetModuleHandle(nullptr), sSignature, relative, offset, nSelectResultIndex);
	}

	inline uintptr_t find_next_call(const uintptr_t funcAddr, const int32_t limit = 48)
	{
		if (!funcAddr) return 0;

		for (auto i = 1; i < limit; i++)
		{
			const auto addr = funcAddr + i;
			const auto byteValue = *(uint8_t*)addr;

			if (byteValue == 0xE8)
			{
				const auto offset = *(int32_t*)(addr + 1);
				return addr + 1 + 4 + offset;
			}
		}

		return 0;
	}
}