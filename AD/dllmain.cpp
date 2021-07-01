#include <Windows.h>
#include <iostream>
#include <thread>
#include <vector>
#include <fstream>

#include <DbgHelp.h>
#pragma comment( lib, "dbghelp.lib" )

const auto base = reinterpret_cast<std::uint64_t>(GetModuleHandleA(nullptr));

std::uintptr_t convar_vtable;
std::uintptr_t concommand_vtable;

std::uint64_t data_section_addr;
std::size_t data_section_size;

std::uint64_t text_section_addr;
std::size_t text_section_size;

struct convar_info
{
	std::uintptr_t address;
	const std::string name;
	const std::string description;
};

struct segment
{
	std::string name = "";
	std::uintptr_t start_addr = 0;
	std::uintptr_t end_addr = 0;
	std::size_t size = 0;

	segment(HMODULE mod, const std::string& name_s)
	{
		name = name_s;

		const auto nt = ImageNtHeader(mod);
		auto section = reinterpret_cast<IMAGE_SECTION_HEADER*>(nt + 1);

		for (auto iteration = 0u; iteration < nt->FileHeader.NumberOfSections; ++iteration, ++section)
		{
			const auto segment_name = std::string(reinterpret_cast<const char*>(section->Name));

			if (segment_name == name)
			{
				start_addr = reinterpret_cast<std::uintptr_t>(mod) + section->VirtualAddress;
				size = section->Misc.VirtualSize;
				end_addr = start_addr + size;

				break;
			}
		}
	}
};

void scan_data()
{
	AllocConsole();

	FILE* file_stream;

	freopen_s(&file_stream, "CONIN$", "r", stdin);
	freopen_s(&file_stream, "CONOUT$", "w", stdout);
	freopen_s(&file_stream, "CONOUT$", "w", stderr);
	
	fclose(file_stream);

	SetConsoleTitleA("Dumper");

	std::vector<convar_info> convars;
	std::vector<convar_info> con_commands;
	
	auto file = std::ofstream("dump.txt");

	const auto text = segment(GetModuleHandleA(nullptr), ".text");
	const auto data = segment(GetModuleHandleA(nullptr), ".data");

	std::printf(
		"Found .text and .data Sections!\n"
		".text: %p\n"
		".data: %p\n\n\n",

		text.start_addr,
		data.start_addr
	);

	for (auto addr = text.start_addr; addr < text.end_addr; ++addr)
	{
		const auto bytes = reinterpret_cast<std::uint8_t*>(addr);

		//48 8D 05 ? ? ? ? 48 89 4C 24 50 ? ? ? 48 89 4C 24 48
		//48 8D 05 ? ? ? ? 48 89 01 ? ? ? 4C 89 49 18

		if (!convar_vtable && bytes[0] == 0x48 && bytes[1] == 0x8D && bytes[2] == 0x05 && bytes[7] == 0x48 && bytes[8] == 0x89 && bytes[17] == 0x4C && bytes[18] == 0x24 && bytes[19] == 0x48)
			convar_vtable = addr;

		if (!concommand_vtable && bytes[0] == 0x48 && bytes[1] == 0x8D && bytes[2] == 0x05 && bytes[7] == 0x48 && bytes[8] == 0x89 && bytes[9] == 0x01 && bytes[13] == 0x4C && bytes[16] == 0x18)
			concommand_vtable = addr;
	}

	convar_vtable = (convar_vtable + *reinterpret_cast<std::uint32_t*>(convar_vtable + 3) + 7);
	concommand_vtable = (concommand_vtable + *reinterpret_cast<std::uint32_t*>(concommand_vtable + 3) + 7);
	
	std::printf(
		"Found ConVar and ConCommand VTables!\n"
		"ConVar: %p\n"
		"ConCommand: %p\n\n\n",

		convar_vtable,
		concommand_vtable
	);

	for (auto addr = data.start_addr; addr < data.end_addr; addr += sizeof(std::uintptr_t))
	{
		const auto current_address = *reinterpret_cast<std::uint64_t*>(addr);

		if (current_address == convar_vtable || current_address == concommand_vtable)
		{
			const auto description = *reinterpret_cast<std::uintptr_t*>(addr + 0x20) && **reinterpret_cast<const char**>(addr + 0x20) ? *reinterpret_cast<const char**>(addr + 0x20) : "None";
			const auto name = *reinterpret_cast<std::uintptr_t*>(addr + 0x18) && **reinterpret_cast<const char**>(addr + 0x18) ? *reinterpret_cast<const char**>(addr + 0x18) : "Name error";
			const auto based_addr = addr - base;

			if (current_address == convar_vtable)
				convars.push_back({ based_addr, name, description });
			else
				con_commands.push_back({ based_addr, name, description });
		}
	}

	std::printf(
		"Scan Finished!\n"
		"ConVars Found: %llu\n"
		"ConCommands Found: %llu\n",

		convars.size(),
		con_commands.size()
	);

	if (convars.size())
	{
		file << "[CONVARS]\n{\n";
		for (const auto& cvar : convars)
		{
			file << "\t{\t\n\t\tName:\t\"" << cvar.name << "\"\n";
			file << "\t\tDescription:\t\"" << cvar.description << "\"\n";
			file << "\t\tAddress: 0x" << std::uppercase << std::hex << cvar.address << std::endl << "\t}\n" << std::endl;
		}
		file << "};\n";
	}

	if (con_commands.size())
	{
		file << "[CCOMMANDS]\n{\n";
		for (const auto& ccommand : con_commands)
		{
			file << "\t{\t\n\t\tName:\t\"" << ccommand.name << "\"\n";
			file << "\t\tDescription:\t\"" << ccommand.description << "\"\n";
			file << "\t\tAddress: 0x" << std::uppercase << std::hex << ccommand.address << std::endl << "\t}\n" << std::endl;
		}
		file << "};\n";
	}

}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
	if (ul_reason_for_call == DLL_PROCESS_ATTACH)
		std::thread(scan_data).detach();

    return TRUE;
}
