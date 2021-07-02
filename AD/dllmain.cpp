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
std::uintptr_t chlclient_vtable;

std::uint64_t data_section_addr;
std::size_t data_section_size;

std::uint64_t text_section_addr;
std::size_t text_section_size;

struct client_class_info
{
	std::uintptr_t address;
	std::string name;
};

struct convar_info
{
	std::uintptr_t address;
	std::string name;
	std::string description;
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

std::vector<std::pair<std::uintptr_t, std::string>> inner_tables;

bool is_table_added(std::uintptr_t table)
{
	auto added = false;

	for (const auto& item : inner_tables)
	{
		if (item.second == *reinterpret_cast<const char**>(table + 0x4C8))
		{
			added = true;

			break;
		}
	}

	return added;
}

void walk_tables(std::uintptr_t table)
{
	const auto n_props = *reinterpret_cast<std::uint32_t*>(table + 0x10);

	if (n_props <= 1)
		return;

	if (!is_table_added(table))
		inner_tables.push_back(std::make_pair(table, *reinterpret_cast<const char**>(table + 0x4C8)));

	const auto props = *reinterpret_cast<std::uintptr_t**>(table + 0x8);

	for (auto i = 0u; i < n_props; ++i)
	{
		const auto prop = props[i];
		const auto new_table = *reinterpret_cast<std::uintptr_t*>(prop + 0x20);

		if (new_table)
		{
			const auto n_props = *reinterpret_cast<std::uint32_t*>(new_table + 0x10);

			if (n_props <= 1)
				continue;

			if (!is_table_added(new_table))
			{
				const std::string name = { *reinterpret_cast<const char**>(new_table + 0x4C8) };

				if (name.find("DT_") == 0)
				{
					inner_tables.push_back(std::make_pair(new_table, name));
					walk_tables(new_table);
				}
			}
		}
	}
}

void scan_data()
{
	AllocConsole();

	FILE* instances_stream;

	freopen_s(&instances_stream, "CONIN$", "r", stdin);
	freopen_s(&instances_stream, "CONOUT$", "w", stdout);
	freopen_s(&instances_stream, "CONOUT$", "w", stderr);
	
	fclose(instances_stream);

	SetConsoleTitleA("Dumper");

	std::vector<convar_info> convars;
	std::vector<convar_info> con_commands;
	std::vector<client_class_info> client_classes;
	
	auto instances = std::ofstream("dump.txt");
	auto netvars = std::ofstream("netvars.txt");

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

		//48 8D 05 ? ? ? ? 48 89 4C 24 50 ? ? ? 48 89 4C 24 48     convar_vtable
		//48 8D 05 ? ? ? ? 48 89 01 ? ? ? 4C 89 49 18              concommand_vtable
		//48 8D 15 ? ? ? ? 4C 8B 80 C8 03                          chlclient_vtable

		if (!convar_vtable && bytes[0] == 0x48 && bytes[1] == 0x8D && bytes[2] == 0x05 && bytes[7] == 0x48 && bytes[8] == 0x89 && bytes[17] == 0x4C && bytes[18] == 0x24 && bytes[19] == 0x48)
			convar_vtable = addr;

		if (!concommand_vtable && bytes[0] == 0x48 && bytes[1] == 0x8D && bytes[2] == 0x05 && bytes[7] == 0x48 && bytes[8] == 0x89 && bytes[9] == 0x01 && bytes[13] == 0x4C && bytes[16] == 0x18)
			concommand_vtable = addr;

		if (!chlclient_vtable && bytes[0] == 0x48 && bytes[1] == 0x8D && bytes[2] == 0x15 && bytes[7] == 0x4C && bytes[8] == 0x8B && bytes[9] == 0x80 && bytes[10] == 0xC8 && bytes[11] == 0x03)
			chlclient_vtable = addr;
	}

	convar_vtable = (convar_vtable + *reinterpret_cast<std::uint32_t*>(convar_vtable + 3) + 7);
	concommand_vtable = (concommand_vtable + *reinterpret_cast<std::uint32_t*>(concommand_vtable + 3) + 7);
	chlclient_vtable = (chlclient_vtable + *reinterpret_cast<std::uint32_t*>(chlclient_vtable + 3) + 7);
	
	std::printf(
		"Found ConVar, ConCommand and CHLClient VTables!\n"
		"ConVar: %p\n"
		"ConCommand: %p\n"
		"CHLClient: %p\n\n\n",

		convar_vtable,
		concommand_vtable,
		chlclient_vtable
	);

	const auto get_all_classes = *reinterpret_cast<std::uintptr_t*>(chlclient_vtable + 0x60);

	const auto client_class_head_ptr = (get_all_classes + *reinterpret_cast<std::uint32_t*>(get_all_classes + 3) + 7);

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

	auto current = *reinterpret_cast<std::uintptr_t*>(client_class_head_ptr);

	while (current)
	{
		client_classes.push_back({ current - base, *reinterpret_cast<const char**>(current + 0x10) });

		const auto table = *reinterpret_cast<std::uintptr_t*>(current + 0x18);

		if (table)
			walk_tables(table);

		current = *reinterpret_cast<std::uintptr_t*>(current + 0x20);
	}

	std::printf(
		"Scan Finished!\n"
		"ConVars Found: %llu\n"
		"ConCommands Found: %llu\n"
		"Client Classes Found: %llu\n",

		convars.size(),
		con_commands.size(),
		client_classes.size()
	);

	if (inner_tables.size())
	{
		for (const auto& tbl : inner_tables)
		{
			const auto table = tbl.first;

			const auto props = *reinterpret_cast<std::uintptr_t*>(table + 0x8);
			const auto n_props = *reinterpret_cast<std::uint32_t*>(table + 0x10);

			netvars << "Table Name: " << tbl.second << "\n\n";

			for (auto i = 0u; i < n_props; ++i)
			{
				const auto prop = *reinterpret_cast<std::uintptr_t*>(props + (i * 8));
				netvars << "NetVar: " << *reinterpret_cast<const char**>(prop + 0x28) << " | 0x" << std::hex << *reinterpret_cast<std::uint32_t*>(prop + 0x4) << "\n";
			}

			netvars << "\n\n\n";
		}
	}

	std::sort(convars.begin(), convars.end(), [](const convar_info& v1, const convar_info& v2)
	{
		return (_stricmp(v1.name.c_str(), v2.name.c_str()) < 0);
	});

	std::sort(con_commands.begin(), con_commands.end(), [](const convar_info& v1, const convar_info& v2)
	{
		return (_stricmp(v1.name.c_str(), v2.name.c_str()) < 0);
	});

	std::sort(client_classes.begin(), client_classes.end(), [](const client_class_info& v1, const client_class_info& v2)
	{
		return (_stricmp(v1.name.c_str(), v2.name.c_str()) < 0);
	});

	if (convars.size())
	{
		instances << "[CONVARS]\n{\n";
		for (const auto& cvar : convars)
		{
			instances << "\t{\t\n\t\tName:\t\"" << cvar.name << "\"\n";
			instances << "\t\tDescription:\t\"" << cvar.description << "\"\n";
			instances << "\t\tAddress: 0x" << std::uppercase << std::hex << cvar.address << std::endl << "\t}\n" << std::endl;
		}
		instances << "};\n";
	}

	if (con_commands.size())
	{
		instances << "[CONCOMMANDS]\n{\n";
		for (const auto& ccommand : con_commands)
		{
			instances << "\t{\t\n\t\tName:\t\"" << ccommand.name << "\"\n";
			instances << "\t\tDescription:\t\"" << ccommand.description << "\"\n";
			instances << "\t\tAddress: 0x" << std::uppercase << std::hex << ccommand.address << std::endl << "\t}\n" << std::endl;
		}
		instances << "};\n";
	}

	if (client_classes.size())
	{
		instances << "[CLIENT CLASSES]\n{\n";
		for (const auto& client_class : client_classes)
		{
			instances << "\t{\t\n\t\tName:\t\"" << client_class.name << "\"\n";
			instances << "\t\tAddress: 0x" << std::uppercase << std::hex << client_class.address << std::endl << "\t}\n" << std::endl;
		}
		instances << "};\n";
	}
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
	if (ul_reason_for_call == DLL_PROCESS_ATTACH)
		std::thread(scan_data).detach();

    return TRUE;
}
