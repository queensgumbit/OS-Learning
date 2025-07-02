#include <stdio.h>
#include <stdlib.h>
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winnt.h>

typedef struct _PE_FILE {
    HANDLE   hFile;
    HANDLE   hMap;
    PBYTE    Base;       // pointer to start of file in memory
    SIZE_T   Size;       // file size

    IMAGE_DOS_HEADER*    DosHdr;    
    IMAGE_NT_HEADERS* NtHeader;
    IMAGE_SECTION_HEADER* Sections;
} PE_FILE, *PPE_FILE;

PPE_FILE LoadPeFile(PCHAR FilePath) {
    PPE_FILE pe = calloc(1, sizeof *pe);
    if(!pe){
        return NULL;
    }

    pe->hFile = CreateFileA(FilePath,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
    if (pe->hFile == INVALID_HANDLE_VALUE) goto fail;

    pe->hMap = CreateFileMappingA(pe->hFile,NULL,PAGE_READONLY,0, 0,NULL);
    if (!pe->hMap) goto fail;

    pe->Base = (PBYTE)MapViewOfFile(pe->hMap,FILE_MAP_READ,0,0,0);
    if (!pe->Base) goto fail;

    pe->Size = GetFileSize(pe->hFile, NULL);

    pe->DosHdr = (IMAGE_DOS_HEADER*)pe->Base;
    if (pe->DosHdr->e_magic != IMAGE_DOS_SIGNATURE) goto fail;
    pe->NtHeader = (IMAGE_NT_HEADERS*)(pe->Base + pe->DosHdr->e_lfanew);
    if (pe->NtHeader->Signature != IMAGE_NT_SIGNATURE) goto fail;
    pe->Sections = (IMAGE_SECTION_HEADER*)((PBYTE)&pe->NtHeader->OptionalHeader + pe->NtHeader->FileHeader.SizeOfOptionalHeader);
    return pe;

fail:
    DestroyPeFile(pe);
    return NULL;
}

VOID DestroyPeFile(PPE_FILE pe) {
    if (!pe) return;
    if (pe->Base)  UnmapViewOfFile(pe->Base);
    if (pe->hMap)  CloseHandle(pe->hMap);
    if (pe->hFile) CloseHandle(pe->hFile);
    free(pe);
}

DWORD RvaToOfs(PPE_FILE pe, DWORD Rva) {
    WORD n = pe->NtHeader->FileHeader.NumberOfSections;
    for(int i = 0; i<n ;i++){
    DWORD sectionVA = &pe->Sections[i].VirtualAddress; //virtual address
    DWORD sectionSize = max(&pe->Sections[i].SizeOfRawData, &pe->Sections[i].Misc.VirtualSize);   
    if(Rva >= sectionVA && Rva < sectionVA +sectionSize ){ //checks if the rva is located inside the virtual range of this section
        DWORD delta = Rva - sectionVA; 
        return &pe->Sections[i].PointerToRawData +delta; // sectionHeaders[i].PointerToRawData - gives the offset to the raw data in the section and we add the delta to it.
    }
    } 
    fprintf(stderr, "Failed to find RVA offset for: 0x%X\n", Rva);
    return 0;
  }

DWORD ShowImports(PPE_FILE pe) {
    DWORD ImportRva = pe->NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    DWORD importOffset = rvaToOffset(ImportRva, &pe->Sections);
    IMAGE_IMPORT_DESCRIPTOR *importDesc = (IMAGE_IMPORT_DESCRIPTOR*)(pe->Base + importOffset); 
    while (1) {
        if (importDesc->OriginalFirstThunk == 0 && importDesc->Name == 0)
        break;

        DWORD nameOffset = rvaToOffset(importDesc->Name, &pe->Sections); 
        if (nameOffset == 0) {
            fprintf(stderr, "Failed to convert Name RVA to offset: 0x%X\n", importDesc->Name);
            break;
        }
        printf("Reading DLL name RVA: 0x%X\n", importDesc->Name);

        char dllname[256];
        char* dllname = (char*)(pe->Base + importOffset);
        printf("DLL: %s\n", dllname);
    }
}


void PrintExports(PPE_FILE pe) {
    DWORD exportRVA = pe->NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress; //get the VA of exports, inside the ntheaders and then the optional header,dataDIR
    DWORD exportOffset = rvaToOffset(exportRVA, &pe->Sections); //use the function and get the export offset
    IMAGE_EXPORT_DIRECTORY exportDirectory;
    DWORD nameArrayOffset = rvaToOffset(exportDirectory.AddressOfNames, &pe->Sections);//gets nameArrayOffset - to know where the array begins to then start the curser there
    for (int i = 0; i < exportDirectory.NumberOfNames; i++) {
        DWORD nameRVA;
        DWORD functionNameOffset = rvaToOffset(nameRVA,  &pe->Sections); //get the offset of the function name

        char functionName[256];
        char* functionName = (char*)(pe->Base + functionNameOffset);
        printf("Exported Function: %s\n", functionName);
    }
}

    
int main(int argc, char** argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <pe-file>\n", argv[0]);
        return 1;
    }

    PPE_FILE pe = LoadPeFile(argv[1]);
    if (!pe) {
        fprintf(stderr, "Failed to load PE file\n");
        return 1;
    }

    ShowImports(pe);
    PrintExports(pe);

    DestroyPeFile(pe);
    return 0;
}

