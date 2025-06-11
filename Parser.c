#include <stdio.h>
#include <stdlib.h>
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winnt.h>

    IMAGE_DOS_HEADER dosHeader;
    IMAGE_NT_HEADERS ntHeaders;
    IMAGE_SECTION_HEADER* sectionHeaders;
    
    FILE *file; //declaring outside of all functions so that they could use it
    DWORD rvaToOffset(DWORD rva, IMAGE_SECTION_HEADER* sectionHeaders){
        for(int i = 0; i< ntHeaders.FileHeader.NumberOfSections;i++){
            DWORD sectionVA = sectionHeaders[i].VirtualAddress; //virtual address
            DWORD sectionSize = max(sectionHeaders[i].SizeOfRawData, sectionHeaders[i].Misc.VirtualSize);

            
            if(rva >= sectionVA && rva < sectionVA +sectionSize ){ //checks if the rva is located inside the virtual range of this section
                DWORD delta = rva - sectionVA; 
                return sectionHeaders[i].PointerToRawData +delta; // sectionHeaders[i].PointerToRawData - gives the offset to the raw data in the section and we add the delta to it.
            }
        } 
        fprintf(stderr, "Failed to find RVA offset for: 0x%X\n", rva);
        return 0;
  }


    void printImports(DWORD importRVA) {
        DWORD importOffset = rvaToOffset(importRVA, sectionHeaders);
         //use the function and get the import offset
 
        fseek(file, importOffset, SEEK_SET);//put the curser of the file at the start, ranging across the import offset

        IMAGE_IMPORT_DESCRIPTOR importDesc; //declaration
        int loopCounter = 0;
        while (1) {
            if (loopCounter++ > 100) break;
            fread(&importDesc, sizeof(IMAGE_IMPORT_DESCRIPTOR), 1, file);//read the file - gets the address,size , how many blocks to read and the file.
            if (importDesc.OriginalFirstThunk == 0 && importDesc.Name == 0)
                break;

            DWORD nameOffset = rvaToOffset(importDesc.Name, sectionHeaders); //use the function and get the offset of the certain import
            if (nameOffset == 0) {
                fprintf(stderr, "Failed to convert Name RVA to offset: 0x%X\n", importDesc.Name);
                break;
            }
            fseek(file, nameOffset, SEEK_SET); //put curser at the start of the file
            printf("Reading DLL name RVA: 0x%X\n", importDesc.Name);

            char dllname[256];
            fgets(dllname, sizeof(dllname), file); //reads a line/string of the file
            printf("DLL: %s\n", dllname);
    }
}


void printExports(IMAGE_SECTION_HEADER* sectionHeaders) {
    DWORD exportRVA = ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress; //get the VA of exports, inside the ntheaders and then the optional header,dataDIR
    DWORD exportOffset = rvaToOffset(exportRVA, sectionHeaders); //use the function and get the export offset
    

    fseek(file, exportOffset, SEEK_SET);//put the curser where the offset begins at the start of it

    IMAGE_EXPORT_DIRECTORY exportDirectory;
    fread(&exportDirectory, sizeof(IMAGE_EXPORT_DIRECTORY), 1, file); //read the file - gets the addr and the size,one block to read 

    DWORD nameArrayOffset = rvaToOffset(exportDirectory.AddressOfNames, sectionHeaders);//gets nameArrayOffset - to know where the array begins to then start the curser there
    for (int i = 0; i < exportDirectory.NumberOfNames; i++) {
        DWORD nameRVA;
        fseek(file, nameArrayOffset + i * sizeof(DWORD), SEEK_SET);//start the curser where the array begins
        fread(&nameRVA, sizeof(DWORD), 1, file);//read the file, geting the addr of the RVA of the name.

        DWORD functionNameOffset = rvaToOffset(nameRVA,  sectionHeaders); //get the offset of the function name
        fseek(file, functionNameOffset, SEEK_SET);//put the curser to start wheere the offset begins

        char functionName[256];
        fgets(functionName, sizeof(functionName), file);//reads a line inside the file
        printf("Exported Function: %s\n", functionName);
    }
}

    
int main(){
    printf("program started");
    file = fopen("testPE.exe", "rb");
    if (!file) {
        printf("Failed to open file\n");
        return 1;
    }
    printf("File opened successfully\n");
    fread(&dosHeader, sizeof(IMAGE_DOS_HEADER), 1, file);
    if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) { //if the e_magic does not start with MZ , its not valid
        printf("Not a valid PE file\n");
        return 1;
    }

    fseek(file, dosHeader.e_lfanew, SEEK_SET);// put the curser to the file where the e_ifanew field starts
    fread(&ntHeaders, sizeof(IMAGE_NT_HEADERS), 1, file); //read ntheaders
    if (ntHeaders.Signature != IMAGE_NT_SIGNATURE) {
        printf("Not a valid PE file\n");
        return 1;
    }

    //memory allocation once we have the ntHeaders number of sections
    sectionHeaders = malloc(sizeof(IMAGE_SECTION_HEADER) * ntHeaders.FileHeader.NumberOfSections);
    if (!sectionHeaders) {
        printf("Memory allocation failed\n");
        return 1;
    }

    fread(sectionHeaders, sizeof(IMAGE_SECTION_HEADER), ntHeaders.FileHeader.NumberOfSections, file); //reads the file sectionHeaders number of times and then puts each section header in the SectionHeaders array

    for (int i = 0; i < ntHeaders.FileHeader.NumberOfSections; i++) {
        printf("Section Header: %.8s\n", sectionHeaders[i].Name);
    }

    DWORD importRVA = ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (importRVA != 0)
        printImports(importRVA);

    DWORD exportRVA = ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (exportRVA != 0) 
        printExports(sectionHeaders);

    fclose(file);
    free( sectionHeaders); //free memory
    return 0;
}



