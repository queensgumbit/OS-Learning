#include <stdio.h>
#include <stdlib.h>
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winnt.h>

    IMAGE_DOS_HEADER dosHeader;
    IMAGE_NT_HEADERS ntHeaders;
    IMAGE_SECTION_HEADER sectionHeaders[100];
    IMAGE_IMPORT_BY_NAME importName[100];
    
    FILE *file; //declaring outside of all functions so that they could use it
    DWORD rvaToOffset(DWORD rva){
        for(int i = 0; i< ntHeaders.FileHeader.NumberOfSections;i++){
            DWORD sectionVA = sectionHeaders[i].VirtualAddress; //virtual address
            DWORD sectionSize = sectionHeaders[i].Misc.VirtualSize; //virtual size 
            
            if(rva >= sectionVA && rva < sectionVA +sectionSize ){ //checks if the rva is located inside the virtual range of this section
                DWORD delta = rva - sectionVA; 
                return sectionHeaders[i].PointerToRawData +delta; // sectionHeaders[i].PointerToRawData - gives the offset to the raw data in the section and we add the delta to it.
            }
        } 
        return 0; //not found
  }

    void printImports(DWORD importRVA) {
    DWORD importOffset = rvaToOffset(importRVA); //use the function and get the import offset
    fseek(file, importOffset, SEEK_SET);//put the curser of the file at the start, ranging across the import offset

    IMAGE_IMPORT_DESCRIPTOR importDesc; //declaration
    while (1) { 
        fread(&importDesc, sizeof(IMAGE_IMPORT_DESCRIPTOR), 1, file);//read the file - gets the address,size , how many blocks to read and the file.
        if (importDesc.OriginalFirstThunk == 0 && importDesc.Name == 0) //if the firstthunk and the name is 0 , means theer are no more imports, (DLLS end with 0)
            break;

        DWORD nameOffset = rvaToOffset(importDesc.Name); //use the function and get the offset of the certain import
        fseek(file, nameOffset, SEEK_SET); //put curser at the start of the file

        char dllname[256];
        fgets(dllname, sizeof(dllname), file); //reads a line/string of the file
        printf("DLL: %s\n", dllname);
    }
}


void printExports() {
    DWORD exportRVA = ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress; //get the VA of exports, inside the ntheaders and then the optional header,dataDIR
    DWORD exportOffset = rvaToOffset(exportRVA); //use the function and get the export offset
    fseek(file, exportOffset, SEEK_SET);//put the curser where the offset begins at the start of it

    IMAGE_EXPORT_DIRECTORY exportDirectory;
    fread(&exportDirectory, sizeof(IMAGE_EXPORT_DIRECTORY), 1, file); //read the file - gets the addr and the size,one block to read 

    DWORD nameArrayOffset = rvaToOffset(exportDirectory.AddressOfNames);//gets nameArrayOffset - to know where the array begins to then start the curser there
    for (int i = 0; i < exportDirectory.NumberOfNames; i++) {
        DWORD nameRVA;
        fseek(file, nameArrayOffset + i * sizeof(DWORD), SEEK_SET);//start the curser where the array begins
        fread(&nameRVA, sizeof(DWORD), 1, file);//read the file, geting the addr of the RVA of the name.

        DWORD functionNameOffset = rvaToOffset(nameRVA); //get the offset of the function name
        fseek(file, functionNameOffset, SEEK_SET);//put the curser to start wheere the offset begins

        char functionName[256];
        fgets(functionName, sizeof(functionName), file);//reads a line inside the file
        printf("Exported Function: %s\n", functionName);
    }
}

    
int main(){

    IMAGE_DATA_DIRECTORY importDirectory = ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    //so inside the ntheaders and then inside the optionalheader, 
    //the first in the array of data directory(idata) is the import table


    file = fopen("C:\\Windows\\System32\\notepad.exe", "rb"); //the exe i use is notepad
    if (!file) {
        printf("Failed to open file\n");
        return 1;
    }

    fread(&dosHeader, sizeof(IMAGE_DOS_HEADER), 1, file);
    if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) { //if the IMAGE_DOS_SIGNATURE does not start with MZ - magic value of PE files,its not valid
        printf("Not a valid PE file\n");
        return 1;
    }

    fseek(file, dosHeader.e_lfanew, SEEK_SET);//put the curser where the e_ifanew section is
    fread(&ntHeaders, sizeof(IMAGE_NT_HEADERS), 1, file);//read the file
    if (ntHeaders.Signature != IMAGE_NT_SIGNATURE) { //if the signature inside the ntHeaders does not match with the IMAGE_NT_SIGNATURE - its not valid
        printf("Not a valid PE file\n");
        return 1;
    }
 //print section headers
    fread(sectionHeaders, sizeof(IMAGE_SECTION_HEADER), ntHeaders.FileHeader.NumberOfSections, file);
    for (int i = 0; i < ntHeaders.FileHeader.NumberOfSections; i++) {
        printf("Section Header: %.8s\n", sectionHeaders[i].Name);
    }
//print the imports
    DWORD importRVA = ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (importRVA != 0)
        printImports(importRVA);
//print exports
    DWORD exportRVA = ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (exportRVA != 0) 
        printExports();

    fclose(file);//closing the fiel
    return 0;
}

