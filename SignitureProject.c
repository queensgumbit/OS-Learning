#include <windows.h>
#include <stdio.h>
#include <wchar.h>
#include <fileapi.h> // for the function SetFilePointer()
#include <bcrypt.h> //for CNG objects
#pragma comment(lib, "bcrypt")
#define BUFFER_SIZE 4096


//outside of main - blocks from the PE PARSER, struct PE FILE, DestroyPE , LoadPE and RvaToOffset.
typedef struct _PE_FILE {
    HANDLE   hFile;
    HANDLE   hMap;
    PBYTE    Base;       // pointer to start of file in memory
    SIZE_T   Size;       // file size

    IMAGE_DOS_HEADER*    DosHdr;    
    IMAGE_NT_HEADERS* NtHeader;
    IMAGE_SECTION_HEADER* Sections;
} PE_FILE, *PPE_FILE;


VOID DestroyPeFile(PPE_FILE pe) {
    if (!pe) return;
    if (pe->Base)  UnmapViewOfFile(pe->Base);
    if (pe->hMap)  CloseHandle(pe->hMap);
    if (pe->hFile) CloseHandle(pe->hFile);
    free(pe);
}


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


DWORD RvaToOfs(PPE_FILE pe, DWORD Rva) {
    WORD n = pe->NtHeader->FileHeader.NumberOfSections;
    for(int i = 0; i<n ;i++){
    DWORD sectionVA = pe->Sections[i].VirtualAddress; //virtual address
    DWORD sectionSize = max(pe->Sections[i].SizeOfRawData, pe->Sections[i].Misc.VirtualSize);   
    if(Rva >= sectionVA && Rva < sectionVA +sectionSize ){ //checks if the rva is located inside the virtual range of this section
        DWORD delta = Rva - sectionVA; 
        return pe->Sections[i].PointerToRawData +delta; // sectionHeaders[i].PointerToRawData - gives the offset to the raw data in the section and we add the delta to it.
    }
    } 
    fprintf(stderr, "Failed to find RVA offset for: 0x%X\n", Rva);
    return 0;
  }

//function that helps to hash specific portion of a file - from start byte to end byte(given as parameters)
void HashRange(HANDLE hFile, BCRYPT_HASH_HANDLE hHash, DWORD start,DWORD end){
    BYTE buffer[BUFFER_SIZE];
    DWORD bytesToRead;
    DWORD bytesRead;
    SetFilePointer(hFile, start, NULL, FILE_BEGIN);
    DWORD remaining = end - start;

    while(remaining > 0){
        bytesToRead = min(BUFFER_SIZE,remaining);
        if(!ReadFile(hFile, buffer, bytesToRead, &bytesRead,NULL) || bytesRead==0) break;
        //in the loop - figuring out how many bytes to read(bytesToRead) and read that much bytes into the buffer
        BCryptHashData(hHash , buffer, bytesRead , 0);// adding the data read to the hash
        remaining -= bytesRead;
    }
  }

int main(int argc,char* argv[]){ 
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <C:\\Users\\alexd\\Desktop\\Yasmin\\SignitureProject>\n", argv[0]); //stderr is standart error - output stream used to output error messages
        return 1;
    }
    char* pePath = argv[1]; 

    PPE_FILE pe = LoadPeFile(pePath);
    if (!pe) {
        fprintf(stderr, "Could not parse PE file headers.\n");
        return 1;
    }

    
    LPCSTR path = argv[1]; //LPCWSTR 32-bit pointer to a constant string of 16-bit
    //first step is to create an handle to the file 
    HANDLE hFile = CreateFileA(path,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "Cannot open %s: %08X\n", path, GetLastError()); //if the handle value is invalid we print the error, 8 chars.
        return 1;
    }
    //getting the check_sum offsets:
    DWORD CheckSumOffset = (DWORD)((BYTE*)&pe->NtHeader->OptionalHeader.CheckSum - pe->Base);
    DWORD CheckSumFiledSize = sizeof(DWORD);

    //need to get the certification table entry(which tell us where the signiture is stored) spesifications so i can skip over it while hashing:
    IMAGE_DATA_DIRECTORY certDir = pe->NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY]; //
    DWORD certDirOffset = (DWORD)((BYTE*)&pe->NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY] - pe->Base);
    DWORD certTableOffset = certDir.VirtualAddress;
    DWORD certTableSize = certDir.Size;

    // Initialize CNG SHA-256 - basiclly the hasing algoritm
    BCRYPT_ALG_HANDLE  hAlg  = NULL; //handle to the algoritm
    BCRYPT_HASH_HANDLE hHash = NULL; //handle for the hash
    NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg,BCRYPT_SHA256_ALGORITHM,NULL, 0);
    //NTSTUTUS - data type that stores a status code returned by windows api functions/
    //this call of function sets up the hashing engine so we can use it.

    if (status != 0) { //STUTUS_SUCESS indicates if the function was completed succesfully
        fprintf(stderr, "OpenAlgorithmProvider failed: %08X\n", status);
        CloseHandle(hFile);
        return 1;
    }

    status = BCryptCreateHash(hAlg, &hHash,NULL, 0,NULL, 0,0); 
    //the value of the third parameter is NULL and the value of the fourt parameter is zero, the memory for the hash object is allocated and freed by this function. 
    //the fifth parameter is null because when we calledBCrtpthAlgoritmProvider we didnt use the flag : BCRYPTH_ALG_HANDLE_HMAC_FLAG , just in this case this paramenetr could be other thqan NULL.

    if (status != 0) {
        fprintf(stderr, "CreateHash failed: %08X\n", status);
        BCryptCloseAlgorithmProvider(hAlg, 0); // give the handle for the alg and 0 for the second paramenter because there are no flags are defined for this function.
        CloseHandle(hFile);
        return 1;
    }

    HashRange(hFile, hHash , 0, CheckSumOffset); // hashing the file till checksum offsets
    HashRange(hFile, hHash,CheckSumOffset+CheckSumFiledSize,certTableOffset); //hashing from the end of check sum field tostart ofd cert table
    HashRange(hFile, hHash,certTableOffset+certTableSize,pe->Size);//hashing from the end of the certification table till the end of the file
    


    if (status == 0) { // after all the steps of setting up the hash
        DWORD hashLen = 0, cbNeeded = 0;
        status = BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH,(PUCHAR)&hashLen, sizeof hashLen,&cbNeeded, 0);
        /* function retrieves the value of a named property for a CNG object. 
        BCRYPT_HASH_LENGTH L"HashDigestLength" The size, in bytes, of the hash value of a hash provider. This data type is a DWORD.*/

        if (status == 0) {
            BYTE digest[32];
            status = BCryptFinishHash(hHash, digest, hashLen, 0); 
            /*BCryptFinishHash function retrieves the hash or Message Authentication Code (MAC) value for the data accumulated from prior calls to BCryptHashData.
            Returns a status code that indicates the success or failure of the function.*/
            if (status == 0) {
                for (DWORD i = 0; i < hashLen; i++) 
                    printf("%02x", digest[i]); //for loop from 0 to the length of the hash, printing each object inside digest array , 2 char output.
                printf("\n");
            } 
            else {
                fprintf(stderr, "FinishHash function failed: %08X\n", status);
            }
        }
        else {
            fprintf(stderr, "GetProperty function failed: %08X\n", status);
        }
    }

    if (hHash) BCryptDestroyHash(hHash);
    if (hAlg ) BCryptCloseAlgorithmProvider(hAlg, 0);

    return (status == 0) ? 0 : 1;
}

