#include <windows.h>
#include <stdio.h>
#include <bcrypt.h> //for CNG objects
#pragma comment(lib, "bcrypt")



int wmain(int argc, wchar_t* argv[]) {
    if (argc != 2) {
        fwprintf(stderr, L"Usage: %s <path-to-exe>\n", argv[0]); //stderr is standart error - output stream used to output error messages
        return 1;
    }
    LPCWSTR path = argv[1]; //LPCWSTR 32-bit pointer to a constant string of 16-bit
    //first step is to create an handle to the file 
    HANDLE hFile = CreateFileW(path,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        fwprintf(stderr, L"Cannot open %s: %08X\n", path, GetLastError()); //if the handle value is invalid we print the error, 8 chars.
        return 1;
    }

    // 3) Initialize CNG SHA-256 - basiclly the hasing algoritm
    BCRYPT_ALG_HANDLE  hAlg  = NULL; //handle to the algoritm
    BCRYPT_HASH_HANDLE hHash = NULL; //handle for the hash
    NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg,BCRYPT_SHA256_ALGORITHM,NULL, 0);
    //NTSTUTUS - data type that stores a status code returned by windows api functions/
    //this call of function sets up the hashing engine so we can use it.

    if (status != STATUS_SUCCESS) { //STUTUS_SUCESS indicates if the function was completed succesfully
        fwprintf(stderr, L"OpenAlgorithmProvider failed: %08X\n", status);
        CloseHandle(hFile);
        return 1;
    }

    status = BCryptCreateHash(hAlg, &hHash,NULL, 0,NULL, 0,0); 
    //the value of the third parameter is NULL and the value of the fourt parameter is zero, the memory for the hash object is allocated and freed by this function. 
    //the fifth parameter is null because when we calledBCrtpthAlgoritmProvider we didnt use the flag : BCRYPTH_ALG_HANDLE_HMAC_FLAG , just in this case this paramenetr could be other thqan NULL.

    if (status != STATUS_SUCCESS) {
        fwprintf(stderr, L"CreateHash failed: %08X\n", st);
        BCryptCloseAlgorithmProvider(hAlg, 0); // give the handle for the alg and 0 for the second paramenter because there are no flags are defined for this function.
        CloseHandle(hFile);
        return 1;
    }

    BYTE  buffer[4096];
    DWORD bytesRead;
    while (ReadFile(hFile, buffer, sizeof buffer, &bytesRead, NULL) && bytesRead) {
        status = BCryptHashData(hHash, buffer, bytesRead, 0); //meanwhile reading the file we update the status by performing an one way hash.
        if (status != STATUS_SUCCESS) {
            fwprintf(stderr, L"HashData failed: %08X\n", status);
            break;
        }
    }
    CloseHandle(hFile);

    if (status == STATUS_SUCCESS) { // after all the steps of setting up the hash
        DWORD hashLen = 0, cbNeeded = 0;
        status = BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH,(PUCHAR)&hashLen, sizeof hashLen,&cbNeeded, 0);
        /* function retrieves the value of a named property for a CNG object. 
        BCRYPT_HASH_LENGTH L"HashDigestLength" The size, in bytes, of the hash value of a hash provider. This data type is a DWORD.*/

        if (status == STATUS_SUCCESS) {
            BYTE digest[32];
            status = BCryptFinishHash(hHash, digest, hashLen, 0); 
            /*BCryptFinishHash function retrieves the hash or Message Authentication Code (MAC) value for the data accumulated from prior calls to BCryptHashData.
            Returns a status code that indicates the success or failure of the function.*/
            if (status == STATUS_SUCCESS) {
                for (DWORD i = 0; i < hashLen; i++) 
                    printf("%02x", digest[i]); //for loop from 0 to the length of the hash, printing each object inside digest array , 2 char output.
                printf("\n");
            } 
            else {
                fwprintf(stderr, L"FinishHash function failed: %08X\n", status);
            }
        }
        else {
            fwprintf(stderr, L"GetProperty function failed: %08X\n", status);
        }
    }

    if (hHash) BCryptDestroyHash(hHash);
    if (hAlg ) BCryptCloseAlgorithmProvider(hAlg, 0);

    return (status == STATUS_SUCCESS) ? 0 : 1;
}

