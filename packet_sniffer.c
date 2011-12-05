/*------------------------------------------------------------------------------
 * Max Guo
 * December 5, 2011
 * Packet Sniffer
 *----------------------------------------------------------------------------*/

/*------------------------------------------------------------------------------
 * TODO: - Some annoying warnings left
 *       - dumbed down version of something I did over the summer, got rid of
 *             a lot of proprietary stuff, might have broken something,
 *             and considering I don't own a Windows computer, it'll be hard
 *             to find anytime to work on this anymore
 *----------------------------------------------------------------------------*/

/*------------------------------------------------------------------------------
 * USAGE: - code first written in Microsoft Visual Studio 2005 and reworked in
 *              Microsoft Visual Studio 2010
 *        - slightly formatted on a Mac computer, therefore format might be
 *              messed up if opened on a PC
 *        - must have multithreading enabled in project settings
 *        - incorporates the Ring Buffer
 *----------------------------------------------------------------------------*/

#include <stdio.h>                                  //standard i/o
#include <winsock2.h>                               //for socket programming to capture ethernet data
#include <process.h>                                //for multithreading
#include <windows.h>                                //for semaphores
#include <conio.h>                                  //for checking keyboard hits
#include <time.h>                                   //for creating dynamic file names
#include "ring_buf.h"                               //circular buffer

#define SIO_RCVALL _WSAIOW(IOC_VENDOR, 1)           //removes the need for mstcpip.h
#define DATA_SIZE 500                               //size of data packet
#define CIRC_BUF_SIZE 33554432                      //33554432 (2^25), 2097152 (2^21), 524288 (2^19), 4096 (2^12)

int InitSocket();                                   //preps socket
void CheckKeyPress(void*);                          //checks for keypress
void StartSniffing(void*);                          //captures data
void ProcessData(void*);                            //processes data

SOCKET sniffer;                                     //socket to grab data
errno_t err;                                        //for error handling when opening files
time_t rawtime;                                     //for timestamping files
struct tm *timeinfo;                                //for timestamping files
HANDLE handle_capture;                              //handles capture thread
HANDLE handle_processing;                           //handles processing thread
HANDLE handle_semaphore;                            //handles semaphore for shared buffer
HANDLE handle_keypress;                             //handles checking for keypress
ring_buffer *shared_buf;                            //shared memory
int kbhit_flag = 0;                                 //0 if keyboard is not hit, 1 if keyboard is hit
int num_bytes_read = 1;                             //number of bytes read from ethernet connection

/*------------------------------------------------------------------------------
 * main() method - opens up a connection to sniff data then spawns three threads, one to capture data, the other thread
 *                 to process the data, and the third to check for a keyboard press
 * inputs:
 *     none
 * returns:
 *     int -   0 on successful execution
 *             1 if error occurs
 *----------------------------------------------------------------------------*/
int main() {
    if (InitSocket()) {                             //open Ethernet port
        printf("InitSocket() error.\n");
        return 1;
    }
    
    shared_buf = create_buf(CIRC_BUF_SIZE);
    handle_semaphore = CreateSemaphore(NULL, 1, 1, NULL);                       //create semaphore
    if (handle_semaphore == NULL) {
        printf("CreateSemaphore() failed.\n");
        return 1;
    }
    
    handle_capture = (HANDLE)_beginthread(StartSniffing, 0, (void *)sniffer);   //data capture thread
    handle_processing = (HANDLE)_beginthread(ProcessData, 0, NULL);             //data processing thread
    handle_keypress = (HANDLE)_beginthread(CheckKeyPress, 0, NULL);             //check keypress thread

    WaitForSingleObject(handle_capture, INFINITE);                              //allow capture thread to finish
    WaitForSingleObject(handle_processing, INFINITE);                           //allow processing thread to finish
    WaitForSingleObject(handle_keypress, 0);                                    //allow checking thread to finish

    CloseHandle(handle_capture);
    CloseHandle(handle_processing);
    CloseHandle(handle_keypress);
    CloseHandle(handle_semaphore);
    return 0;
}

/*------------------------------------------------------------------------------
 * InitSocket() method - initializes socket connected to ethernet port
 * inputs:
 *     none
 * returns:
 *     int - 0 on successful execution
 *           1 if error occurs
 *----------------------------------------------------------------------------*/
int InitSocket() {
    struct in_addr addr;
    struct sockaddr_in dest;
    DWORD in;
    int i;
    int j;
    char hostname[100];
    struct hostent *local;
    WSADATA wsa;

    //initialize winsock
    printf("Initializing Winsock... ");
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        printf("WSAStartup() failed.\n");
        return 1;
    }
    printf("Initialized.\n");

    //create a raw socket
    printf("Creating Socket... ");
    sniffer = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sniffer == INVALID_SOCKET) {
        printf("Failed to create socket.\n");
        return 1;
    }
    printf("Created.\n");

    //retrieve the local hostname
    if (gethostname(hostname, sizeof(hostname)) == SOCKET_ERROR) {
        printf("Error: %d\n", WSAGetLastError());
        return 1;
    }
    printf("Host name: %s\n", hostname);

    //retrieve the available IPs of the local host
    local = gethostbyname(hostname);
    printf("\nAvailable Network Interfaces:\n");
    if (local == NULL) {
        printf("Error: %d\n", WSAGetLastError());
        return 1;
    }
    for (i = 0; local->h_addr_list[i] != 0; i++) {
        memcpy(&addr, local->h_addr_list[i], sizeof(struct in_addr));
        printf("Interface Number: %d Address: %s\n", i, inet_ntoa(addr));
    }
    printf("\nEnter the interface number you would like to sniff: ");
    scanf_s("%d", &in);
    memset(&dest, 0, sizeof(dest));
    memcpy(&dest.sin_addr.s_addr, local->h_addr_list[in], sizeof(dest.sin_addr.s_addr));
    dest.sin_family = AF_INET;
    dest.sin_port = 0;

    //bind socket
    printf("Binding socket to local system... ");
    if (bind(sniffer, (struct sockaddr *)&dest, sizeof(dest)) == SOCKET_ERROR) {
        printf("bind(%s) failed.\n", inet_ntoa(addr));
        return 1;
    }
    printf("Binding successful.\n");

    //enable this socket with the power to sniff: SIO_RCVALL is the key, receives all
    j = 1;
    printf("Setting socket to sniff... ");
    if (WSAIoctl(sniffer, SIO_RCVALL, &j, sizeof(j), 0, 0, &in, 0, 0) == SOCKET_ERROR) {
        printf("WSAIoctl() failed.\n");
        return 1;
    }
    printf("Socket set.\n\n");
    return 0;
}

/*------------------------------------------------------------------------------
 * CheckKeyPress() method - checks for a key press to stop data capture
 * inputs:
 *     void *v - NULL, present because _beginthread() in main() requires a third argument, not used
 * returns:
 *     void - no return value
 *----------------------------------------------------------------------------*/
void CheckKeyPress(void *v) {
    while (1) {
        if (_kbhit()) {
            kbhit_flag = 1;
            _getch();
        }
    }
}

/*------------------------------------------------------------------------------
 * StartSniffing() method - data capture method, sniffs data from input socket
 * inputs:
 *     void *sniffer - socket to sniff for data
 * returns:
 *     void - no return value
 *----------------------------------------------------------------------------*/
void StartSniffing(void *sniffer) {
    char *Buffer = (char *)malloc(DATA_SIZE);

    if (Buffer == NULL) {
        printf("Buffer malloc() failed.\n");
        return;
    }

    printf("Capturing... Press any key to stop capturing.\n\n");
    while (num_bytes_read) {
        if (kbhit_flag) {                                   //check to see if kbhit_flag is set
            printf("Capturing stopped. Finishing data processing.\n");
            break;
        }

        num_bytes_read = recvfrom((SOCKET)sniffer, Buffer, DATA_SIZE, 0, 0, 0);
        if (num_bytes_read <= 0) {
            printf("recvfrom() failed.\n");
            break;
        } else {
            WaitForSingleObject(handle_semaphore, 0);
            write_to_buf(shared_buf, Buffer, sizeof(Buffer));
            ReleaseSemaphore(handle_semaphore, 1, NULL);
        }
    }

    //cleanup
    free(Buffer);
    closesocket((SOCKET)sniffer);
    WSACleanup();
    _endthread();
}

/*------------------------------------------------------------------------------
 * ProcessData() method - data process method, allows for live data analysis
 * inputs:
 *     void *v - NULL, present because _beginthread() in main() requires a third argument, not used
 * returns:
 *     void - no return value
 *----------------------------------------------------------------------------*/
void ProcessData(void *v) {
    int size;
    char filename[24];
    FILE *logfile;
    char *temp_data = (char *)malloc(DATA_SIZE);
    int success = 0;

    //save data into dynamic filename so it won't overwrite previous files
    time(&rawtime);
    timeinfo = localtime(&rawtime);
    strftime(filename, sizeof(filename), "log_%Y%m%d_%H%M%S.bin", timeinfo);
    filename[23] = '\0';

    if ((err = fopen_s(&logfile, filename, "wb")) != 0) {
        printf("Unable to create file %s.\n", filename);
        return;
    }

    WaitForSingleObject(handle_capture, 0);
    WaitForSingleObject(handle_semaphore, 0);
    success = read_buf(shared_buf, temp_data, DATA_SIZE);
    ReleaseSemaphore(handle_semaphore, 1, NULL);

    while (success) {
        WaitForSingleObject(handle_semaphore, 0);
        success = read_buf(shared_buf, temp_data, DATA_SIZE);
        ReleaseSemaphore(handle_semaphore, 1, NULL);
        fwrite(temp_data, DATA_SIZE, 1, logfile);

        WaitForSingleObject(handle_semaphore, 0);
        size = get_max_read_size(shared_buf);
        ReleaseSemaphore(handle_semaphore, 1, NULL);
        if (size == 0) {
            Sleep(15);                          //stall reader so writer could write to buffer
        }
    }

    //cleanup
    fclose(logfile);
    free_buf(shared_buf);
    free(temp_data);
    _endthread();
}

