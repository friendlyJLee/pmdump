/*
 *
 * pmdump - Process Memory Dump
 *
 *
 * Copyright (c) 2017,
 *   Jaeho Lee, Dan S. Wallach
 * All rights reserved.
 *
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or (at
 * your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <memory.h>

#define MAX_FILENAME_LENGTH 1024
#define OUTPUT_FILE "output_pmdump.bin"
#define MAGIC_HEADER_STRING "PMDUMP_FILE_WITH_HEADER"
#define MAGIC_HEADER_STRING_LENGTH 23


/**
 * structure for memorymap region entry
 */
#define MEMORY_ENTRY_SIZE_IN_FILE (4+4+4+5+4+13+4+1024)
typedef struct st_memorymap_entry {
    unsigned long start_address;
    unsigned long end_address;
    unsigned long length;
    char perm[5];
    unsigned long offset;
    char device[13];
    int inode;
    char filename[1024];
    struct st_memorymap_entry* next;
} memorymap_entry;


/**
 *
 * @param line one list string from maps file
 *             example b723e000-b723f000 rw-p 0000b000 fd:00 953        /system/lib/libbacktrace.so
 * @return memorymap_entry object
 */
memorymap_entry* create_memorymap_entry_from_string(char *line){

    memorymap_entry *entry = (memorymap_entry*) malloc(sizeof(memorymap_entry));
    if (entry == NULL){
        printf("Unable to allocate memory for memorymap_entry");
        return NULL;
    }

    char tmpStr[MAX_FILENAME_LENGTH];

    // start_address
    int index = 0;
    int dstIndex = 0;
	while(line[index]!='-') tmpStr[dstIndex++]=line[index++];
    tmpStr[dstIndex] = 0;
    sscanf(tmpStr, "%08lx", &entry->start_address );

	//end_address
    index++;
    dstIndex = 0;
	while(line[index]!='\t' && line[index]!=' ') tmpStr[dstIndex++]=line[index++];
    tmpStr[dstIndex] = 0;
    sscanf(tmpStr, "%08lx", &entry->end_address );

    // length
    entry->length = entry->end_address - entry->start_address;

    //perm
    while(line[index]=='\t' || line[index]==' ') index++;
    dstIndex = 0;
	while(line[index]!='\t' && line[index]!=' ') entry->perm[dstIndex++]=line[index++];
    entry->perm[dstIndex]=0;

	//offset
	while(line[index]=='\t' || line[index] ==' ') index++;
	dstIndex =0;
    while(line[index]!='\t' && line[index]!=' ') tmpStr[dstIndex++]=line[index++];
    tmpStr[dstIndex] = 0;
    sscanf(tmpStr, "%08lx", &entry->offset );

	//device
    while(line[index]=='\t' || line[index] ==' ') index++;
    dstIndex =0;
    while(line[index]!='\t' && line[index]!=' ') entry->device[dstIndex++]=line[index++];
    entry->device[dstIndex]=0;

	//inode
    while(line[index]=='\t' || line[index] ==' ') index++;
    dstIndex=0;
    while(line[index]!='\t' && line[index]!=' ') tmpStr[dstIndex++]=line[index++];
    tmpStr[dstIndex]='\0';
    entry->inode = atoi(tmpStr);

	//filename
    entry->filename[0] = 0;
    while(line[index]=='\t' || line[index] ==' ') index++;
    dstIndex=0;
    while(line[index]!='\t' && line[index]!=' '&& line[index]!='\n') entry->filename[dstIndex++]=line[index++];
    entry->filename[dstIndex]='\0';

    entry->next = NULL;

    return entry;
}

/*
 * Print memorymap_entry for debug purpose
 */
void print_memorymap_entry(memorymap_entry *entry){

    printf("%lx %lx %lx %s %lx %s %u %s\n", entry->start_address, entry->end_address, entry->length, entry->perm, entry->offset, entry->device, entry->inode, entry->filename);
};

/**
 * memory_entry to binary file
 *
 * @param entry
 * @return
 */
char* serialize_memory_entry(memorymap_entry *entry){

    //#define MEMORY_ENTRY_SIZE_IN_FILE (4+4+4+5+4+13+4+1024)

    char *bytes = (char*) malloc(MEMORY_ENTRY_SIZE_IN_FILE);
    int *intAddr = (int*) bytes;
    int index = 0;
    *intAddr = entry->start_address;
    index += sizeof(int);

    intAddr = (int*) ( bytes + index);
    *intAddr = entry->end_address;
    index += sizeof(int);

    intAddr = (int*) ( bytes + index);
    *intAddr = entry->length;
    index += sizeof(int);

    strncpy(bytes + index, entry->perm, 5);
    index += 5;

    intAddr = (int*) ( bytes + index);
    *intAddr = entry->offset;
    index += sizeof(int);

    strncpy(bytes + index, entry->device, 13);
    index += 13;

    intAddr = (int*) ( bytes + index);
    *intAddr = entry->inode;
    index += sizeof(int);

    strncpy(bytes + index, entry->filename, 1024);

    return bytes;
}


void dump_memory_entry(FILE* srcFile, memorymap_entry *entry, int serverSocket, FILE *dstFile)
{
    unsigned long address;
    int pageLength = 0x1000;
    unsigned char page[pageLength];
	fseeko(srcFile, entry->start_address, SEEK_SET);

	for (address=entry->start_address; address < entry->end_address; address += pageLength)
	{
		fread(&page, 1, pageLength, srcFile);

		if (serverSocket == -1)
		{
            int res = 0;
			if ( (res = fwrite(&page, 1, pageLength, dstFile)) != pageLength){
                printf("Error during fwrite: sent bytes: %d\n", res);
                exit(-1);
            };
		}
		else
		{
			if ( send(serverSocket, &page, pageLength, 0) != pageLength) {
                printf("Error during send\n");
                exit(-1);
            };
		}
	}
	/* in case, cleansing for preventing side-effect in next dumping experiment */
	memset(page, 0, pageLength);
}


void dump_maps_info_header(memorymap_entry *list_head, int number_of_entries, int serverSocket, FILE *dstFile)
{

    // magic_string + entry_numbers + body_offset + entries + magic_string
    int headerSize = MAGIC_HEADER_STRING_LENGTH + sizeof(int) + sizeof(int) + sizeof(memorymap_entry)*number_of_entries + MAGIC_HEADER_STRING_LENGTH;
    char *header = (char*) malloc(headerSize);
    if (header == NULL){
        printf("Malloc error in dump_maps_info_header");
        exit(-1);
    }

    int index = 0;

    strncpy(header, MAGIC_HEADER_STRING, MAGIC_HEADER_STRING_LENGTH);
    index += MAGIC_HEADER_STRING_LENGTH;

    int *intAddr = (int*) ( header + index);
    *intAddr = number_of_entries;
    index += sizeof(int);

    intAddr = (int*) (header + index);
    *intAddr = index + sizeof(int) + MEMORY_ENTRY_SIZE_IN_FILE*number_of_entries + MAGIC_HEADER_STRING_LENGTH;
    index += sizeof(int);

    while(list_head != NULL) {
        char *bytes = serialize_memory_entry(list_head);
        memcpy(header + index, bytes, MEMORY_ENTRY_SIZE_IN_FILE);
        free(bytes);
        list_head = list_head->next;
        index += MEMORY_ENTRY_SIZE_IN_FILE;
    }

    strncpy(header+index, MAGIC_HEADER_STRING, MAGIC_HEADER_STRING_LENGTH);
    index += MAGIC_HEADER_STRING_LENGTH;

    // write header
    if (serverSocket == -1)
    {
        int res = 0;
        if ( (res = fwrite(header, 1, index, dstFile)) != index){
            printf("Error during fwrite: sent bytes: %d\n", res);
            exit(-1);
        };
    }
    else
    {
        if ( send(serverSocket, header, index, 0) != index) {
            printf("Error during send\n");
            exit(-1);
        };
    }

    free(header);

}


#define FILTER_DONT_CARE -1
#define FILTER_OFF 0
#define FILTER_ON 1


void printUsageAndExit(char *exeName){
    printf("\n%s [OPTION]... MODE[,MODE]... <pid>\n", exeName);
    printf("%s [OPTION]... MODE[,MODE]... <pid> <ip-address> <port>\n", exeName);
    printf("\nDumping process memory to '%s' file or network.\n", OUTPUT_FILE);
    printf("The dumped result contains /proc/<pid>/maps entries info and its memory contents.\n");
    printf("\nOptions\n");
    printf("\t--raw\tDumping only data without /proc/<pid>/maps info header\n");
    printf("\t--anon\tDumping only anonymous memory\n");
    printf("\nEach MODE is of the form '[-+][rwxps]'. If no mode is given, don't care the permission\n");
    printf("\nExample\n");
    printf("\t%s +r +w -x +p --anon 1928\t\t# dump only 'rw-p' permission with no file-mapped memory.\n", exeName);
    printf("\t%s +w --raw 1928 127.0.0.1 1212\t# dump only writable memory without header info.\n", exeName);
    exit(0);
}
int main(int argc, char **argv) {

    FILE *outputFp;

    // options
    int r_perm = FILTER_DONT_CARE;
    int w_perm = FILTER_DONT_CARE;
    int x_perm = FILTER_DONT_CARE;
    int p_perm = FILTER_DONT_CARE;
    int s_perm = FILTER_DONT_CARE;
    int anon_only = FILTER_OFF;
    int raw_dump_only = FILTER_OFF;

    // option parsing
    int argIndex = 1;
    for (; argIndex < argc; argIndex++){
        if (strncmp(argv[argIndex], "-r", 2) == 0){
            r_perm = FILTER_OFF;
        }
        else if (strncmp(argv[argIndex], "+r", 2) == 0){
            r_perm = FILTER_ON;
        }
        else if (strncmp(argv[argIndex], "-w", 2) == 0){
            w_perm = FILTER_OFF;
        }
        else if (strncmp(argv[argIndex], "+w", 2) == 0){
            w_perm = FILTER_ON;
        }
        else if (strncmp(argv[argIndex], "-x", 2) == 0){
            x_perm = FILTER_OFF;
        }
        else if (strncmp(argv[argIndex], "+x", 2) == 0){
            x_perm = FILTER_ON;
        }
        else if (strncmp(argv[argIndex], "-p", 2) == 0){
            p_perm = FILTER_OFF;
        }
        else if (strncmp(argv[argIndex], "+p", 2) == 0){
            p_perm = FILTER_ON;
        }
        else if (strncmp(argv[argIndex], "-s", 2) == 0){
            s_perm = FILTER_OFF;
        }
        else if (strncmp(argv[argIndex], "+s", 2) == 0){
            s_perm = FILTER_ON;
        }
        else if (strncmp(argv[argIndex], "--raw", 5) == 0){
            raw_dump_only = FILTER_ON;
        }
        else if (strncmp(argv[argIndex], "--anon", 6) == 0){
            anon_only = FILTER_ON;
        }
        else break;
    }

    // p s perm conflict check
    if ((p_perm == FILTER_ON && s_perm == FILTER_ON) || (p_perm == FILTER_OFF && s_perm == FILTER_OFF)){
        printf("'p' and 's' perm cannot be the same option.\n");
        printUsageAndExit(argv[0]);
    }

    // arg parsing
    int left_arg_numbers = argc-argIndex;
    int pid = 0;
	if (left_arg_numbers == 1 || left_arg_numbers == 3){
        pid = atoi(argv[argIndex]);
        long ptraceResult = ptrace(PTRACE_ATTACH, pid, NULL, NULL);
        if (ptraceResult < 0)
        {
            printf("Unable to attach to the pid specified\n");
            exit(1);
        }
        printf("Successfully attached to the pid: %d\n", pid);
        wait(NULL);

		char mapsFilename[1024];
		sprintf(mapsFilename, "/proc/%s/maps", argv[argIndex]);
		FILE* pMapsFile = fopen(mapsFilename, "r");
		char memFilename[1024];
		sprintf(memFilename, "/proc/%s/mem", argv[argIndex]);
		FILE* pMemFile = fopen(memFilename, "r");

        int serverSocket = -1;
        if (left_arg_numbers == 3)
        {
            unsigned int port;
            int count = sscanf(argv[argIndex+2], "%d", &port);
            if (count == 0)
            {
                printf("Invalid port specified\n");
                exit(1);
            }
            serverSocket = socket(AF_INET, SOCK_STREAM, 0);
            if (serverSocket == -1)
            {
                printf("Could not create socket\n");
                exit(1);
            }
            struct sockaddr_in serverSocketAddress;
            serverSocketAddress.sin_addr.s_addr = inet_addr(argv[argIndex+1]);
            serverSocketAddress.sin_family = AF_INET;
            serverSocketAddress.sin_port = htons(port);
            if (connect(serverSocket, (struct sockaddr *) &serverSocketAddress, sizeof(serverSocketAddress)) < 0)
            {
                printf("Could not connect to server\n");
                exit(1);
            }
        }
        if (serverSocket == -1){
            outputFp = fopen(OUTPUT_FILE, "wb");
        }


		char line[256];
        memorymap_entry *list_head = NULL;
        memorymap_entry *list_cur = NULL;
        int number_of_entries = 0;

        memorymap_entry *entry = NULL;
		while (fgets(line, 256, pMapsFile) != NULL)
		{

            if (entry != NULL) free(entry); // free previous entry that is filtered but not freed.

            entry = create_memorymap_entry_from_string(line);
            if (entry == NULL){
                exit(-1);
            }

            // FILTER_CHECK: "rwxp" or "rwxs"

            if (r_perm != FILTER_DONT_CARE){
                if (entry->perm[0] == 'r' && r_perm == FILTER_OFF) continue;
                if (entry->perm[0] == '-' && r_perm == FILTER_ON) continue;
            }
            if (w_perm != FILTER_DONT_CARE){
                if (entry->perm[1] == 'w' && w_perm == FILTER_OFF) continue;
                if (entry->perm[1] == '-' && w_perm == FILTER_ON) continue;
            }
            if (x_perm != FILTER_DONT_CARE){
                if (entry->perm[2] == 'x' && x_perm == FILTER_OFF) continue;
                if (entry->perm[2] == '-' && x_perm == FILTER_ON) continue;
            }
            if (p_perm != FILTER_DONT_CARE){
                if (entry->perm[3] == 'p' && p_perm == FILTER_OFF) continue;
                if (entry->perm[3] != 'p' && p_perm == FILTER_ON) continue;
            }
            if (s_perm != FILTER_DONT_CARE){
                if (entry->perm[3] == 'p' && s_perm == FILTER_OFF) continue;
                if (entry->perm[3] != 'p' && s_perm == FILTER_ON) continue;
            }

            // FILTER_CHECK: anonymous memory only

            if (anon_only == FILTER_ON && entry->inode != 0) continue;

            print_memorymap_entry(entry);

            // PASS ALL FILTERS

            if (list_head == NULL){
                list_head = entry;
                list_cur = entry;
            }
            else {
                list_cur->next = entry;
                list_cur = entry;
            }
            number_of_entries++;

            entry = NULL;
		}

        printf("# Total entries to dump: %d\n", number_of_entries);


        /* dump header */
        if(raw_dump_only != FILTER_ON) {
            printf("# dump_maps_info_header\n");
            dump_maps_info_header(list_head, number_of_entries, serverSocket, outputFp);
        }

        /* dump body */
        list_cur = list_head;
        printf("# dump_memory_entry\n");
        while (list_cur != NULL){
            dump_memory_entry(pMemFile, list_cur, serverSocket, outputFp);
            list_cur = list_cur->next;
        }

		fclose(pMapsFile);
		fclose(pMemFile);
		if (serverSocket != -1)
		{
			close(serverSocket);
		}
        else {
            fclose(outputFp);
        }

		ptrace(PTRACE_CONT, pid, NULL, NULL);
		ptrace(PTRACE_DETACH, pid, NULL, NULL);

        printf("\n# pmdump sucessfully dumped the memory with the following options.\n");
        char permStr[5];
        int i;
        for (i = 0; i < 4; i++) permStr[i] = '*';
        permStr[4] = 0;
        if (r_perm == FILTER_ON) permStr[0] = 'r';
        if (r_perm == FILTER_OFF) permStr[0] = '-';
        if (w_perm == FILTER_ON) permStr[1] = 'w';
        if (w_perm == FILTER_OFF) permStr[1] = '-';
        if (x_perm == FILTER_ON) permStr[2] = 'x';
        if (x_perm == FILTER_OFF) permStr[2] = '-';
        if (p_perm == FILTER_ON) permStr[3] = 'p';
        if (p_perm == FILTER_OFF) permStr[3] = 's';
        if (s_perm == FILTER_ON) permStr[3] = 's';
        if (s_perm == FILTER_OFF) permStr[3] = 'p';

        printf("  - permission filter: '%s'\n", permStr);
        printf("  - --raw only: %s\n", raw_dump_only == FILTER_ON ? "ON" : "OFF");
        printf("  - --anon only: %s\n", anon_only == FILTER_ON ? "ON" : "OFF");
        printf("  - target pid: %d\n", pid);
        printf("  - output: %s\n", serverSocket == -1 ? OUTPUT_FILE : "To remote");
	}
	else
	{
        printUsageAndExit(argv[0]);
	}

    return 0;
}
