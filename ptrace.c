#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <stdlib.h>
#include <string.h>

#define PTRACE_SYSEMU           0x1d
#define PTRACE_SYSEMU_SINGLESTEP 0x1e
#define __NR_getpid		0x14 
//#define DBG	1

static siginfo_t wait_trap(pid_t chld)
{
        siginfo_t si;
        if (waitid(P_PID, chld, &si, WEXITED|WSTOPPED) != 0)
                perror("waitid");
        if (si.si_pid != chld)
                perror("got unexpected pid in event\n");
        if (si.si_code != CLD_TRAPPED)
                perror("got unexpected event type");
        return si;                                                                                                  
}

void dump_regs(struct pt_regs *regs) {
	printf("r0 = %016lx and r1= %016lx\n", regs->gpr[0], regs->gpr[1]);
	printf("r2 = %016lx and r3= %016lx\n", regs->gpr[2], regs->gpr[3]);
	printf("r4 = %016lx and r5= %016lx\n", regs->gpr[4], regs->gpr[5]);
}

int trace_syscall()
{
	pid_t chld = fork();

	if (chld < 0) {
		perror("Fork");
		exit(-1);
	}

	/* CHILD */
	if (chld == 0) {
		int sysemu_result, syscall_result = 0;
		
		/*
		 * This syscall will be trapped by PTRACE_SYSCALL, thus, it
		 * will execute
		 */
		syscall_result = syscall(__NR_getpid, 0, 0, 0, 0);
		/*
		 * This syscall will be trapped by PTRACE_SYSEMU, thus, it
		 * will *not* execute and return the syscall number
		 */
		sysemu_result = syscall(__NR_getpid, 0, 0, 0, 0);

#ifdef DBG
		printf("sysemu_result = %lx and syscall_result = %lx\n", sysemu_result, syscall_result);
#endif

		/* The output should be the current PID */
		if (syscall_result != getpid()) {
			printf("Failure: PTRACE_SYSCALL output is not correct. (%x != %x)\n", syscall_result, getpid());

			return -1;
		}

		/* The output should be the very first argument */
		if (sysemu_result != 0) {
			printf("Failure: PTRACE_SYSEMU output is not correct.  (%x)\n", sysemu_result);
			
			return -1;
		}

		return 0;
	}

	/* Parent */
	if (chld > 0) {
		int ret;
		struct pt_regs regs;

		ret = ptrace(PTRACE_ATTACH, chld, NULL, NULL);
		if (ret < 0) {
			perror("ptrace attach error");
			exit(-1);
		}

		printf("Tracing process PID = %lx\n", chld);

		/* Start with PTRACE_SYSCALL */
		ret = ptrace(PTRACE_SYSCALL, chld, 0, 0);
		if (ret < 0) {
			perror("ptrace sysemu error");
			exit(-1);
		}
		wait_trap(chld);
		ptrace(PTRACE_GETREGS, chld, 0, &regs);
#ifdef DBG
		printf("PTRACE_SYSCALL regs\n");
		dump_regs(&regs);
#endif

		/* Checks if the registers are properly set as expected in
		 * in the syscall entrance
		 */
		if (regs.gpr[0] != __NR_getpid || regs.gpr[3] != 0 ||
			regs.gpr[4] != 0 || regs.gpr[5] != 0 || regs.gpr[6] != 0) {
			printf("Failure: SYSCALL does not seem to have r[0] = __NR_getpid or the regs are corrupted\n");
			dump_regs(&regs);
		}


		/* Now trace with PTRACE_SYSEMU */
		ret = ptrace(PTRACE_SYSEMU, chld, 0, 0);
		if (ret < 0) {
			perror("ptrace sysemu error");
			exit(-1);
		}
		wait_trap(chld);
		ptrace(PTRACE_GETREGS, chld, 0, &regs);
#ifdef DBG
		printf("PTRACE_SYSEMU regs\n");
		dump_regs(&regs);
#endif
		if (regs.gpr[0] != __NR_getpid || regs.gpr[3] != 0 ||
			regs.gpr[4] != 0 || regs.gpr[5] != 0 || regs.gpr[6] != 0) {
			printf("Failure: SYSCALL does not seem to have r[0] = __NR_getpid, or the regs are corrupted\n");
			dump_regs(&regs);
			return -1;
		}

	        ret = ptrace(PTRACE_CONT, chld, NULL, NULL);
		waitpid(chld, NULL, 0);

	}

	printf("Test passed\n");
	return 0;
}

int main()
{
	return trace_syscall();
}
