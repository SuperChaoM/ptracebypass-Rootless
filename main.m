#include <stdio.h>
#include <dlfcn.h>
#include <Foundation/Foundation.h>
#include "patchfinder/libdimentio.h"
// #include "patchfinder/find_kernel_base_under_checkra1n.h"


#include <sys/proc.h>
#include <sys/param.h>
#include "proc.h"
//#define CONFIG_DTRACE 1

//#define CONFIG_PERSONAS 1
//#define _PROC_HAS_SCHEDINFO_ 1


extern int proc_listpids(uint32_t type, uint32_t typeinfo, void *buffer, int buffersize);
extern int proc_pidinfo(int pid, int flavor, uint64_t arg,  void *buffer, int buffersize);
struct proc_bsdinfo {
	uint32_t		pbi_flags;		/* 64bit; emulated etc */
	uint32_t		pbi_status;
	uint32_t		pbi_xstatus;
	uint32_t		pbi_pid;
	uint32_t		pbi_ppid;
	uid_t			pbi_uid;
	gid_t			pbi_gid;
	uid_t			pbi_ruid;
	gid_t			pbi_rgid;
	uid_t			pbi_svuid;
	gid_t			pbi_svgid;
	uint32_t		rfu_1;			/* reserved */
	char			pbi_comm[MAXCOMLEN];
	char			pbi_name[2*MAXCOMLEN];	/* empty if no name is registered */
	uint32_t		pbi_nfiles;
	uint32_t		pbi_pgid;
	uint32_t		pbi_pjobc;
	uint32_t		e_tdev;			/* controlling tty dev */
	uint32_t		e_tpgid;		/* tty process group id */
	int32_t			pbi_nice;
	uint64_t		pbi_start_tvsec;
	uint64_t		pbi_start_tvusec;
};
#define PROC_ALL_PIDS		1
#define PROC_PIDTBSDINFO		3
#define PROC_PIDTBSDINFO_SIZE		(sizeof(struct proc_bsdinfo))
//Dopamine 第1版本
static void *libjb = NULL;

void kwrite32(uint64_t va, uint32_t v) {
	void *libjb_kwrite32 = dlsym(libjb, "kwrite32");
	int (*kwrite32_)(uint64_t va, uint32_t v) = libjb_kwrite32;
	kwrite32_(va, v);
}

void kwrite64(uint64_t va, uint64_t v) {
	void *libjb_kwrite64 = dlsym(libjb, "kwrite64");
	int (*kwrite64_)(uint64_t va, uint64_t v) = libjb_kwrite64;
	kwrite64_(va, v);
}

uint64_t kread64(uint64_t va) {
	void *libjb_kread64 = dlsym(libjb, "kread64");
	uint64_t (*kread64_)(uint64_t va) = libjb_kread64;
	uint64_t ret = kread64_(va);
	return ret;
}

uint32_t kread32(uint64_t va) {
	void *libjb_kread32 = dlsym(libjb, "kread32");
	uint32_t (*kread32_)(uint64_t va) = libjb_kread32;
	uint32_t ret = kread32_(va);
	return ret;
}

uint64_t get_kslide(void) {
	void *libjb_kslide = dlsym(libjb, "bootInfo_getUInt64");
	uint64_t (*libjb_kslide_)(NSString *) = libjb_kslide;
	uint64_t ret = libjb_kslide_(@"kernelslide");
	return ret;
}

int jbdInitPPLRW(void) {
	void *libjb_pplrw = dlsym(libjb, "jbdInitPPLRW");
	int (*libjb_pplrw_)(void) = libjb_pplrw;
	int ret = libjb_pplrw_();
	return ret;
}

#define PROC_P_LIST_LE_PREV_OFF 0x8  // 假设这个偏移量为0x8
#define MAX_ITERATIONS 0x100  // 遍历0x100次
//需要根据相关xnu版本处理 来处理
uint64_t getProc(pid_t pid) {
    //  https://github.com/apple/darwin-xnu/blob/main/bsd/sys/proc_internal.h#L193
    //  https://github.com/apple/darwin-xnu/blob/main/bsd/sys/queue.h#L470
    
    uint64_t proc2 = kread64(kernproc);
    int iterations = 0;
	while(1)
	{
			

		    // 计算p_proc_ro的地址
            uint64_t p_proc_ro_addr = proc2 + offsetof(struct proc, p_proc_ro);
           // 读取p_proc_ro的值
            uint64_t proc_ro_addr = kread64(p_proc_ro_addr);

            // 计算p_uniqueid的地址
            uint64_t p_uniqueid_addr = proc_ro_addr + offsetof(struct proc_ro, p_uniqueid);
            // 读取p_uniqueid的值
            uint64_t p_uniqueid_value = kread64(p_uniqueid_addr);
            // 打印进程地址和p_uniqueid值
			// printf("[i] Process at 0x%llx has unique ID: %llu\n", proc2, p_uniqueid_value);
			
            // 计算p_ppid的地址
			uint64_t p_ppid_addr = proc2 + offsetof(struct proc, p_ppid);
			uint64_t p_puniqueid_addr = proc2 + offsetof(struct proc, p_puniqueid);
			// 读取p_ppid的值
			uint32_t p_ppid_value = kread32(p_ppid_addr);
			uint32_t p_puniqueid_value = kread32(p_puniqueid_addr);

			// printf("[i] ptracetest proc->p_ppid: %d\n,p_puniqueid_value: %d\n", p_ppid_value,p_puniqueid_value);
			if(pid == p_uniqueid_value)
			{
				printf("[i] p_puniqueid_addr: 0x%llx\n", p_puniqueid_addr);
			    printf("[i] Process at 0x%llx has unique ID: %llu\n proc->p_ppid: %d\n,p_puniqueid_value: %d\n", proc2, p_uniqueid_value,p_ppid_value,p_puniqueid_value);
				return  proc2;
			}

		    proc2 = kread64(proc2 + 0x8/*PROC_P_LIST_LE_PREV_OFF*/);
	}
    
    return 0;
}

//https://stackoverflow.com/questions/49506579/how-to-find-the-pid-of-any-process-in-mac-osx-c
int find_pids(const char *name)
{
	int ret = -1;
    pid_t pids[2048];
    int bytes = proc_listpids(PROC_ALL_PIDS, 0, pids, sizeof(pids));
    int n_proc = bytes / sizeof(pids[0]);
    for (int i = 0; i < n_proc; i++) {
        struct proc_bsdinfo proc;
        int st = proc_pidinfo(pids[i], PROC_PIDTBSDINFO, 0,
                             &proc, PROC_PIDTBSDINFO_SIZE);
        if (st == PROC_PIDTBSDINFO_SIZE) {
            if (strcmp(name, proc.pbi_name) == 0) {
                /* Process PID */
                // printf("%d [%s] [%s]\n", pids[i], proc.pbi_comm, proc.pbi_name);     
				return pids[i];           
            }
        }       
    }
	return ret;
}

// https://github.com/apple/darwin-xnu/blob/main/bsd/sys/proc_internal.h#L463
#define P_LNOATTACH     0x00001000 
#define P_LTRACED       0x00000400

// https://github.com/apple/darwin-xnu/blob/main/bsd/sys/proc.h#L179C1-L179C35
#define P_TRACED        0x00000800      /* Debugged process being traced */

#define ISSET(t, f)     ((t) & (f))
#define CLR(t, f)       (t) &= ~(f)
#define SET(t, f)       (t) |= (f)

int main(int argc, char *argv[], char *envp[]) {
	@autoreleasepool {
		libjb = dlopen("/var/containers/Bundle/Application/.jbroot-FE39EE5D178AA940/basebin/libjailbreak.dylib", RTLD_NOW);
		if(libjb != 0) {
			printf("libjailbreak load\n");
		}else
		{
			printf("failed libjailbreak\n");
			return 1;
		}

		if(dimentio_init(0, NULL, NULL) != KERN_SUCCESS) {
    		printf("failed dimentio_init!\n");
			return 1;
  		}

		if(kbase == 0) {
			printf("failed get_kbase\n");
			return 1;
		}
        //macho header 0xFFFFFFF007004000
		uint64_t kslide = kbase - 0xFFFFFFF007004000;
		printf("[i] kbase: 0x%llx, kslide: 0x%llx\n", kbase, kslide);
		printf("[i] kread64 from base: 0x%llx\n", kread64(kbase));

		int ptracetest_pid = atoi(argv[1]);

		printf("[i] ptracetest pid2: %d\n", ptracetest_pid);
		if(ptracetest_pid == -1) {
			printf("Not running ptracetest.\n");
			return 1;
		}


		uint64_t ptracetest_proc = getProc(ptracetest_pid);
		printf("[i] ptracetest proc: 0x%llx\n", ptracetest_proc);

		// https://github.com/apple/darwin-xnu/blob/main/bsd/kern/mach_process.c#L133
	
		uint64_t ptracetest_lflag = ptracetest_proc + 0x268/*lflagoffset*/;
		unsigned int lflagvalue = kread32(ptracetest_lflag);
		printf("[i] ptracetest ptracetest_lflag->addr:  0x%llx\n", ptracetest_lflag);
		printf("[i] ptracetest proc->p_lflag: 0x%x\n", lflagvalue);
		if(ISSET(lflagvalue, P_LNOATTACH))
		{
			printf("[+] find P_LNOATTACH ...\n");
		
		}
		if(ISSET(lflagvalue, P_LTRACED))
		{
			printf("[+] find P_LTRACED  ...\n");
		
		}
			
	

		if(ISSET(lflagvalue, P_LNOATTACH))
        {
            printf("[+] P_LNOATTACH has been set, clearing...\n");
            CLR(lflagvalue, P_LNOATTACH);
        	kwrite32(ptracetest_lflag, lflagvalue);
			printf("[+] P_LNOATTACH now unset.\n");

			lflagvalue = kread32(ptracetest_lflag);
			printf("[+] ptracetest proc->p_lflag: 0x%x\n", lflagvalue);
        }

		// https://github.com/apple/darwin-xnu/blob/main/bsd/kern/kern_sysctl.c#L1079
		if(argc == 3 && strcmp(argv[2], "notrace") == 0){
			if(ISSET(lflagvalue, P_LTRACED))
        	{
            	printf("[+] P_LTRACED has been set, clearing...\n");
            	CLR(lflagvalue, P_LTRACED);
        		kwrite32(ptracetest_lflag, lflagvalue);
				printf("[+] P_LTRACED now unset.\n");

				lflagvalue = kread32(ptracetest_lflag);
				printf("[+] ptracetest proc->p_lflag: 0x%x\n", lflagvalue);
        	}
		}
		
		if(argc == 3 && strcmp(argv[2], "trace") == 0) {
			if(!ISSET(lflagvalue, P_LTRACED))
        	{
            	printf("[+] P_LTRACED has NOT been set, setting...\n");
            	SET(lflagvalue, P_LTRACED);
        		kwrite32(ptracetest_lflag, lflagvalue);
				printf("[+] P_LTRACED now set.\n");

				lflagvalue = kread32(ptracetest_lflag);
				printf("[+] ptracetest proc->p_lflag: 0x%x\n", lflagvalue);
        	}
		}

       if(argc == 3 && strcmp(argv[2], "pid") == 0) 
	   {
	       // 计算p_ppid的地址
		   uint64_t p_ppid_addr = ptracetest_proc + offsetof(struct proc, p_ppid);
	     	// 读取p_ppid的值
		   uint32_t p_ppid_value = kread32(p_ppid_addr);

			printf("[i] ptracetest proc->p_ppid: %d\n", p_ppid_value);
			if(p_ppid_value != 1) {
				printf("[+] Patching proc->p_ppid to 1...\n");
				kwrite32(p_ppid_addr, 1);

				p_ppid_value = kread32(p_ppid_addr);
				printf("[+] ptracetest proc->p_ppid: %d\n", p_ppid_value);
			}
	   }

		dlclose(libjb);

		return 0;
	}
}
