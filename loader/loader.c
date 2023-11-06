/*
 * Loader Implementation
 *
 * 2022, Operating Systems
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>
#include "exec_parser.h"

static so_exec_t *exec;
#include <errno.h>
#define DIE(assertion, call_description)		\
	do {										\
		if (assertion) {						\
			fprintf(stderr, "(%s, %d): ",		\
					__FILE__, __LINE__);		\
			perror(call_description);			\
			exit(errno);						\
		}										\
	} while (0)

static int fd;
struct sigaction default_h;

/* returneaza indexul segmentului in care se aflta adresa fault */
int fault_segment(void *fault) {
	for(int i = 0; i < exec->segments_no; i++) {
		so_seg_t seg = exec->segments[i];
		if( (seg.vaddr <= (uintptr_t)fault) && (uintptr_t)fault <= (seg.vaddr + seg.mem_size))
			return i;	
	}
	return -1; 
}

static void segv_handler(int signum, siginfo_t *info, void *context)
{
	int pagesize = getpagesize();
	void *fault = info->si_addr;
	int seg_index = fault_segment(fault);

	/* CAZ 1 adresa nu se gaseste intr-un segment => default_h */
	if(seg_index == -1){
		default_h.sa_sigaction(signum, info, context);
		return;
	}

	/* CAZ 2 am gasit segmentul */
	so_seg_t *seg = &exec->segments[seg_index];
	int nr_pag = seg->mem_size/pagesize + 1;
	
	/*in data retin daca paginile au fost mapate(1 sau 0)*/
	if(!(seg->data)) 
		seg->data = (char*)calloc(nr_pag,sizeof(char));
	DIE(seg->data == NULL, "calloc(data) failed");

	/* CAZ 2.1 pagina este mapata deja (acces nepermis la memorie) => default_h */
	int page_index = (int)(fault - seg->vaddr) / pagesize;
	if(((char*)(seg->data))[page_index] == 1) { 
		default_h.sa_sigaction(signum, info, context);
		return;
	}
	
	/* CAZ 2.2 pagina trebuie mapata( + copiere date ) */ 
	int page_addr = seg->vaddr + page_index * pagesize; 
	int flags =  MAP_FIXED | MAP_PRIVATE;
	unsigned int offset = seg->offset + pagesize*page_index;
	void *mmap_r = mmap((void*)page_addr, pagesize, PROT_READ | PROT_WRITE, flags, fd, offset);
	DIE(mmap_r == MAP_FAILED, "mmap failed");

	/* adresa fault depaseste file_size => zona cu zero */
	if(page_addr >= seg->vaddr + seg->file_size) {
		memset((void*)page_addr, 0, pagesize);
	}
	/* o parte este copiata(pana la file_size, restul este setat la zero */
	else if(!(page_addr + pagesize <= seg->vaddr + seg->file_size)) {
		memset((void*)(seg->vaddr + seg->file_size), 0, pagesize - seg->file_size % pagesize );
	}
	int prot = mprotect(mmap_r, pagesize, seg->perm);
	DIE(prot == -1, "mprotect failed");
	((char*)(seg->data))[page_index] = 1;
\
}

int so_init_loader(void)
{
	int rc;
	struct sigaction sa;

	memset(&sa, 0, sizeof(sa));
	sa.sa_sigaction = segv_handler;
	sa.sa_flags = SA_SIGINFO;
	rc = sigaction(SIGSEGV, &sa, NULL);
	if (rc < 0) {
		perror("sigaction");
		return -1;
	}
	return 0;
}

int so_execute(char *path, char *argv[])
{
	fd = open(path, O_RDONLY);
	DIE(fd < 0, "invalid file descriptor");
	
	exec = so_parse_exec(path);
	if (!exec)
		return -1;

	so_start_exec(exec, argv);

	close(fd);
	
	return -1;
}
