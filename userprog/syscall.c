#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"

// 내가 추가
#include "filesys/filesys.h"
#include "threads/init.h"
#include "filesys/file.h"
#include "devices/input.h"
#include "kernel/stdio.h"
#include "threads/synch.h"

void syscall_entry(void);
void syscall_handler(struct intr_frame *f UNUSED);

// 내가 추가
void check_address(void *addr);
void halt(void);
bool create(const char *file, unsigned initial_size);
bool remove(const char *file);
int open(const char *file);
int filesize(int fd);
int read(int fd, void *buffer, unsigned size);
int write(int fd, const void *buffer, unsigned size);
void seek(int fd, unsigned position);
unsigned tell(int fd);
void close(int fd);
struct file *fd_to_fp(int fd);
int add_fp_in_fdt(struct file *fp);
// lock 선언, syscall이 이 파일에 대해서 쓰고 있다고 Lock을 걸어버림
struct lock filesys_lock;

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081			/* Segment selector msr */
#define MSR_LSTAR 0xc0000082		/* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void syscall_init(void)
{
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48 |
							((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t)syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			  FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
	// 내가 추가
	// lock 선언 후 초기화
	lock_init(&filesys_lock);
}

/* The main system call interface */
void syscall_handler(struct intr_frame *f UNUSED)
{
	// TODO: Your implementation goes here.
	int sys_number = f->R.rax;

	switch (sys_number)
	{
	case SYS_HALT:
		halt();
		break;
	case SYS_EXIT:
		exit(f->R.rdi);
		break;
	// case SYS_FORK:
	// 	fork(f->R.rdi);
	// 	break;
	// case SYS_EXEC:
	// 	exec(f->R.rdi);
	// 	break;
	// case SYS_WAIT:
	// 	wait(f->R.rdi);
	// 	break;
	case SYS_CREATE:
		create(f->R.rdi, f->R.rsi);
		break;
	case SYS_REMOVE:
		remove(f->R.rdi);
		break;
	case SYS_OPEN:
		open(f->R.rdi);
		break;
	case SYS_FILESIZE:
		filesize(f->R.rdi);
		break;
	case SYS_READ:
		read(f->R.rdi, f->R.rsi, f->R.rdx);
		break;
	case SYS_WRITE:
		write(f->R.rdi, f->R.rsi, f->R.rdx);
		break;
	case SYS_SEEK:
		seek(f->R.rdi, f->R.rdx);
		break;
	case SYS_TELL:
		tell(f->R.rdi);
		break;
	case SYS_CLOSE:
		close(f->R.rdi);
		break;
	}
	printf("system call!\n");
	thread_exit();
}

void check_address(void *addr)
{
	struct thread *t = thread_current();
	if (!is_user_vaddr(addr) || !pml4_get_page(t->pml4, addr))
		exit(-1);
}

void halt(void)
{
	power_off();
}

void exit(int status)
{
	struct thread *t = thread_current();
	printf("%s: exit%d\n", t->name, status);
	thread_exit();
	// 정상 종료 status == 0
}

// pid_t fork (const char *thread_name){
// }

// int exec (const char *file) {
// }

// int wait (pid_t pid) {
// }

bool create(const char *file, unsigned initial_size)
{
	// file을 하드 디스크에 create를 하기 위해 file 포인터에 제대로된 주소가 저장되어 있는지 확인
	check_address(file);
	return filesys_create(file, initial_size);
}

bool remove(const char *file)
{
	check_address(file);
	return filesys_remove(file);
}

int add_fp_in_fdt(struct file *fp)
{
	struct thread *t = thread_current();
	int fd = 2;

	while (t->fdt[fd] != NULL && fd < 64)
		fd++;

	if (fd > 63)
		return -1;

	t->fdt[fd] = fp;
	return fd;
}

int open(const char *file)
{
	check_address(file);
	struct thread *t = thread_current();
	struct file *fp = filesys_open(file);
	if (!fp)
		return -1;
	// fd table에 fp 추가
	int fd = add_fp_in_fdt(fp);
	if (fd == -1)
		file_close(fp);
	return fd;
}

int filesize(int fd)
{
	struct file *fp = fd_to_fp(fd);
	if (!fp)
		return -1;
	return file_length(fp);
}

int read(int fd, void *buffer, unsigned size)
{
	// 유효한 주소 체크
	check_address(buffer);
	check_address(buffer + size - 1);
	int read_count;
	unsigned char *buf = buffer;

	struct file *fp = fd_to_fp(fd);
	if (!fp)
		return -1;
	// STDIN 일 때,
	if (fd == 0)
	{
		for (read_count = 0; read_count < size; read_count++)
		{
			// 한 글자씩 input_getc()로 받아와서 buf에 넣는다.
			char input = input_getc();
			*buf++ = input;
			if (input = '\0')
				break;
		}
	}
	// STDOUT 일 때,
	else if (fd == 1)
		return -1;
	else
	{
		// 일반 파일일 경우, 그냥 buffer부터 size만큼 읽는다.
		// filesys에 대한 Lock도 요청한후 release 한다.
		lock_acquire(&filesys_lock);
		read_count = file_read(fp, buffer, size);
		lock_release(&filesys_lock);
	}
	return read_count;
}

int write(int fd, const void *buffer, unsigned size)
{
	check_address(buffer);
	struct file *fp = fd_to_fp(fd);
	int write_count;
	if (!fp)
		return -1;
	// STDOUT일 때,
	if (fd == 1)
	{
		putbuf(buffer, size);
		write_count = size;
	}
	else if (fd == 0)
		return -1;
	else
	{
		lock_acquire(&filesys_lock);
		write_count = file_write(fp, buffer, size);
		lock_acquire(&filesys_lock);
	}
	return write_count;
}

void seek(int fd, unsigned position)
{
	if (fd < 2)
		return;
	struct file *fp = fd_to_fp(fd);
	check_address(fp);
	if (!fp)
		return;
	file_seek(fp, position);
}

unsigned tell(int fd)
{
	if (fd < 2)
		return;
	struct file *fp = fd_to_fp(fd);
	check_address(fp);
	if (!fp)
		return -1;
	return file_tell(fp);
}

void close(int fd)
{
	struct file *fp = fd_to_fp(fd);
	struct thread *t = thread_current();
	check_address(fp);
	if (!fp)
		return -1;
	file_close(fp);
	t->fdt[fd] = NULL;
}

struct file *fd_to_fp(int fd)
{
	if (fd < 0 || fd >= 64)
		return NULL;

	struct thread *t = thread_current();
	struct file *file = t->fdt[fd];
	return file;
}
