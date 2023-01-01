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
#include "filesys/file.h"
#include "threads/palloc.h"
#include "threads/init.h"
#include "devices/input.h"
#include "kernel/stdio.h"
#include "threads/synch.h"
#include <string.h>
#include "userprog/process.h"
#include "user/syscall.h"

void syscall_entry(void);
void syscall_handler(struct intr_frame *f UNUSED);

// 내가 추가
void check_address(void *addr);
struct file *fd_to_fp(int fd);
int add_fp_in_fdt(struct file *fp);

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
	// 내가 추가
	// lock 선언 후 초기화
	lock_init(&filesys_lock);

	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48 |
							((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t)syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			  FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
}

/* The main system call interface */
void syscall_handler(struct intr_frame *f UNUSED)
{
	// TODO: Your implementation goes here.
	switch (f->R.rax)
	{
	case SYS_HALT:
		halt();
		break;
	case SYS_EXIT:
		exit(f->R.rdi);
		break;
	case SYS_FORK:
		memcpy(&thread_current()->parent_if, f, sizeof(struct intr_frame));
		f->R.rax = fork(f->R.rdi);
		break;
	case SYS_CREATE:
		f->R.rax = create(f->R.rdi, f->R.rsi);
		break;
	case SYS_REMOVE:
		f->R.rax = remove(f->R.rdi);
		break;
	case SYS_OPEN:
		f->R.rax = open(f->R.rdi);
		break;
	case SYS_FILESIZE:
		f->R.rax = filesize(f->R.rdi);
		break;
	case SYS_READ:
		f->R.rax = read(f->R.rdi, f->R.rsi, f->R.rdx);
		break;
	case SYS_WRITE:
		f->R.rax = write(f->R.rdi, f->R.rsi, f->R.rdx);
		break;
	case SYS_EXEC:
		exec(f->R.rdi);
		break;
	case SYS_WAIT:
		f->R.rax = wait(f->R.rdi);
		break;
	case SYS_SEEK:
		seek(f->R.rdi, f->R.rsi);
		break;
	case SYS_TELL:
		f->R.rax = tell(f->R.rdi);
		break;
	case SYS_CLOSE:
		close(f->R.rdi);
		break;
	default:
		exit(-1);
		break;
	}
	// printf("system call!\n");
	// thread_exit();
}

void check_address(void *addr)
{
	struct thread *t = thread_current();
	if (!is_user_vaddr(addr) || !pml4_get_page(t->pml4, addr) || !addr)
		exit(-1);
}

void halt(void)
{
	power_off();
}

void exit(int status)
{
	struct thread *t = thread_current();
	t->exit_status = status;
	printf("%s: exit%d\n", t->name, status);
	thread_exit();
	// 정상 종료 status == 0
}

int fork(const char *thread_name)
{
	check_address(thread_name);
	return process_fork(thread_name, &thread_current()->parent_if);
}

int exec(const char *file_name)
{
	check_address(file_name);

	int size = strlen(file_name) + 1;
	char *fn_copy = palloc_get_page(PAL_ZERO);
	if (!fn_copy)
	{
		exit(-1);
		return -1;
	}
	strlcpy(fn_copy, file_name, size);
	if (process_exec(fn_copy) == -1)
	{
		exit(-1);
		return -1;
	}
}

int wait(pid_t pid)
{
	return process_wait(pid);
}

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
	int fd = t->next_fd;

	while (t->fdt[fd] != NULL && fd < 128)
		fd++;

	if (fd > 127)
		return -1;

	t->fdt[fd] = fp;
	return fd;
}

int open(const char *file)
{
	check_address(file);
	struct thread *t = thread_current();
	struct file *fp = filesys_open(file);
	if (fp)
	{
		for (int i = 2; i < 128; i++)
		{
			if (!t->fdt[i])
			{
				t->fdt[i] = fp;
				t->next_fd = i + 1;
				return i;
			}
		}
		file_close(fp);
	}
	return -1;
}

int filesize(int fd)
{
	if (fd < 0 || fd >= 128)
		return -1;
	struct file *fp = fd_to_fp(fd);

	if (!fp)
		return -1;
	return file_length(fp);
}

int read(int fd, void *buffer, unsigned size)
{
	// 유효한 주소 체크
	check_address(buffer);
	if (fd == 1)
	{
		return -1;
	}

	if (fd == 0)
	{
		lock_acquire(&filesys_lock);
		int byte = input_getc();
		lock_release(&filesys_lock);
		return byte;
	}
	struct file *file = thread_current()->fdt[fd];
	if (file)
	{
		lock_acquire(&filesys_lock);
		int read_byte = file_read(file, buffer, size);
		lock_release(&filesys_lock);
		return read_byte;
	}
	return -1;
}

int write(int fd, const void *buffer, unsigned size)
{
	check_address(buffer);

	if (fd == 0) // STDIN일때 -1
		return -1;

	if (fd == 1)
	{
		lock_acquire(&filesys_lock);
		putbuf(buffer, size);
		lock_release(&filesys_lock);
		return size;
	}

	struct file *file = thread_current()->fdt[fd];
	if (file)
	{
		lock_acquire(&filesys_lock);
		int write_byte = file_write(file, buffer, size);
		lock_release(&filesys_lock);
		return write_byte;
	}
}

void seek(int fd, unsigned position)
{
	struct file *fp = fd_to_fp(fd);
	if (fp)
		file_seek(fp, position);
}

unsigned tell(int fd)
{
	struct file *fp = fd_to_fp(fd);
	if (fp)
		return file_tell(fp);
}

void close(int fd)
{
	struct file *fp = fd_to_fp(fd);
	struct thread *t = thread_current();
	// check_address(fp);
	if (!fp)
		return;
	lock_acquire(&filesys_lock);
	t->fdt[fd] = NULL;
	file_close(fp);
	lock_release(&filesys_lock);
}

struct file *fd_to_fp(int fd)
{
	if (fd < 0 || fd >= 64)
		return NULL;

	struct thread *t = thread_current();
	struct file *file = t->fdt[fd];
	return file;
}
