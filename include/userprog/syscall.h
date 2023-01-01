#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

// 필요한 기본 라이브러리
#include <stdbool.h>
#include "threads/thread.h"

// lock 선언, syscall이 이 파일에 대해서 쓰고 있다고 Lock을 걸어버림
struct lock filesys_lock;

void syscall_init(void);
void get_argument(void *esp, int *arg, int count);

// 내가 추가
void check_address(void *addr);

void halt(void);
void exit(int status);
int fork(const char *thread_name);
int exec(const char *file_name);
int wait(tid_t pid);
bool create(const char *file, unsigned initial_size);
bool remove(const char *file);
int open(const char *file);
int filesize(int fd);
int read(int fd, void *buffer, unsigned size);
int write(int fd, const void *buffer, unsigned size);
void seek(int fd, unsigned position);
unsigned tell(int fd);
void close(int fd);

#endif /* userprog/syscall.h */
