#ifndef QEMU_COMMON
#define QEMU_COMMON

typedef void Monitor;

# ifndef O_CLOEXEC
 # define O_CLOEXEC 02000000
# endif

# ifndef SOCK_CLOEXEC
 #define SOCK_CLOEXEC O_CLOEXEC
# endif

#endif
