
/**
 * bind_hook.c
 *
 * Calls setsockopt() with #SO_BINDTODEVICE before _any_ bind(). The
 * name of the interface to bind to is obtained from environment
 * variable `_BINDTODEVICE`.
 *
 * Needs root perms. errors are not signalled out. use strace to
 * debug.
 *
 * Compile with:
 *   gcc -Wall -Werror -shared -fPIC -o bind_hook.so -D_GNU_SOURCE bind_hook.c -ldl
 * Example usage:
 *   LD_PRELOAD=./bind_hook.so _BINDTODEVICE=eth0 nc -l 0.0.0.0 9500
 *
 * @author: init-js
 **/

#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <dlfcn.h>
#include <errno.h>


static char iface[IF_NAMESIZE];
static int (*bind_original)(int, const struct sockaddr*, socklen_t addrlen);

int bind(int sockfd, const struct sockaddr *addr,
	 socklen_t addrlen);


__attribute__((constructor))
void ctor() {
	bind_original = dlsym(RTLD_NEXT, "bind");

	char *env_iface = getenv("_BINDTODEVICE");
	if (env_iface) {
		strncpy(iface, env_iface, IF_NAMESIZE - 1);
	}
}

int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
	int _errno;

	if (iface[0]) {
		/* preserve errno */
		_errno = errno;
		setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE,
			   (void*)iface, IF_NAMESIZE);
		errno = _errno;
	}
	return bind_original(sockfd, addr, addrlen);
}
