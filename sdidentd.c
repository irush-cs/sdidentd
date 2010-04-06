/*
 * Copyright (C) 2009-2010 Hebrew University Of Jerusalem, Israel
 * See the LICENSE file.
 *
 * Author: Yair Yarom <irush@cs.huji.ac.il>
 */

#include <stdio.h>
#include <sys/select.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <ctype.h>
#include <sys/sysctl.h>
#include <syslog.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <netinet/in.h>
#include <netinet/in_pcb.h>
#include <netinet/tcp.h>
#include <netinet/tcp_var.h>
#include <arpa/inet.h>
#include <pwd.h>

#define SYSTEMNAME "OSX"

const char* getaline() {
    fd_set rset;
    fd_set eset;
    struct timeval timeout = {60, 0};
    int i;
    char* p;
    static char* buffer = NULL;
    static int buffer_size = 0;
    static char* endp;

    // initial buffer
    if (buffer == NULL) {
        buffer_size = 512;
        if ((buffer = malloc(buffer_size)) == NULL) {
            exit(1);
        }
        buffer[0] = 0;
        endp = buffer;
    } else {
        // remove previous line
        p = buffer + strlen(buffer);
        while (*p == 0 && p < endp) p++;
        memmove(buffer, p, endp - p);
        endp = buffer + (endp - p);
        *endp = 0;
    }

    while (1) {
        // if there's a line, return it
        if ((p = strpbrk(buffer, "\r\n"))) {
            while (index("\r\n", *p)) {
                *p++ = 0;
            }
            break;
        }

        // read data
        FD_ZERO(&rset);
        FD_SET(0, &rset);
        FD_ZERO(&eset);
        FD_SET(0, &eset);
        i = select(1, &rset, NULL, &eset, &timeout);
        if (i <= 0) {
            free(buffer);
            exit(-i);
        }

        // exit on error
        if (FD_ISSET(0, &eset)) {
            break;
        }

        // resize buffer if needed
        if (endp - buffer == buffer_size - 1) {
            buffer_size *= 2;
            i = endp - buffer;
            if ((p = realloc(buffer, buffer_size))) {
                buffer = p;
            } else {
                free(buffer);
                exit(2);
            }
            endp = buffer + i;
        }

        // read as much as possible
        i = read(0, endp, buffer_size - (endp - buffer) - 1);
        if (i < 0) {
            free(buffer);
            exit(-i);
        }
        
        if (i == 0) {
            break;
        }

        endp += i;
        *endp = 0;
    }
    return buffer;
}

int parseline(const char* line, u_short* sport, u_short* cport) {
    const char* p = line;
    long l;

    // initial space
    while(*p && isspace(*p)) p++;
    if (!*p) return 0;

    // server port
    l = 0;
    while(*p && isdigit(*p)) {
        l = l * 10 + (*p - '0');
        if (l > 65535) 
            return 0;
        p++;
    }
    *sport = (u_short)l;
    if (!*p || sport == 0) return 0;

    // seperator
    while (*p && index(" \t,", *p)) p++;
    
    // client port
    l = 0;
    while(*p && isdigit(*p)) {
        l = l * 10 + (*p - '0');
        if (l > 65535)
            return 0;
        p++;
    }
    *cport = (u_short)l;
    if (cport == 0) return 0;

    // nothing else
    while (*p && isspace(*p)) p++;
    return *p == 0;
}

int findaddr(struct sockaddr_in* saddr, struct sockaddr_in* caddr) {
    struct sockaddr_in addr;
    socklen_t len = sizeof(addr);
    
    if (getsockname(0, (struct sockaddr*)&addr, &len) < 0) {
        syslog(LOG_ERR, "Can't get socket address: %s", strerror(errno));
        return 0;
    }

    if (addr.sin_family != PF_INET) {
        syslog(LOG_WARNING, "Supports only ipv4 for now");
        return 0;
    }

    memcpy(&(saddr->sin_addr), &(addr.sin_addr), sizeof(addr.sin_addr));

    if (getpeername(0, (struct sockaddr*)&addr, &len) < 0) {
        syslog(LOG_ERR, "Can't get socket peer: %s", strerror(errno));
        return 0;
    }

    memcpy(&(caddr->sin_addr), &(addr.sin_addr), sizeof(addr.sin_addr));
    
    return 1;
}


int finduser(const struct sockaddr_in* saddr, const struct sockaddr_in* caddr, char* name) {
    size_t buf_len;
    void* buf;
    int result = 0;
    struct xinpgen* xig;
    struct xtcpcb64* xtcb;
    struct xinpcb64* xicb;
    struct passwd* pwd;
    
    if (sysctlbyname("net.inet.tcp.pcblist64", 0, &buf_len, 0, 0) < 0) {
        syslog(LOG_ERR, "sysctl(net.inet.tcp.pcblist64) failed: %s\n", strerror(errno));
        return -1;
    }

    if ((buf = malloc(buf_len)) == NULL) {
        syslog(LOG_ERR, "malloc(%i) failed: %s", buf_len, strerror(errno));
        return -1;
    }

    if (sysctlbyname("net.inet.tcp.pcblist64", buf, &buf_len, 0, 0) < 0) {
        syslog(LOG_ERR, "sysctl(net.inet.tcp.pcblist64) failed: %s\n", strerror(errno));
        result = -1;
        goto founduser;
    }

    xig = (struct xinpgen*)buf;

    for (xtcb = (struct xtcpcb64*)((char*)xig + xig->xig_len);
         xtcb->xt_len != sizeof(struct xinpgen);
         xtcb = (struct xtcpcb64*)((char*)xtcb + xtcb->xt_len)) {
        xicb = &(xtcb->xt_inpcb);

        if (xicb->inp_dependladdr.inp46_local.ia46_addr4.s_addr == saddr->sin_addr.s_addr &&
            xicb->inp_dependfaddr.inp46_foreign.ia46_addr4.s_addr == caddr->sin_addr.s_addr &&
            xicb->inp_lport == saddr->sin_port &&
            xicb->inp_fport == caddr->sin_port) {
            errno = 0;
            if ((pwd = getpwuid(xicb->xi_socket.so_uid)) == NULL) {
                if (errno) {
                    syslog(LOG_ERR, "getpwuid(%i) errored: %s", xicb->xi_socket.so_uid, strerror(errno));
                } else {
                    syslog(LOG_ERR, "unknown owner for socket: %i", xicb->xi_socket.so_uid);
                }
                result = -1;
            } else {
                name[511] = 0;
                strncpy(name, pwd->pw_name, 511);
                result = 1;
            }
            goto founduser;
        }
    }

 founduser:
    free(buf);
    return result;
}

int main(int argc, char* argv[]) {
    const char* p;
    char pwname[512];
    struct sockaddr_in saddr, caddr;
    u_short sport, cport;
    int i;

    if (argc > 1) {
        printf("sdidentd 1.0\n\
Simple Darwin Ident Daemon\n\
Copyright (C) 2009-2010 Hebrew University Of Jerusalem, Israel\n\
Author: Yair Yarom <irush@cs.huji.ac.il>\n");
        return 0;
    }

    memset(&saddr, 0, sizeof(saddr));
    memset(&saddr, 0, sizeof(caddr));
    
    if (!findaddr(&saddr, &caddr)) {
        return 3;
    }

    for (p = getaline(); *p; fflush(stdout), p = getaline()) {
        if (!parseline(p, &sport, &cport)) {
            printf("%s : ERROR : INVALID-PORT\r\n", p);
            continue;
        }
        saddr.sin_port = htons(sport);
        caddr.sin_port = htons(cport);
        i = finduser(&saddr, &caddr, pwname);
        if (i == 0) {
            printf("%s : ERROR : NO-USER\r\n", p);
        } else if (i < 0) {
            printf("%s : ERROR : UNKNOWN-ERROR\r\n", p);
        } else {
            printf("%s : USERID : %s : %s\r\n", p, SYSTEMNAME, pwname);
        }
    }
    return 0;
}
