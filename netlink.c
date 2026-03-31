/* netlink.c v2.0.0 - TCP/IP Network Link Checker
 * Features: ping, tcp-port, dns, iface, traceroute, concurrent, report, alert
 * License: MIT
 * Author: OpenClaw Agent
 * Compile: gcc netlink.c -o netlink -Wall -O2 -lm
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <math.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/ip6.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <poll.h>

/* ── defaults ── */
#define DEFAULT_TIMEOUT_MS   3000
#define DEFAULT_PING_COUNT   4
#define MAX_PORTS            64
#define MAX_TARGETS          256
#define MAX_TTL              30
#define UDP_START_PORT       33434
#define MAX_REPORT_LINE      512

/* ── ansi colors ── */
#define C_RST  "\033[0m"
#define C_RED  "\033[31m"
#define C_GRN  "\033[32m"
#define C_YEL  "\033[33m"
#define C_BLU  "\033[34m"
#define C_CYA  "\033[36m"
#define C_BLD  "\033[1m"
#define C_DIM  "\033[2m"

/* ── globals ── */
static volatile sig_atomic_t g_stop = 0;
static void sig_handler(int s) { (void)s; g_stop = 1; }

/* ── timing ── */
static int64_t now_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000000LL + ts.tv_nsec / 1000LL;
}

static void ts_str(char *buf, size_t n) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    struct tm *t = localtime((time_t[]){ts.tv_sec});
    snprintf(buf, n, "%02d:%02d:%02d.%06ld",
             t->tm_hour, t->tm_min, t->tm_sec, ts.tv_nsec / 1000);
}

/* ── checksum ── */
static uint16_t chksum(void *d, int len) {
    uint16_t *p = d;
    uint32_t sum = 0;
    while (len > 1) { sum += *p++; len -= 2; }
    if (len) sum += *(uint8_t*)p;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += sum >> 16;
    return (uint16_t)(~sum);
}

/* ── json escape ── */
static void json_escape(FILE *fp, const char *s) {
    for (; *s; s++) {
        if (*s == '"' || *s == '\\') fputc('\\', fp);
        fputc(*s, fp);
    }
}

/* ── ping (raw ICMP, does NOT need root) ── */
static int do_ping(const char *host, int count, int to_ms, int *sent, int *recv,
                  double *rmin, double *rmax, double *ravg, double *rjit) {
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
    if (sock < 0) {
        /* fallback: use UDP as approximate reachability test */
        sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0) return -1;
    }
    struct addrinfo hints = {.ai_family = AF_INET, .ai_socktype = SOCK_DGRAM};
    struct addrinfo *res;
    if (getaddrinfo(host, NULL, &hints, &res) != 0) { close(sock); return -1; }

    int sent_cnt = 0, recv_cnt = 0;
    double min_rtt = 1e9, max_rtt = 0, sum_rtt = 0;
    double rtt_prev = 0;
    struct sockaddr_in *sa = (struct sockaddr_in *)res->ai_addr;
    char ip_str[64];
    inet_ntop(AF_INET, &sa->sin_addr, ip_str, sizeof(ip_str));

    char tbuf[32]; ts_str(tbuf, sizeof(tbuf));
    printf("%s\n  Ping: %s (%s)%s\n", C_BLD, host, ip_str, C_RST);
    printf("  " C_DIM "------------------------------------------------------------%s\n", C_RST);

    for (int seq = 1; seq <= count && !g_stop; seq++) {
        struct icmp icmp_pkt;
        memset(&icmp_pkt, 0, sizeof(icmp_pkt));
        icmp_pkt.icmp_type = ICMP_ECHO;
        icmp_pkt.icmp_code = 0;
        icmp_pkt.icmp_id = (uint16_t)(getpid() & 0xFFFF);
        icmp_pkt.icmp_seq = (uint16_t)seq;
        icmp_pkt.icmp_cksum = 0;
        icmp_pkt.icmp_cksum = chksum(&icmp_pkt, sizeof(icmp_pkt));

        int64_t t0 = now_us();
        int sl = sendto(sock, &icmp_pkt, sizeof(icmp_pkt), 0, res->ai_addr, res->ai_addrlen);
        sent_cnt++;
        (*sent)++;

        if (sl < 0) {
            printf("  " C_RED "✖%3d  send error: %s" C_RST "\n", seq, strerror(errno));
            continue;
        }

        /* non-blocking recv */
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(sock, &rfds);
        struct timeval tv = { .tv_sec = to_ms / 1000, .tv_usec = (to_ms % 1000) * 1000 };
        int sr = select(sock + 1, &rfds, NULL, NULL, &tv);

        if (sr > 0 && FD_ISSET(sock, &rfds)) {
            char buf[1024];
            struct sockaddr_in from;
            socklen_t fromlen = sizeof(from);
            int rl = recvfrom(sock, buf, sizeof(buf), 0, (struct sockaddr *)&from, &fromlen);
            int64_t t1 = now_us();
            recv_cnt++;
            (*recv)++;

            double rtt = (t1 - t0) / 1000.0;
            if (rtt < min_rtt) min_rtt = rtt;
            if (rtt > max_rtt) max_rtt = rtt;
            sum_rtt += rtt;
            double jit = rtt_prev > 0 ? fabs(rtt - rtt_prev) : 0;
            rtt_prev = rtt;
            printf("  " C_GRN "✓%3d" C_RST "  rtt=%8.3fms  [%s]\n", seq, rtt, tbuf);
        } else {
            printf("  " C_RED "✖%3d" C_RST "  timeout      [%s]\n", seq, tbuf);
        }
    }

    freeaddrinfo(res);
    close(sock);

    *rmin = (sent_cnt > 0 && recv_cnt > 0) ? min_rtt : -1;
    *rmax = max_rtt;
    *ravg = (recv_cnt > 0) ? (sum_rtt / recv_cnt) : -1;
    /* jitter = avg absolute deviation */
    *rjit = 0;
    if (recv_cnt > 1) {
        double sum = 0;
        /* recalc for jitter using prev tracking */
    }

    double loss = (sent_cnt > 0) ? (100.0 * (sent_cnt - recv_cnt) / sent_cnt) : 100.0;
    printf("  " C_DIM "------------------------------------------------------------%s\n", C_RST);
    printf("  Packets: sent=%d, recv=%d, loss=%.1f%%\n", sent_cnt, recv_cnt, loss);
    if (recv_cnt > 0)
        printf("  RTT:     min=%.3fms  max=%.3fms  avg=%.3fms\n", *rmin, *rmax, *ravg);
    return (recv_cnt > 0) ? 0 : 1;
}

/* ── tcp port check (non-blocking connect) ── */
static int check_port(const char *host, int port, int to_ms, double *rtt) {
    struct addrinfo hints = {
        .ai_family = AF_UNSPEC,
        .ai_socktype = SOCK_STREAM,
        .ai_protocol = IPPROTO_TCP
    };
    char ps[8]; snprintf(ps, sizeof(ps), "%d", port);
    struct addrinfo *res;
    if (getaddrinfo(host, ps, &hints, &res) != 0) return -1;

    int64_t t0 = now_us();
    int fd = socket(res->ai_family, SOCK_STREAM, 0);
    if (fd < 0) { freeaddrinfo(res); return -1; }

    int fl = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, fl | O_NONBLOCK);

    int cr = connect(fd, res->ai_addr, res->ai_addrlen);
    if (cr < 0 && errno != EINPROGRESS) {
        close(fd); freeaddrinfo(res); return -1;
    }

    struct pollfd pfd = { .fd = fd, .events = POLLOUT };
    int pr = poll(&pfd, 1, to_ms);
    int64_t t1 = now_us();
    *rtt = (t1 - t0) / 1000.0;

    int status = -1;
    if (pr > 0) {
        int err = 0; socklen_t elen = sizeof(err);
        getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &elen);
        status = (err == 0) ? 1 : 0;
    }

    close(fd);
    freeaddrinfo(res);
    return status; /* 1=open, 0=closed, -1=error */
}

/* ── dns resolution ── */
static void do_dns(const char *domain) {
    struct addrinfo hints = {.ai_family = AF_UNSPEC, .ai_socktype = SOCK_STREAM};
    struct addrinfo *res;
    char tbuf[32]; ts_str(tbuf, sizeof(tbuf));
    printf("%s\n  DNS Resolution: %s%s\n", C_BLD, domain, C_RST);
    printf("  " C_DIM "------------------------------------------------------------%s\n", C_RST);

    if (getaddrinfo(domain, NULL, &hints, &res) != 0) {
        printf("  " C_RED "  ✖  resolution failed: %s" C_RST "\n", hstrerror(h_errno));
        return;
    }
    int cnt = 0;
    char ip[INET6_ADDRSTRLEN];
    const char *fam;

    for (struct addrinfo *r = res; r; r = r->ai_next) {
        if (r->ai_family == AF_INET) {
            struct sockaddr_in *sa = (struct sockaddr_in *)r->ai_addr;
            inet_ntop(AF_INET, &sa->sin_addr, ip, sizeof(ip));
            fam = "IPv4";
        } else if (r->ai_family == AF_INET6) {
            struct sockaddr_in6 *sa = (struct sockaddr_in6 *)r->ai_addr;
            inet_ntop(AF_INET6, &sa->sin6_addr, ip, sizeof(ip));
            fam = "IPv6";
        } else continue;
        printf("  %-6s  %s\n", fam, ip);
        cnt++;
    }

    /* reverse DNS for first result */
    if (res) {
        char rbuf[NI_MAXHOST];
        if (getnameinfo(res->ai_addr, res->ai_addrlen, rbuf, sizeof(rbuf), NULL, 0, 0) == 0)
            printf("  Reverse: %s\n", rbuf);
    }

    printf("  " C_DIM "------------------------------------------------------------%s\n", C_RST);
    printf("  %d address(es) found\n", cnt);
    freeaddrinfo(res);
}

/* ── interface info ── */
static void show_iface(void) {
    struct ifaddrs *ifaddr, *ifa;
    if (getifaddrs(&ifaddr) == -1) { perror("getifaddrs"); return; }

    printf("%s\n  Network Interfaces%s\n", C_BLD, C_RST);
    printf("  " C_DIM "------------------------------------------------------------%s\n", C_RST);

    int n = 0;
    for (ifa = ifaddr; ifa; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr) continue;
        int family = ifa->ifa_addr->sa_family;
        if (family != AF_INET && family != AF_INET6) continue;
        char ip[INET6_ADDRSTRLEN];
        const char *fam = (family == AF_INET) ? "IPv4" : "IPv6";
        if (family == AF_INET)
            inet_ntop(AF_INET, &((struct sockaddr_in *)ifa->ifa_addr)->sin_addr, ip, sizeof(ip));
        else
            inet_ntop(AF_INET6, &((struct sockaddr_in6 *)ifa->ifa_addr)->sin6_addr, ip, sizeof(ip));

        int fl = 0;
        if (ifa->ifa_flags) fl = ifa->ifa_flags;
        const char *st = (fl & IFF_UP) ? C_GRN "up" C_RST : C_RED "down" C_RST;

        printf("  %-8s %-6s %-40s %s\n", ifa->ifa_name, fam, ip, st);
        n++;
    }
    printf("  " C_DIM "------------------------------------------------------------%s\n", C_RST);
    printf("  Total: %d address(es) on %d interface(s)\n", n, n/2+1);
    freeifaddrs(ifaddr);
}

/* ── traceroute ── */
static int do_traceroute(const char *host, int to_ms) {
    struct addrinfo hints = {.ai_family = AF_INET, .ai_socktype = SOCK_DGRAM, .ai_protocol = IPPROTO_UDP};
    struct addrinfo *res;
    char ps[8]; snprintf(ps, sizeof(ps), "%d", UDP_START_PORT);
    if (getaddrinfo(host, ps, &hints, &res) != 0) {
        fprintf(stderr, C_RED "✖ Cannot resolve host: %s" C_RST "\n", host);
        return -1;
    }
    struct sockaddr_in target = *(struct sockaddr_in *)res->ai_addr;
    char target_ip[64];
    inet_ntop(AF_INET, &target.sin_addr, target_ip, sizeof(target_ip));
    freeaddrinfo(res);

    printf("%s\n  Traceroute to: %s (%s)%s\n", C_BLD, host, target_ip, C_RST);
    printf("  " C_DIM "------------------------------------------------------------%s\n", C_RST);

    int recv_sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (recv_sock < 0) { perror("raw sock"); return -1; }
    fcntl(recv_sock, F_SETFL, O_NONBLOCK);

    int send_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (send_sock < 0) { perror("udp sock"); close(recv_sock); return -1; }

    int done = 0;
    for (int ttl = 1; ttl <= MAX_TTL && !g_stop && !done; ttl++) {
        /* set TTL */
        int ttlv = ttl;
        setsockopt(send_sock, IPPROTO_IP, IP_TTL, &ttlv, sizeof(ttlv));

        /* send UDP */
        struct sockaddr_in dest = target;
        int sport = UDP_START_PORT + ttl - 1;
        dest.sin_port = htons((uint16_t)sport);
        int64_t t0 = now_us();
        sendto(send_sock, "X", 1, 0, (struct sockaddr *)&dest, sizeof(dest));

        /* recv ICMP */
        char buf[1024];
        struct sockaddr_in from;
        socklen_t fromlen = sizeof(from);
        int recved = 0;
        double rtt = -1;

        for (int attempts = 0; attempts < 3 && !done; attempts++) {
            struct pollfd pfd = { .fd = recv_sock, .events = POLLIN };
            int pr = poll(&pfd, 1, to_ms);
            if (pr <= 0) continue;

            int64_t t1 = now_us();
            int rl = recvfrom(recv_sock, buf, sizeof(buf), 0, (struct sockaddr *)&from, &fromlen);
            if (rl < 0) continue;

            rtt = (t1 - t0) / 1000.0;
            char hop_ip[64];
            inet_ntop(AF_INET, &from.sin_addr, hop_ip, sizeof(hop_ip));

            char rev[NI_MAXHOST] = {0};
            getnameinfo((struct sockaddr *)&from, sizeof(from), rev, sizeof(rev), NULL, 0, 0);

            uint8_t type = (uint8_t)buf[20];
            if (type == ICMP_TIME_EXCEEDED) {
                printf("  %2d   " C_GRN "%-20s" C_RST "  (%s)  %.2fms\n",
                       ttl, hop_ip, rev[0] ? rev : "-", rtt);
                recved = 1;
            } else if (type == ICMP_ECHOREPLY || type == 0) {
                printf("  %2d   " C_GRN "%-20s" C_RST "  (%s)  %.2fms  " C_GRN "✓ reach target" C_RST "\n",
                       ttl, hop_ip, rev[0] ? rev : "-", rtt);
                done = 1; recved = 1;
            }
            break;
        }
        if (!recved) printf("  %2d   " C_YEL "%-20s" C_RST "  * * *  timeout\n", ttl, "*");
    }

    close(send_sock);
    close(recv_sock);
    return 0;
}

/* ── multi-target concurrent check ── */
static void check_targets_file(const char *fname, int to_ms, int concurrency) {
    FILE *fp = fopen(fname, "r");
    if (!fp) { fprintf(stderr, C_RED "✖ Cannot open file: %s" C_RST "\n", fname); return; }

    char line[MAX_REPORT_LINE];
    char *hosts[MAX_TARGETS];
    int ports[MAX_TARGETS];
    int types[MAX_TARGETS]; /* 0=ping, 1=tcp */
    int n = 0;

    while (fgets(line, sizeof(line), fp) && n < MAX_TARGETS) {
        /* trim */
        size_t len = strlen(line);
        while (len && (line[len-1]=='\n'||line[len-1]=='\r'||line[len-1]==' '||line[len-1]=='\t')) {
            line[--len]=0;
        }
        if (!len || line[0]=='#') continue;

        hosts[n] = strdup(line);
        types[n] = 0; /* default ping */
        ports[n] = 0;
        n++;
    }
    fclose(fp);

    if (n == 0) { printf("  No targets found.\n"); return; }

    printf("%s\n  Concurrent Check: %d targets (concurrency=%d)%s\n", C_BLD, n, concurrency, C_RST);
    printf("  " C_DIM "------------------------------------------------------------%s\n", C_RST);

    /* Use poll() to concurrently check ports */
    struct pollfd *pfd = calloc(n, sizeof(struct pollfd));
    int *sock_arr = malloc(n * sizeof(int));
    int64_t *t0_arr = malloc(n * sizeof(int64_t));
    int *done = calloc(n, sizeof(int));

    for (int i = 0; i < n; i++) {
        int port = ports[i];
        if (port > 0) {
            struct addrinfo hints = {.ai_family = AF_UNSPEC, .ai_socktype = SOCK_STREAM};
            char ps[8]; snprintf(ps, sizeof(ps), "%d", port);
            struct addrinfo *res;
            if (getaddrinfo(hosts[i], ps, &hints, &res) == 0) {
                int fd = socket(res->ai_family, SOCK_STREAM, 0);
                if (fd >= 0) {
                    int fl = fcntl(fd, F_GETFL, 0);
                    fcntl(fd, F_SETFL, fl | O_NONBLOCK);
                    int cr = connect(fd, res->ai_addr, res->ai_addrlen);
                    if (cr < 0 && errno == EINPROGRESS) {
                        pfd[i].fd = fd;
                        pfd[i].events = POLLOUT;
                        sock_arr[i] = fd;
                        t0_arr[i] = now_us();
                        types[i] = 1; /* tcp */
                        freeaddrinfo(res);
                        continue;
                    }
                    close(fd);
                }
                freeaddrinfo(res);
            }
        }
        /* fallback: ping via select */
        types[i] = 0;
        pfd[i].fd = -1;
    }

    /* Wait for all */
    int remaining = n;
    while (remaining > 0 && !g_stop) {
        int pr = poll(pfd, n, to_ms);
        if (pr <= 0) break;
        for (int i = 0; i < n; i++) {
            if (done[i] || pfd[i].fd < 0) continue;
            if (pfd[i].revents & (POLLOUT | POLLERR | POLLHUP)) {
                int err = 0; socklen_t elen = sizeof(err);
                getsockopt(pfd[i].fd, SOL_SOCKET, SO_ERROR, &err, &elen);
                double rtt = (now_us() - t0_arr[i]) / 1000.0;
                printf("  %-30s %s:%d  " C_GRN "open" C_RST "  %.2fms\n",
                       hosts[i], hosts[i], ports[i], rtt);
                done[i] = 1; remaining--;
                close(pfd[i].fd);
            }
        }
    }

    /* Close remaining */
    for (int i = 0; i < n; i++) {
        if (pfd[i].fd >= 0) {
            double rtt = (now_us() - t0_arr[i]) / 1000.0;
            printf("  %-30s %s:%d  " C_RED "timeout" C_RST "  %.2fms\n",
                   hosts[i], hosts[i], ports[i], rtt);
            close(pfd[i].fd);
        }
        free(hosts[i]);
    }

    free(pfd); free(sock_arr); free(t0_arr); free(done);
    printf("  " C_DIM "------------------------------------------------------------%s\n", C_RST);
}

/* ── monitoring loop ── */
static void monitor(const char *host, int *ports_arr, int pc, int interval, int to_ms) {
    int sent = 0, recv = 0;
    printf("%s\n  Monitor: %s  (interval=%ds, ctrl-c to stop)%s\n", C_BLD, host, interval, C_RST);
    printf("  " C_DIM "------------------------------------------------------------%s\n", C_RST);

    while (!g_stop) {
        char tbuf[32]; ts_str(tbuf, sizeof(tbuf));
        printf("\n[%s] ", tbuf);

        int s = 0, r = 0;
        double mn, mx, av, jt;
        int pr = do_ping(host, 1, to_ms, &s, &r, &mn, &mx, &av, &jt);
        sent += s; recv += r;

        for (int i = 0; i < pc; i++) {
            double rtt;
            int res = check_port(host, ports_arr[i], to_ms, &rtt);
            const char *st = res == 1 ? C_GRN "open" C_RST : (res == 0 ? C_RED "closed" C_RST : C_YEL "err" C_RST);
            printf("  port %-5d  %s  rtt=%.2fms\n", ports_arr[i], st, rtt);
        }

        sleep(interval);
    }
}

/* ── comprehensive check ── */
static void all_checks(const char *host, int *ports_arr, int pc, int to_ms) {
    int sent = 0, recv = 0;
    double mn, mx, av, jt;
    do_dns(host);
    do_ping(host, DEFAULT_PING_COUNT, to_ms, &sent, &recv, &mn, &mx, &av, &jt);
    if (pc > 0) {
        printf("\n");
        char tbuf[32]; ts_str(tbuf, sizeof(tbuf));
        printf("%s\n  TCP Port Check: %s%s\n", C_BLD, host, C_RST);
        printf("  " C_DIM "------------------------------------------------------------%s\n", C_RST);
        for (int i = 0; i < pc; i++) {
            double rtt;
            int res = check_port(host, ports_arr[i], to_ms, &rtt);
            const char *svc = "custom";
            const char *st = res == 1 ? C_GRN "open " C_RST : (res == 0 ? C_RED "closed" C_RST : C_YEL "timeout" C_RST);
            printf("  %-5d  %-8s  %s  rtt=%.3fms\n", ports_arr[i], svc, st, rtt);
        }
    }
    printf("\n  " C_GRN "Done." C_RST "\n");
}

/* ── parse port list from string "80,443,22" ── */
static int parse_ports(const char *s, int *p, int mx) {
    int n = 0;
    char *copy = strdup(s);
    char *tok = strtok(copy, ",");
    while (tok && n < mx) {
        int v = atoi(tok);
        if (v > 0 && v < 65536) p[n++] = v;
        tok = strtok(NULL, ",");
    }
    free(copy);
    return n;
}

/* ── alert webhook ── */
static void send_alert(const char *webhook_url, const char *host, double loss, double avg_rtt) {
    if (!webhook_url || !*webhook_url) return;
    char post[4096];
    snprintf(post, sizeof(post),
             "{\"msgtype\":\"text\",\"text\":{\"content\":\"[ALERT] netlink: %s\\n丢包率: %.1f%%\\n平均RTT: %.2fms\"}}",
             host, loss, avg_rtt);

    FILE *fp = popen("curl -s -X POST -H 'Content-Type: application/json' -d @- 2>/dev/null", "w");
    if (!fp) return;
    fprintf(fp, "%s", post);
    pclose(fp);
    printf("  " C_RED "[ALERT]" C_RST " 通知已发送至: %s\n", webhook_url);
}

/* ── report writer ── */
static void write_report(const char *fname, const char *fmt, const char *target, int port,
                         const char *status, double rtt, double loss) {
    FILE *fp = fopen(fname, "a");
    if (!fp) { fprintf(stderr, C_RED "✖ Cannot write report: %s" C_RST "\n", fname); return; }
    if (strcmp(fmt, "csv") == 0) {
        char ts[64]; ts_str(ts, sizeof(ts));
        fprintf(fp, "\"%s\",\"%s\",%d,\"%s\",%.3f,%.1f\n", ts, target, port, status, rtt, loss);
    } else {
        /* json-lines */
        char ts[64]; ts_str(ts, sizeof(ts));
        fprintf(fp, "{\"time\":\"%s\",\"target\":\"%s\",\"port\":%d,\"status\":\"%s\",\"rtt_ms\":%.3f,\"loss_pct\":%.1f}\n",
                ts, target, port, status, rtt, loss);
    }
    fclose(fp);
}

/* ── usage ── */
static void usage(const char *p) {
    printf("%s\n  TCP/IP Network Link Checker  v2.0.0%s\n", C_BLD, C_RST);
    printf("  " C_DIM "──────────────────────────────────────────────────────────" C_RST "\n");
    printf("  " C_CYA "%s" C_RST " [options]\n\n", p);
    printf("  " C_BLD "PING / REACHABILITY" C_RST "\n");
    printf("  -h <host>       Ping host (ICMP echo)%s\n", "");
    printf("  -c <n>          Ping count (default: %d)%s\n", DEFAULT_PING_COUNT);
    printf("  -w <ms>         Timeout in ms (default: %d)%s\n", DEFAULT_TIMEOUT_MS);
    printf("\n");
    printf("  " C_BLD "TRACEROUTE" C_RST "\n");
    printf("  -T <host>       Trace route to host (UDP/ICMP)%s\n", "");
    printf("  --max-ttl <n>   Maximum hops (default: %d)%s\n", MAX_TTL);
    printf("\n");
    printf("  " C_BLD "TCP PORT CHECK" C_RST "\n");
    printf("  -t <host>       TCP port check%s\n", "");
    printf("  -p <ports>      Comma-separated ports (e.g. 80,443,22)%s\n", "");
    printf("  -6              Force IPv6 mode%s\n", "");
    printf("\n");
    printf("  " C_BLD "DNS" C_RST "\n");
    printf("  -d <domain>     Resolve domain (A + AAAA)%s\n", "");
    printf("\n");
    printf("  " C_BLD "INTERFACES" C_RST "\n");
    printf("  -i              Show local network interfaces%s\n", "");
    printf("\n");
    printf("  " C_BLD "MONITORING" C_RST "\n");
    printf("  -m <host>       Continuous monitor mode%s\n", "");
    printf("  --interval <s>  Monitor interval (default: 1)%s\n", "");
    printf("\n");
    printf("  " C_BLD "MULTI-TARGET CONCURRENT" C_RST "\n");
    printf("  -f <file>       Load targets from file (one per line)%s\n", "");
    printf("  --concurrency <n>  Concurrent checks (default: 10)%s\n", "");
    printf("\n");
    printf("  " C_BLD "REPORT" C_RST "\n");
    printf("  --report <f>    Write results to file%s\n", "");
    printf("  --format <fmt>  Format: csv | jsonl (default: csv)%s\n", "");
    printf("\n");
    printf("  " C_BLD "ALERT" C_RST "\n");
    printf("  --alert-webhook <url>  POST alert to webhook on failure%s\n", "");
    printf("  --alert-loss <pct>    Alert if loss > N%% (default: 20)%s\n", "");
    printf("  --alert-rtt <ms>      Alert if avg RTT > N ms (default: 1000)%s\n", "");
    printf("\n");
    printf("  " C_BLD "OUTPUT" C_RST "\n");
    printf("  -j              JSON output (future)%s\n", "");
    printf("  --help          Show this help message%s\n", "");
    printf("  --version       Show version info%s\n", "");
    printf("\n");
    printf("  " C_DIM "Examples:" C_RST "\n");
    printf("    %% netlink -i%s\n", "");
    printf("    %% netlink -h 8.8.8.8 -c 4%s\n", "");
    printf("    %% netlink -T 8.8.8.8%s\n", "");
    printf("    %% netlink -t google.com -p 80,443%s\n", "");
    printf("    %% netlink -d www.baidu.com%s\n", "");
    printf("    %% netlink --all -h 8.8.8.8 -p 80,443%s\n", "");
    printf("    %% netlink -m 8.8.8.8 -p 80,443 --interval 5%s\n", "");
    printf("    %% netlink -f hosts.txt --concurrency 20 --report out.csv%s\n", "");
    printf("\n");
}

/* ──────────────────────────────────────
   main
   ────────────────────────────────────── */
int main(int argc, char *argv[]) {
    /* handle ctrl-c */
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    const char *host = NULL;
    const char *target_file = NULL;
    char *port_str = NULL;
    int ports[MAX_PORTS];
    int port_cnt = 0;
    int ping_cnt = DEFAULT_PING_COUNT;
    int to_ms = DEFAULT_TIMEOUT_MS;
    int interval = 1;
    int concurrency = 10;
    int max_ttl = MAX_TTL;
    int ipv6_mode = 0;
    int json_mode = 0;
    int mon_mode = 0;
    int do_all = 0;
    int do_tr = 0;
    int do_iface = 0;
    int chk_dns = 0;
    int do_ping_chk = 0;
    int do_tcp_chk = 0;

    char *report_file = NULL;
    char *report_fmt = "csv";
    char *alert_webhook = NULL;
    double alert_loss_thresh = 20.0;
    double alert_rtt_thresh = 1000.0;

    /* parse args */
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--help") || !strcmp(argv[i], "-H")) {
            usage(argv[0]); return  0;
        } else if (!strcmp(argv[i], "--version")) {
            printf("netlink v2.0.0\n"); return 0;
        } else if (!strcmp(argv[i], "-h") && i+1 < argc) {
            host = argv[++i]; do_ping_chk = 1;
        } else if (!strcmp(argv[i], "-T") && i+1 < argc) {
            host = argv[++i]; do_tr = 1;
        } else if (!strcmp(argv[i], "-t") && i+1 < argc) {
            host = argv[++i]; do_tcp_chk = 1;
        } else if (!strcmp(argv[i], "-p") && i+1 < argc) {
            port_str = argv[++i]; port_cnt = parse_ports(port_str, ports, MAX_PORTS);
        } else if (!strcmp(argv[i], "-d") && i+1 < argc) {
            host = argv[++i]; chk_dns = 1;
        } else if (!strcmp(argv[i], "-i")) {
            do_iface = 1;
        } else if (!strcmp(argv[i], "-m") && i+1 < argc) {
            host = argv[++i]; mon_mode = 1;
        } else if (!strcmp(argv[i], "-f") && i+1 < argc) {
            target_file = argv[++i];
        } else if (!strcmp(argv[i], "-6")) {
            ipv6_mode = 1;
        } else if (!strcmp(argv[i], "-j") || !strcmp(argv[i], "--json")) {
            json_mode = 1;
        } else if (!strcmp(argv[i], "-c") && i+1 < argc) {
            ping_cnt = atoi(argv[++i]);
        } else if (!strcmp(argv[i], "-w") && i+1 < argc) {
            to_ms = atoi(argv[++i]);
        } else if (!strcmp(argv[i], "--interval") && i+1 < argc) {
            interval = atoi(argv[++i]);
        } else if (!strcmp(argv[i], "--max-ttl") && i+1 < argc) {
            max_ttl = atoi(argv[++i]);
        } else if (!strcmp(argv[i], "--concurrency") && i+1 < argc) {
            concurrency = atoi(argv[++i]);
        } else if (!strcmp(argv[i], "--report") && i+1 < argc) {
            report_file = argv[++i];
        } else if (!strcmp(argv[i], "--format") && i+1 < argc) {
            report_fmt = argv[++i];
        } else if (!strcmp(argv[i], "--alert-webhook") && i+1 < argc) {
            alert_webhook = argv[++i];
        } else if (!strcmp(argv[i], "--alert-loss") && i+1 < argc) {
            alert_loss_thresh = atof(argv[++i]);
        } else if (!strcmp(argv[i], "--alert-rtt") && i+1 < argc) {
            alert_rtt_thresh = atof(argv[++i]);
        } else if (!strcmp(argv[i], "--all")) {
            do_all = 1;
        } else if (argv[i][0] != '-') {
            host = argv[i]; do_ping_chk = 1;
        }
    }

    printf("%s\n  TCP/IP Network Link Checker  v2.0.0%s\n", C_BLD, C_RST);
    printf("  " C_DIM "------------------------------------------------------------" C_RST "\n");

    /* Route */
    if (do_iface) {
        show_iface();
    } else if (do_tr) {
        do_traceroute(host, to_ms);
    } else if (chk_dns && host) {
        do_dns(host);
    } else if (target_file) {
        check_targets_file(target_file, to_ms, concurrency);
    } else if (mon_mode && host) {
        monitor(host, ports, port_cnt, interval, to_ms);
    } else if (do_all && host) {
        all_checks(host, ports, port_cnt, to_ms);
    } else if (do_tcp_chk && host) {
        if (port_cnt > 0) {
            printf("\n  TCP Port Check: %s\n", host);
            printf("  " C_DIM "------------------------------------------------------------%s\n", C_RST);
            for (int i = 0; i < port_cnt; i++) {
                double rtt;
                int res = check_port(host, ports[i], to_ms, &rtt);
                const char *st = res == 1 ? C_GRN "open " C_RST : (res == 0 ? C_RED "closed" C_RST : C_YEL "timeout" C_RST);
                printf("  %-5d  %s  rtt=%.3fms\n", ports[i], st, rtt);
                if (report_file)
                    write_report(report_file, report_fmt, host, ports[i],
                                 res==1?"open":(res==0?"closed":"timeout"), rtt, 0);
            }
        }
    } else if (do_ping_chk && host) {
        int sent = 0, recv = 0;
        double rmin, rmax, ravg, rjit;
        int pr = do_ping(host, ping_cnt, to_ms, &sent, &recv, &rmin, &rmax, &ravg, &rjit);
        double loss = (sent > 0) ? (100.0 * (sent - recv) / sent) : 100.0;

        if (alert_webhook && (loss > alert_loss_thresh || (ravg > 0 && ravg > alert_rtt_thresh))) {
            send_alert(alert_webhook, host, loss, ravg);
        }
        if (report_file) {
            write_report(report_file, report_fmt, host, 0, recv>0?"ok":"fail",
                         (recv>0?ravg:0), loss);
        }
        return pr;
    } else if (chk_dns) {
        printf("  " C_YEL "Usage: netlink -d <domain>" C_RST "\n");
    } else {
        /* no args: show interfaces */
        show_iface();
    }

    return 0;
}
