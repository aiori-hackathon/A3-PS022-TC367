/* ==============================================================================
 * Kavach PS-022: High-Performance Synthetic DNS Traffic Generator (C)
 * Submission ID: A3-PS022-TC367
 *
 * Implements synthetic load generation for:
 *   - Mode S1: Single source constant-rate flood
 *   - Mode S2: Distributed flood (~1,000 random sources from 198.18.0.0/15)
 *   - Mode S3: Pulsing burst flood (0.5x, 1x, 2x burst tolerance, period <= 10s)
 *   - Mode Ceiling: Saturation benchmark to measure generator host maximum PPS
 *
 * Strictly enforces Generator Safety Guard boundaries:
 *   - Destination Target IP MUST belong to 10.99.0.0/24 (exits with code 100 if outside)
 *   - Synthetic Source IPs MUST belong to 198.18.0.0/15 or 10.99.0.1 (exit code 100)
 *   - /proc/sys/net/ipv4/ip_forward MUST be 0 (exit code 100)
 * ==============================================================================
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <sys/socket.h>
#include <sys/types.h>

#define ERR_SECURITY_VIOLATION 100

static volatile sig_atomic_t g_running = 1;

static void sigint_handler(int sig) {
    (void)sig;
    g_running = 0;
}

/* --------------------------------------------------------------------------
 * Safety Guard Validation Functions
 * -------------------------------------------------------------------------- */

static void enforce_ip_forward_zero(void) {
    int fd = open("/proc/sys/net/ipv4/ip_forward", O_RDONLY);
    if (fd >= 0) {
        char buf[8] = {0};
        ssize_t n = read(fd, buf, sizeof(buf) - 1);
        close(fd);
        if (n > 0 && buf[0] != '0') {
            fprintf(stderr, "\033[1;31m[FATAL SECURITY VIOLATION] net.ipv4.ip_forward is not 0 (found: %c)!\n"
                            "Must be 0 to prevent spoofed reply leakage. Run: sudo sysctl -w net.ipv4.ip_forward=0\033[0m\n", buf[0]);
            exit(ERR_SECURITY_VIOLATION);
        }
    }
}

static void enforce_target_ip(uint32_t target_ip_net) {
    uint32_t ip = ntohl(target_ip_net);
    // 10.99.0.0/24: 0x0A630000 to 0x0A6300FF
    uint32_t net = 0x0A630000;
    uint32_t mask = 0xFFFFFF00;
    if ((ip & mask) != net || (ip == 0x0A630000) || (ip == 0x0A6300FF)) {
        char buf[INET_ADDRSTRLEN];
        struct in_addr addr;
        addr.s_addr = target_ip_net;
        inet_ntop(AF_INET, &addr, buf, sizeof(buf));
        fprintf(stderr, "\033[1;31m[FATAL SECURITY VIOLATION] Target IP '%s' is OUTSIDE the lab subnet (10.99.0.0/24)!\033[0m\n", buf);
        exit(ERR_SECURITY_VIOLATION);
    }
}

static void enforce_source_ip(uint32_t src_ip_net) {
    uint32_t ip = ntohl(src_ip_net);
    // Permitted: 10.99.0.1 (legitimate client)
    if (ip == 0x0A630001) {
        return;
    }
    // Permitted: 198.18.0.0/15 (0xC6120000, mask 0xFFFE0000)
    uint32_t bench_net = 0xC6120000;
    uint32_t bench_mask = 0xFFFE0000;
    if ((ip & bench_mask) != bench_net) {
        char buf[INET_ADDRSTRLEN];
        struct in_addr addr;
        addr.s_addr = src_ip_net;
        inet_ntop(AF_INET, &addr, buf, sizeof(buf));
        fprintf(stderr, "\033[1;31m[FATAL SECURITY VIOLATION] Source IP '%s' is not in permitted benchmark range (198.18.0.0/15)!\033[0m\n", buf);
        exit(ERR_SECURITY_VIOLATION);
    }
}

/* --------------------------------------------------------------------------
 * Checksum and Packet Construction
 * -------------------------------------------------------------------------- */

static uint16_t checksum(const void *data, size_t len) {
    const uint16_t *p = (const uint16_t *)data;
    uint32_t sum = 0;
    while (len > 1) {
        sum += *p++;
        len -= 2;
    }
    if (len == 1) {
        sum += *(const uint8_t *)p;
    }
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return (uint16_t)(~sum);
}

/* Build RFC 1035 UDP/53 DNS Query packet for www.lab.test */
static size_t build_dns_packet(uint8_t *buf, uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, uint16_t dst_port, uint16_t seq) {
    struct iphdr *ip = (struct iphdr *)buf;
    struct udphdr *udp = (struct udphdr *)(buf + sizeof(struct iphdr));
    uint8_t *dns = buf + sizeof(struct iphdr) + sizeof(struct udphdr);

    // DNS Header (12 bytes)
    dns[0] = (uint8_t)(seq >> 8);
    dns[1] = (uint8_t)(seq & 0xFF);
    dns[2] = 0x01; // RD = 1 (Recursion Desired)
    dns[3] = 0x00;
    dns[4] = 0x00; dns[5] = 0x01; // QDCOUNT = 1
    dns[6] = 0x00; dns[7] = 0x00; // ANCOUNT = 0
    dns[8] = 0x00; dns[9] = 0x00; // NSCOUNT = 0
    dns[10] = 0x00; dns[11] = 0x00; // ARCOUNT = 0

    // Question Section: "www.lab.test", Type A, Class IN
    // \x03www\x03lab\x04test\x00
    uint8_t *q = dns + 12;
    q[0] = 3; memcpy(q + 1, "www", 3);
    q[4] = 3; memcpy(q + 5, "lab", 3);
    q[8] = 4; memcpy(q + 9, "test", 4);
    q[13] = 0; // Terminating root label
    q[14] = 0x00; q[15] = 0x01; // QTYPE = A (1)
    q[16] = 0x00; q[17] = 0x01; // QCLASS = IN (1)

    size_t dns_len = 12 + 18;
    size_t udp_len = sizeof(struct udphdr) + dns_len;
    size_t total_len = sizeof(struct iphdr) + udp_len;

    // UDP Header
    udp->source = htons(src_port);
    udp->dest = htons(dst_port);
    udp->len = htons((uint16_t)udp_len);
    udp->check = 0; // Legal for IPv4 UDP

    // IPv4 Header
    ip->version = 4;
    ip->ihl = 5;
    ip->tos = 0;
    ip->tot_len = htons((uint16_t)total_len);
    ip->id = htons(seq);
    ip->frag_off = 0;
    ip->ttl = 64;
    ip->protocol = IPPROTO_UDP;
    ip->check = 0;
    ip->saddr = src_ip;
    ip->daddr = dst_ip;
    ip->check = checksum(ip, sizeof(struct iphdr));

    return total_len;
}

static inline uint64_t get_time_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

/* --------------------------------------------------------------------------
 * Execution Modes
 * -------------------------------------------------------------------------- */

static int run_ceiling(int sock, uint32_t target_ip, uint16_t target_port, double duration) {
    printf("[INFO] Running Ceiling Benchmark to %s:%u for %.1fs...\n", "10.99.0.2", target_port, duration);
    uint32_t src_ip = inet_addr("198.18.0.10");
    uint8_t pkt[128];
    size_t pkt_len = build_dns_packet(pkt, src_ip, target_ip, 12345, target_port, 1);

    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_port = htons(target_port);
    dst.sin_addr.s_addr = target_ip;

    uint64_t start_ns = get_time_ns();
    uint64_t end_ns = start_ns + (uint64_t)(duration * 1e9);
    uint64_t count = 0;

    while (g_running && get_time_ns() < end_ns) {
        if (sendto(sock, pkt, pkt_len, 0, (struct sockaddr *)&dst, sizeof(dst)) > 0) {
            count++;
        }
    }

    uint64_t elapsed_ns = get_time_ns() - start_ns;
    double elapsed_s = (double)elapsed_ns / 1e9;
    double pps = (double)count / (elapsed_s > 0 ? elapsed_s : 1.0);
    printf("[RESULT] Ceiling: Transmitted %llu packets in %.3fs (Rate: %.0f pps)\n",
           (unsigned long long)count, elapsed_s, pps);
    return 0;
}

static int run_s1(int sock, uint32_t target_ip, uint16_t target_port, uint32_t src_ip, uint32_t rate_pps, double duration) {
    printf("[INFO] Running Scenario S1 (Single Source) -> Target: 10.99.0.2:%u, Rate: %u pps, Duration: %.1fs\n",
           target_port, rate_pps, duration);

    uint8_t pkt[128];
    size_t pkt_len = build_dns_packet(pkt, src_ip, target_ip, 23456, target_port, 1);

    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_port = htons(target_port);
    dst.sin_addr.s_addr = target_ip;

    uint64_t interval_ns = rate_pps > 0 ? (1000000000ULL / rate_pps) : 0;
    uint64_t start_ns = get_time_ns();
    uint64_t end_ns = start_ns + (uint64_t)(duration * 1e9);
    uint64_t next_send_ns = start_ns;
    uint64_t count = 0;
    uint16_t seq = 0;

    while (g_running) {
        uint64_t now = get_time_ns();
        if (now >= end_ns) break;

        if (now >= next_send_ns) {
            seq++;
            pkt_len = build_dns_packet(pkt, src_ip, target_ip, 23456, target_port, seq);
            if (sendto(sock, pkt, pkt_len, 0, (struct sockaddr *)&dst, sizeof(dst)) > 0) {
                count++;
            }
            next_send_ns += interval_ns;
            if (next_send_ns < now) {
                next_send_ns = now; // Prevent burst catch-up drift
            }
        } else {
            uint64_t diff = next_send_ns - now;
            if (diff > 100000) { // > 100us
                struct timespec ts;
                ts.tv_sec = 0;
                ts.tv_nsec = (long)(diff - 50000);
                nanosleep(&ts, NULL);
            }
        }
    }

    uint64_t elapsed_ns = get_time_ns() - start_ns;
    double elapsed_s = (double)elapsed_ns / 1e9;
    printf("[RESULT] S1 Finished: Sent %llu packets in %.2fs (Effective: %.0f pps)\n",
           (unsigned long long)count, elapsed_s, (double)count / (elapsed_s > 0 ? elapsed_s : 1.0));
    return 0;
}

static int run_s2(int sock, uint32_t target_ip, uint16_t target_port, int num_sources, uint32_t rate_pps, double duration) {
    if (num_sources <= 0) num_sources = 1000;
    printf("[INFO] Running Scenario S2 (Distributed Flood) -> Target: 10.99.0.2:%u, %d Sources from 198.18.0.0/15, Rate: %u pps, Duration: %.1fs\n",
           target_port, num_sources, rate_pps, duration);

    // Pre-populate pool of random source IPs strictly inside 198.18.0.0/15
    uint32_t *src_pool = (uint32_t *)malloc(num_sources * sizeof(uint32_t));
    if (!src_pool) {
        perror("malloc");
        return 1;
    }

    srand(12345);
    for (int i = 0; i < num_sources; i++) {
        // 198.18.0.0/15 has 131,072 IPs: 198.18.0.1 to 198.19.255.254
        uint32_t offset = 1 + (rand() % 131070);
        uint32_t ip = 0xC6120000 + offset;
        src_pool[i] = htonl(ip);
        enforce_source_ip(src_pool[i]);
    }

    uint8_t pkt[128];
    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_port = htons(target_port);
    dst.sin_addr.s_addr = target_ip;

    uint64_t interval_ns = rate_pps > 0 ? (1000000000ULL / rate_pps) : 0;
    uint64_t start_ns = get_time_ns();
    uint64_t end_ns = start_ns + (uint64_t)(duration * 1e9);
    uint64_t next_send_ns = start_ns;
    uint64_t count = 0;
    int src_idx = 0;
    uint16_t seq = 0;

    while (g_running) {
        uint64_t now = get_time_ns();
        if (now >= end_ns) break;

        if (now >= next_send_ns) {
            seq++;
            uint32_t s_ip = src_pool[src_idx];
            src_idx = (src_idx + 1) % num_sources;

            size_t pkt_len = build_dns_packet(pkt, s_ip, target_ip, 30000 + (src_idx % 10000), target_port, seq);
            if (sendto(sock, pkt, pkt_len, 0, (struct sockaddr *)&dst, sizeof(dst)) > 0) {
                count++;
            }
            next_send_ns += interval_ns;
            if (next_send_ns < now) {
                next_send_ns = now;
            }
        } else {
            uint64_t diff = next_send_ns - now;
            if (diff > 100000) {
                struct timespec ts;
                ts.tv_sec = 0;
                ts.tv_nsec = (long)(diff - 50000);
                nanosleep(&ts, NULL);
            }
        }
    }

    free(src_pool);
    uint64_t elapsed_ns = get_time_ns() - start_ns;
    double elapsed_s = (double)elapsed_ns / 1e9;
    printf("[RESULT] S2 Finished: Sent %llu packets across %d sources in %.2fs (Effective: %.0f pps)\n",
           (unsigned long long)count, num_sources, elapsed_s, (double)count / (elapsed_s > 0 ? elapsed_s : 1.0));
    return 0;
}

static int run_s3(int sock, uint32_t target_ip, uint16_t target_port, uint32_t src_ip, int burst, double multiplier, double period_s, double duration) {
    int pulse_packets = (int)(burst * multiplier);
    if (pulse_packets < 1) pulse_packets = 1;
    if (period_s <= 0.0) period_s = 5.0;

    printf("[INFO] Running Scenario S3 (Pulsing Burst) -> Target: 10.99.0.2:%u, Burst: %d (x%.1f = %d pkts), Period: %.1fs, Duration: %.1fs\n",
           target_port, burst, multiplier, pulse_packets, period_s, duration);

    uint8_t pkt[128];
    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_port = htons(target_port);
    dst.sin_addr.s_addr = target_ip;

    uint64_t start_ns = get_time_ns();
    uint64_t end_ns = start_ns + (uint64_t)(duration * 1e9);
    uint64_t next_cycle_ns = start_ns;
    uint64_t period_ns = (uint64_t)(period_s * 1e9);
    uint64_t total_sent = 0;
    int cycle = 0;
    uint16_t seq = 0;

    while (g_running && get_time_ns() < end_ns) {
        uint64_t now = get_time_ns();
        if (now >= next_cycle_ns) {
            cycle++;
            // Transmit immediate burst
            for (int p = 0; p < pulse_packets && g_running; p++) {
                seq++;
                size_t pkt_len = build_dns_packet(pkt, src_ip, target_ip, 40000 + p, target_port, seq);
                if (sendto(sock, pkt, pkt_len, 0, (struct sockaddr *)&dst, sizeof(dst)) > 0) {
                    total_sent++;
                }
            }
            next_cycle_ns += period_ns;
        }

        // Sleep until next cycle
        now = get_time_ns();
        if (next_cycle_ns > now) {
            uint64_t sleep_ns = next_cycle_ns - now;
            struct timespec ts;
            ts.tv_sec = (time_t)(sleep_ns / 1000000000ULL);
            ts.tv_nsec = (long)(sleep_ns % 1000000000ULL);
            nanosleep(&ts, NULL);
        }
    }

    uint64_t elapsed_ns = get_time_ns() - start_ns;
    double elapsed_s = (double)elapsed_ns / 1e9;
    printf("[RESULT] S3 Finished: Completed %d pulse cycles, Sent %llu packets in %.2fs\n",
           cycle, (unsigned long long)total_sent, elapsed_s);
    return 0;
}

/* --------------------------------------------------------------------------
 * Main Entry Point
 * -------------------------------------------------------------------------- */

static void print_usage(const char *prog) {
    fprintf(stderr, "Usage: %s <mode> [options]\n", prog);
    fprintf(stderr, "Modes:\n");
    fprintf(stderr, "  ceiling        Benchmark maximum generator TX throughput\n");
    fprintf(stderr, "  s1             Single-source constant-rate flood\n");
    fprintf(stderr, "  s2             Distributed flood (~1,000 sources from 198.18.0.0/15)\n");
    fprintf(stderr, "  s3             Pulsing burst flood (0.5x, 1x, 2x burst)\n");
    fprintf(stderr, "\nOptions:\n");
    fprintf(stderr, "  --target <ip>        Target destination IP (default: 10.99.0.2)\n");
    fprintf(stderr, "  --port <port>        Target destination port (default: 53)\n");
    fprintf(stderr, "  --source <ip>        Source IP for S1/S3 (default: 198.18.0.10)\n");
    fprintf(stderr, "  --rate <pps>         Transmission rate in PPS (default: 10000)\n");
    fprintf(stderr, "  --duration <sec>     Execution duration in seconds (default: 5.0)\n");
    fprintf(stderr, "  --sources <count>    Number of sources for S2 (default: 1000)\n");
    fprintf(stderr, "  --burst <count>      Base burst size for S3 (default: 20)\n");
    fprintf(stderr, "  --multiplier <float> Burst multiplier for S3 (default: 1.0)\n");
    fprintf(stderr, "  --period <sec>       Pulse period for S3 (default: 5.0)\n");
}

int main(int argc, char **argv) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    signal(SIGINT, sigint_handler);
    signal(SIGTERM, sigint_handler);

    // Mandatory Security Assertions before opening sockets
    enforce_ip_forward_zero();

    const char *mode = argv[1];
    uint32_t target_ip = inet_addr("10.99.0.2");
    uint16_t target_port = 53;
    uint32_t src_ip = inet_addr("198.18.0.10");
    uint32_t rate_pps = 10000;
    double duration = 5.0;
    int num_sources = 1000;
    int burst = 20;
    double multiplier = 1.0;
    double period_s = 5.0;

    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--target") == 0 && i + 1 < argc) {
            target_ip = inet_addr(argv[++i]);
        } else if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
            target_port = (uint16_t)atoi(argv[++i]);
        } else if (strcmp(argv[i], "--source") == 0 && i + 1 < argc) {
            src_ip = inet_addr(argv[++i]);
        } else if (strcmp(argv[i], "--rate") == 0 && i + 1 < argc) {
            rate_pps = (uint32_t)atoi(argv[++i]);
        } else if (strcmp(argv[i], "--duration") == 0 && i + 1 < argc) {
            duration = atof(argv[++i]);
        } else if (strcmp(argv[i], "--sources") == 0 && i + 1 < argc) {
            num_sources = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--burst") == 0 && i + 1 < argc) {
            burst = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--multiplier") == 0 && i + 1 < argc) {
            multiplier = atof(argv[++i]);
        } else if (strcmp(argv[i], "--period") == 0 && i + 1 < argc) {
            period_s = atof(argv[++i]);
        }
    }

    // Enforce target IP safety
    enforce_target_ip(target_ip);

    // Enforce source IP safety for single-source modes
    if (strcmp(mode, "s1") == 0 || strcmp(mode, "s3") == 0 || strcmp(mode, "ceiling") == 0) {
        enforce_source_ip(src_ip);
    }

    // Open raw socket with custom IP headers
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0) {
        perror("socket(AF_INET, SOCK_RAW)");
        fprintf(stderr, "[ERROR] Raw socket creation requires root/sudo privileges!\n");
        return 1;
    }

    int one = 1;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        perror("setsockopt(IP_HDRINCL)");
        close(sock);
        return 1;
    }

    int ret = 0;
    if (strcmp(mode, "ceiling") == 0) {
        ret = run_ceiling(sock, target_ip, target_port, duration);
    } else if (strcmp(mode, "s1") == 0) {
        ret = run_s1(sock, target_ip, target_port, src_ip, rate_pps, duration);
    } else if (strcmp(mode, "s2") == 0) {
        ret = run_s2(sock, target_ip, target_port, num_sources, rate_pps, duration);
    } else if (strcmp(mode, "s3") == 0) {
        ret = run_s3(sock, target_ip, target_port, src_ip, burst, multiplier, period_s, duration);
    } else {
        fprintf(stderr, "[ERROR] Unknown mode: '%s'\n", mode);
        print_usage(argv[0]);
        ret = 1;
    }

    close(sock);
    return ret;
}
