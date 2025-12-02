#include <arpa/inet.h>
#include <bits/getopt_core.h>
#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

typedef struct {
  int min_delay;
  int max_delay;
  int delay_prob;
  int drop_prob;
} ProxyConfig;

// arguments for handle_argument function
typedef struct {
  char *ip_address;
  in_port_t port;

  char *server_ip_address;
  in_port_t server_port;

  ProxyConfig server_cfg;
  ProxyConfig client_cfg;
} Arguments;

static void parse_arguments(int argc, char *argv[], Arguments *args);
static void handle_arguments(const char *binary_name, const Arguments *args);
static in_port_t parse_port(const char *binary_name, const char *port_str);
_Noreturn static void usage(const char *program_name, int exit_code,
                            const char *message);
static void convert_address(const char *address, struct sockaddr_storage *addr);
static void convert_server_address(const char *address,
                                   struct sockaddr_storage *addr,
                                   socklen_t *addr_len);
static void get_server_address(struct sockaddr_storage *addr, in_port_t port);
static int create_socket(int domain, int type, int protocol);
static void bind_socket(int sockfd, struct sockaddr_storage *addr,
                        in_port_t port);
static void read_message(int sockfd, char *buffer, size_t buffer_size,
                         ssize_t *bytes_received, struct sockaddr_storage *addr,
                         socklen_t *addr_len);
// static void read_server_message(int sockfd, char *buffer, size_t buffer_size,
//                                 ssize_t *bytes_received);
// static void handle_packet(char *buffer, char *payload, long *seq);
static void send_message(int sockfd, const char *message,
                         struct sockaddr_storage *addr, socklen_t addr_len);
static int return_random(int max);
static void sleep_milliseconds(int ms);
static int simulate_drop(int denominator, int drop_prob);
static int simulate_delay(int denominator, int delay_min, int delay_max,
                          int delay_prob);
static void setup_signal_handler(void);
static void sigint_handler(int signum);
static void close_socket(int sockfd);
static void get_timestamp(char *buf, size_t n);
static void log_init(FILE **log_file, const char *filename);
static void log_message(FILE *log_file, const char *event,
                        const char *direction, const char *msg);
static void log_close(FILE *log_file);
static int same_addr(const struct sockaddr_storage *a,
                     const struct sockaddr_storage *b);

enum {
  UNKNOWN_OPTION_MESSAGE_LEN = 24,
  ACK_SIZE = 256,
  BUFFER_SIZE = 1024,
  BASE_TEN = 10,
  DENOMINATOR = 100,
  MILLISECONDS = 1000,
  NANOSECONDS = 1000000L,
  LOG_SIZE = 2048,
};

static const struct option long_options[] = {
    {"listen-ip", required_argument, 0, 0},
    {"listen-port", required_argument, 0, 0},
    {"target-ip", required_argument, 0, 0},
    {"target-port", required_argument, 0, 0},

    {"client-drop", required_argument, 0, 0},
    {"server-drop", required_argument, 0, 0},
    {"client-delay", required_argument, 0, 0},
    {"server-delay", required_argument, 0, 0},

    {"client-delay-time-min", required_argument, 0, 0},
    {"client-delay-time-max", required_argument, 0, 0},
    {"server-delay-time-min", required_argument, 0, 0},
    {"server-delay-time-max", required_argument, 0, 0},

    {0, 0, 0, 0}};

// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
static volatile sig_atomic_t exit_flag = 0;

static void print_sockaddr(struct sockaddr_storage *addr, const char *label) {
  char ipstr[INET6_ADDRSTRLEN];
  void *src = NULL;
  uint16_t port;

  if (addr == NULL) {
    fprintf(stderr, "%s: (null address)\n", label);
    return;
  }

  if (addr->ss_family == AF_INET) {
    struct sockaddr_in *a4 = (struct sockaddr_in *)addr;
    src = (void *)&a4->sin_addr;
    port = ntohs(a4->sin_port);

    if (inet_ntop(AF_INET, src, ipstr, sizeof(ipstr)) == NULL) {
      strcpy(ipstr, "invalid-ipv4");
    }

    fprintf(stderr, "%s: IPv4 %s:%u\n", label, ipstr, port);
  } else if (addr->ss_family == AF_INET6) {
    struct sockaddr_in6 *a6 = (struct sockaddr_in6 *)addr;
    src = (void *)&a6->sin6_addr;
    port = ntohs(a6->sin6_port);

    if (inet_ntop(AF_INET6, src, ipstr, sizeof(ipstr)) == NULL) {
      strcpy(ipstr, "invalid-ipv6");
    }

    fprintf(stderr, "%s: IPv6 [%s]:%u\n", label, ipstr, port);
  } else {
    fprintf(stderr, "%s: Unknown address family: %d\n", label, addr->ss_family);
  }
}

int main(int argc, char *argv[]) {
  Arguments args = {0};

  int sockfd;

  int client_known;
  struct sockaddr_storage server_addr;
  socklen_t server_addr_len;
  struct sockaddr_storage client_addr;
  socklen_t client_addr_len;
  struct sockaddr_storage src_addr;
  socklen_t src_addr_len;

  struct sockaddr_storage addr;

  unsigned int seed;
  FILE *log_file;

  log_file = NULL;
  client_known = 0;
  client_addr.ss_family = AF_UNSPEC;
  server_addr.ss_family = AF_UNSPEC;
  src_addr.ss_family = AF_UNSPEC;

  parse_arguments(argc, argv, &args);
  handle_arguments(argv[0], &args);
  convert_address(args.ip_address, &addr);

  convert_server_address(args.server_ip_address, &server_addr,
                         &server_addr_len);
  get_server_address(&server_addr, args.server_port);

  sockfd = create_socket(addr.ss_family, SOCK_DGRAM, 0);
  bind_socket(sockfd, &addr, args.port);
  setup_signal_handler();
  log_init(&log_file, "proxy.log");

  // set up rand()
  seed = (unsigned int)(time(NULL) ^ getpid());
  srand(seed);

  char message[BUFFER_SIZE];

  while (!exit_flag) {
    ssize_t bytes_received;
    char log_buffer[LOG_SIZE];
    int delay;

    src_addr_len = sizeof(src_addr);

    read_message(sockfd, message, BUFFER_SIZE, &bytes_received, &src_addr,
                 &src_addr_len);

    if (!client_known) {
      memcpy(&client_addr, &src_addr, sizeof(struct sockaddr_storage));
      client_addr_len = src_addr_len;
      client_known = 1;
      printf("CLIENT\n\n");
      print_sockaddr(&client_addr, "CLIENT");
    }

    if (same_addr(&src_addr, &server_addr)) {
      snprintf(log_buffer, sizeof(log_buffer), "Read message from Server: %s",
               message);
      log_message(log_file, "RECIEVE", "proxy<-server", log_buffer);

      delay =
          simulate_delay(DENOMINATOR, args.server_cfg.min_delay,
                         args.server_cfg.max_delay, args.server_cfg.delay_prob);
      if (delay > 0) {
        snprintf(log_buffer, sizeof(log_buffer),
                 "Delayed server message for %d ms", delay);
        log_message(log_file, "DELAY", "client<-proxy", log_buffer);
      }

      if (simulate_drop(DENOMINATOR, args.server_cfg.drop_prob)) {
        snprintf(log_buffer, sizeof(log_buffer), "Dropped server message : %s",
                 message);
        log_message(log_file, "DROP", "client<-proxy", log_buffer);
        continue;
      }

      send_message(sockfd, message, &client_addr, client_addr_len);
      snprintf(log_buffer, sizeof(log_buffer), "Sent message to client: %s",
               message);
      log_message(log_file, "SEND", "client<-proxy", log_buffer);
    } else {
      snprintf(log_buffer, sizeof(log_buffer), "Read message from Client: %s",
               message);
      log_message(log_file, "RECEIVE", "client->proxy", log_buffer);

      delay =
          simulate_delay(DENOMINATOR, args.client_cfg.min_delay,
                         args.client_cfg.max_delay, args.client_cfg.delay_prob);
      if (delay > 0) {
        snprintf(log_buffer, sizeof(log_buffer),
                 "Delayed client message for %d ms", delay);
        log_message(log_file, "DELAY", "proxy->server", log_buffer);
      }

      if (simulate_drop(DENOMINATOR, args.client_cfg.drop_prob)) {
        snprintf(log_buffer, sizeof(log_buffer), "Dropped Client message: %s",
                 message);
        log_message(log_file, "DROP", "proxy->server", log_buffer);
        continue;
      }

      send_message(sockfd, message, &server_addr, server_addr_len);
      snprintf(log_buffer, sizeof(log_buffer), "Sent message to Server: %s",
               message);
      log_message(log_file, "SEND", "proxy->server", log_buffer);
    }
  }

  close_socket(sockfd);
  log_close(log_file);
  return EXIT_SUCCESS;
}

static int same_addr(const struct sockaddr_storage *a,
                     const struct sockaddr_storage *b) {
  if (a == NULL || b == NULL) {
    return 0;
  }

  if (a->ss_family != AF_INET && a->ss_family != AF_INET6) {
    return 0;
  }

  if (b->ss_family != AF_INET && b->ss_family != AF_INET6) {
    return 0;
  }

  if (a->ss_family == AF_INET) {
    const struct sockaddr_in *ia = (const struct sockaddr_in *)a;
    const struct sockaddr_in *ib = (const struct sockaddr_in *)b;

    return (ia->sin_port == ib->sin_port) &&
           (ia->sin_addr.s_addr == ib->sin_addr.s_addr);
  }

  if (a->ss_family == AF_INET6) {
    const struct sockaddr_in6 *ia6 = (const struct sockaddr_in6 *)a;
    const struct sockaddr_in6 *ib6 = (const struct sockaddr_in6 *)b;

    return (ia6->sin6_port == ib6->sin6_port) &&
           (memcmp(&ia6->sin6_addr, &ib6->sin6_addr, sizeof(struct in6_addr)) ==
            0);
  }

  return 0;
}

static void log_init(FILE **log_file, const char *filename) {
  *log_file = fopen(filename, "ae");
  if (*log_file == NULL) {
    perror("fopen");
    exit(EXIT_FAILURE);
  }
}

static void log_message(FILE *log_file, const char *event,
                        const char *direction, const char *msg) {
  char timestamp[ACK_SIZE];
  get_timestamp(timestamp, sizeof(timestamp));

  // log file
  fprintf(log_file, "%s [%s] (%s): %s\n", timestamp, event, direction, msg);
  fflush(log_file);

  // stderr output
  fprintf(stderr, "%s [%s] (%s): %s\n", timestamp, event, direction, msg);
  fflush(stderr);
}

static void log_close(FILE *log_file) {
  if (log_file != NULL) {
    fclose(log_file);
  }
}

static void get_timestamp(char *buf, size_t n) {
  struct timespec ts;
  struct tm tm_info;

  clock_gettime(CLOCK_REALTIME, &ts);
  localtime_r(&ts.tv_sec, &tm_info);

  strftime(buf, n, "%Y-%m-%dT%H:%M:%S", &tm_info);
}

static int simulate_delay(int denominator, int delay_min, int delay_max,
                          int delay_prob) {
  int delay_chance;
  int delay_range;
  int delay;
  int sleep_val;

  delay_chance = return_random(denominator);

  if (delay_chance > delay_prob) {
    return 0;
  }

  delay_range = delay_max - delay_min;
  delay = return_random(delay_range);

  sleep_val = delay + delay_min - 1;

  sleep_milliseconds(sleep_val);
  return delay + delay_min - 1;
}

static void sleep_milliseconds(int ms) {
  if (ms <= 0) {
    return;
  }

  struct timespec ts;
  ts.tv_sec = ms / MILLISECONDS;
  ts.tv_nsec = (long)(ms % MILLISECONDS) * NANOSECONDS;

  nanosleep(&ts, NULL);
}

static int simulate_drop(int denominator, int drop_prob) {
  int drop_chance = return_random(denominator);

  if (drop_chance < 0) {
    perror("drop_chance");
    exit(EXIT_FAILURE);
  }

  if (drop_chance > drop_prob) {
    return 0;
  }
  return 1;
}

static int return_random(int max) {
  if (max <= 0) {
    return -1;
  }

  return rand() % max + 1;
}

static int parse_int(const char *binary_name, const char *str,
                     const char *field) {
  char *endptr;
  long value = strtol(str, &endptr, BASE_TEN);

  if (*endptr != '\0') {
    fprintf(stderr, "%s: invalid integer for %s: '%s'\n", binary_name, field,
            str);
    exit(EXIT_FAILURE);
  }

  return (int)value;
}

static void send_message(int sockfd, const char *message,
                         // cppcheck-suppress constParameterPointer
                         struct sockaddr_storage *addr, socklen_t addr_len) {
  ssize_t bytes_sent;

  bytes_sent = sendto(sockfd, message, strlen(message) + 1, 0,
                      (struct sockaddr *)addr, addr_len);

  if (bytes_sent == -1) {
    perror("sendto");
    exit(EXIT_FAILURE);
  }
}

static void parse_arguments(int argc, char *argv[], Arguments *args) {
  int option_index = 0;

  while (1) {
    int c;
    c = getopt_long(argc, argv, "h", long_options, &option_index);
    if (c == -1) {
      break;
    }

    switch (c) {
    case 0: {
      const char *optname = long_options[option_index].name;

      if (strcmp(optname, "listen-ip") == 0) {
        args->ip_address = optarg;
      } else if (strcmp(optname, "listen-port") == 0) {
        args->port = parse_port(argv[0], optarg);
      } else if (strcmp(optname, "target-ip") == 0) {
        args->server_ip_address = optarg;
      } else if (strcmp(optname, "target-port") == 0) {
        args->server_port = parse_port(argv[0], optarg);
      }

      // server settings
      else if (strcmp(optname, "server-delay-time-min") == 0) {
        args->server_cfg.min_delay =
            parse_int(argv[0], optarg, "server_delay_time_min");
      } else if (strcmp(optname, "server-delay-time-max") == 0) {
        args->server_cfg.max_delay =
            parse_int(argv[0], optarg, "server_max_delay");
      } else if (strcmp(optname, "server-delay") == 0) {
        args->server_cfg.delay_prob =
            parse_int(argv[0], optarg, "server_delay_prob");
      } else if (strcmp(optname, "server-drop") == 0) {
        args->server_cfg.drop_prob =
            parse_int(argv[0], optarg, "server_drop_prob");
      }

      // client settings
      else if (strcmp(optname, "client-delay-time-min") == 0) {
        args->client_cfg.min_delay =
            parse_int(argv[0], optarg, "client_min_delay");
      } else if (strcmp(optname, "client-delay-time-max") == 0) {
        args->client_cfg.max_delay =
            parse_int(argv[0], optarg, "client_max_delay");
      } else if (strcmp(optname, "client-delay") == 0) {
        args->client_cfg.delay_prob =
            parse_int(argv[0], optarg, "client_delay_prob");
      } else if (strcmp(optname, "client-drop") == 0) {
        args->client_cfg.drop_prob =
            parse_int(argv[0], optarg, "client_drop_prob");
      }

      break;
    }

    case 'h':
      usage(argv[0], EXIT_SUCCESS, NULL);
      break;

    case '?':
      usage(argv[0], EXIT_FAILURE, "Unknown option");
      break;

    default:
      usage(argv[0], EXIT_FAILURE, NULL);
    }
  }

  if (!args->ip_address || !args->server_ip_address) {
    usage(argv[0], EXIT_FAILURE, "--target-ip and --server-ip are required");
  }
}

static void handle_arguments(const char *binary_name, const Arguments *args) {
  // validate server
  if (args->server_cfg.min_delay > args->server_cfg.max_delay) {
    usage(binary_name, EXIT_FAILURE, "--server-delay-min > --server-delay-max");
  }

  if (args->server_cfg.delay_prob < 0 ||
      args->server_cfg.delay_prob > DENOMINATOR) {
    usage(binary_name, EXIT_FAILURE, "--server-delay must be 0–100}");
  }

  if (args->server_cfg.drop_prob < 0 ||
      args->server_cfg.drop_prob > DENOMINATOR) {
    usage(binary_name, EXIT_FAILURE, "--server-drop must be 0–100");
  }

  // validate client
  if (args->client_cfg.min_delay > args->client_cfg.max_delay) {
    usage(binary_name, EXIT_FAILURE, "--client-delay-min > --client-delay-max");
  }

  if (args->client_cfg.delay_prob < 0 ||
      args->client_cfg.delay_prob > DENOMINATOR) {
    usage(binary_name, EXIT_FAILURE, "--client-delay must be 0–100");
  }

  if (args->client_cfg.drop_prob < 0 ||
      args->client_cfg.drop_prob > DENOMINATOR) {
    usage(binary_name, EXIT_FAILURE, "--client-drop must be 0–100");
  }
}

in_port_t parse_port(const char *binary_name, const char *str) {
  char *endptr;
  uintmax_t parsed_value;

  errno = 0;
  parsed_value = strtoumax(str, &endptr, BASE_TEN);

  if (errno != 0) {
    perror("Error parsing in_port_t");
    exit(EXIT_FAILURE);
  }

  if (*endptr != '\0') {
    usage(binary_name, EXIT_FAILURE, "Invalid characters in input");
  }

  if (parsed_value > UINT16_MAX) {
    usage(binary_name, EXIT_FAILURE, "in_port_t value out of range");
  }

  return (in_port_t)parsed_value;
}

_Noreturn static void usage(const char *program_name, int exit_code,
                            const char *message) {
  if (message) {
    fprintf(stderr, "\n%s\n\n", message);
  }

  fprintf(stderr,
          "Usage: %s [-h] \n"
          "--listen-ip <ip> \n"
          "--listen-port <port> \n"
          "--target-ip <ip> \n"
          "--target-port <port> \n"
          "--client-drop <percent value> \n"
          "--server-drop <percent value> \n"
          "--client-delay <percent value> \n"
          "--server-delay <percent value> \n"
          "--client-delay-time-min <ms> \n"
          "--client-delay-time-max <ms> \n"
          "--server-delay-time-min <ms> \n"
          "--server-delay-time-max <ms>\n",
          program_name);

  fputs("Options:\n", stderr);
  fputs("  -h  Display this help message\n", stderr);
  exit(exit_code);
}

static void convert_address(const char *address,
                            struct sockaddr_storage *addr) {
  memset(addr, 0, sizeof(*addr));

  if (inet_pton(AF_INET, address, &(((struct sockaddr_in *)addr)->sin_addr)) ==
      1) {
    addr->ss_family = AF_INET;
  } else if (inet_pton(AF_INET6, address,
                       &(((struct sockaddr_in6 *)addr)->sin6_addr)) == 1) {
    addr->ss_family = AF_INET6;
  } else {
    fprintf(stderr, "%s is not an IPv4 or an IPv6 address\n", address);
    exit(EXIT_FAILURE);
  }
}

static void convert_server_address(const char *address,
                                   struct sockaddr_storage *addr,
                                   socklen_t *addr_len) {
  memset(addr, 0, sizeof(*addr));

  if (inet_pton(AF_INET, address, &(((struct sockaddr_in *)addr)->sin_addr)) ==
      1) {
    addr->ss_family = AF_INET;
    *addr_len = sizeof(struct sockaddr_in);
  } else if (inet_pton(AF_INET6, address,
                       &(((struct sockaddr_in6 *)addr)->sin6_addr)) == 1) {
    addr->ss_family = AF_INET6;
    *addr_len = sizeof(struct sockaddr_in6);
  } else {
    fprintf(stderr, "%s is not an IPv4 or an IPv6 address\n", address);
    exit(EXIT_FAILURE);
  }
}

static int create_socket(int domain, int type, int protocol) {
  int sockfd;

  sockfd = socket(domain, type, protocol);

  if (sockfd == -1) {
    perror("Socket creation failed");
    exit(EXIT_FAILURE);
  }

  return sockfd;
}

static void get_server_address(struct sockaddr_storage *addr, in_port_t port) {
  if (addr->ss_family == AF_INET) {
    struct sockaddr_in *ipv4_addr;

    ipv4_addr = (struct sockaddr_in *)addr;
    ipv4_addr->sin_family = AF_INET;
    ipv4_addr->sin_port = htons(port);
  } else if (addr->ss_family == AF_INET6) {
    struct sockaddr_in6 *ipv6_addr;

    ipv6_addr = (struct sockaddr_in6 *)addr;
    ipv6_addr->sin6_family = AF_INET6;
    ipv6_addr->sin6_port = htons(port);
  }
}

static void bind_socket(int sockfd, struct sockaddr_storage *addr,
                        in_port_t port) {
  char addr_str[INET6_ADDRSTRLEN];
  socklen_t addr_len;
  void *vaddr;
  in_port_t net_port;

  net_port = htons(port);

  if (addr->ss_family == AF_INET) {
    struct sockaddr_in *ipv4_addr;

    ipv4_addr = (struct sockaddr_in *)addr;
    addr_len = sizeof(*ipv4_addr);
    ipv4_addr->sin_port = net_port;
    vaddr = (void *)&(((struct sockaddr_in *)addr)->sin_addr);
  } else if (addr->ss_family == AF_INET6) {
    struct sockaddr_in6 *ipv6_addr;

    ipv6_addr = (struct sockaddr_in6 *)addr;
    addr_len = sizeof(*ipv6_addr);
    ipv6_addr->sin6_port = net_port;
    vaddr = (void *)&(((struct sockaddr_in6 *)addr)->sin6_addr);
  } else {
    fprintf(stderr,
            "Internal error: addr->ss_family must be AF_INET or AF_INET6, was: "
            "%d\n",
            addr->ss_family);
    exit(EXIT_FAILURE);
  }

  if (inet_ntop(addr->ss_family, vaddr, addr_str, sizeof(addr_str)) == NULL) {
    perror("inet_ntop");
    exit(EXIT_FAILURE);
  }

  printf("Binding to: %s:%u\n", addr_str, port);

  if (bind(sockfd, (struct sockaddr *)addr, addr_len) == -1) {
    perror("Binding failed");
    fprintf(stderr, "Error code: %d\n", errno);
    exit(EXIT_FAILURE);
  }

  printf("Bound to socket: %s:%u\n\n", addr_str, port);
}

static void read_message(int sockfd, char *buffer, size_t buffer_size,
                         ssize_t *bytes_received, struct sockaddr_storage *addr,
                         socklen_t *addr_len) {
  size_t n;
  memset(buffer, 0, BUFFER_SIZE);

  *bytes_received = recvfrom(sockfd, buffer, buffer_size - 1, 0,
                             (struct sockaddr *)addr, addr_len);

  if (*bytes_received < 0) {
    perror("recvfrom");
    close_socket(sockfd);
    exit(EXIT_FAILURE);
  }

  n = (size_t)*bytes_received;

  if (n >= buffer_size) {
    n = buffer_size - 1;
  }

  buffer[n] = '\0';
}

// static void read_server_message(int sockfd, char *buffer, size_t buffer_size,
//                                 ssize_t *bytes_received) {
//   size_t n;

//   memset(buffer, 0, BUFFER_SIZE);
//   *bytes_received = recvfrom(sockfd, buffer, buffer_size - 1, 0, NULL, NULL);

//   if (*bytes_received < 0) {
//     perror("recvfrom");
//     close_socket(sockfd);
//     exit(EXIT_FAILURE);
//   }

//   n = (size_t)*bytes_received;

//   if (n >= buffer_size) {
//     n = buffer_size - 1;
//   }

//   buffer[n] = '\0';
// }

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
static void sigint_handler(int signum) { exit_flag = 1; }

static void setup_signal_handler(void) {
  struct sigaction sa;

  memset(&sa, 0, sizeof(sa));

#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdisabled-macro-expansion"
#endif
  sa.sa_handler = sigint_handler;
#ifdef __clang__
// #pragma clang diagnostic pop
#endif

  sigemptyset(&sa.sa_mask);
  sa.sa_flags = 0;

  if (sigaction(SIGINT, &sa, NULL) == -1) {
    perror("sigaction");
    exit(EXIT_FAILURE);
  }
}

#pragma GCC diagnostic pop
static void close_socket(int sockfd) {
  if (close(sockfd) == -1) {
    perror("Error closing socket");
    exit(EXIT_FAILURE);
  }
}
