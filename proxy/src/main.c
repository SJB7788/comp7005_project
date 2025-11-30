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

enum {
  UNKNOWN_OPTION_MESSAGE_LEN = 24,
  ACK_SIZE = 256,
  BUFFER_SIZE = 1024,
  BASE_TEN = 10,
  DENOMINATOR = 100,
  MILLISECONDS = 1000,
  NANOSECONDS = 1000000L,
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
                         ssize_t *bytes_received,
                         struct sockaddr_storage *client_addr,
                         socklen_t *addr_len);
static void read_server_message(int sockfd, char *buffer, size_t buffer_size,
                                ssize_t *bytes_received);
// static void handle_packet(char *buffer, char *payload, long *seq);
static void send_message(int sockfd, const char *message,
                         struct sockaddr_storage *addr, socklen_t addr_len);
static int return_random(int max);
static void sleep_milliseconds(int ms);
static int simulate_drop(int denominator, int drop_prob);
static void simulate_delay(int denominator, int delay_min, int delay_max,
                           int delay_prob);
static int simulate_traffic(int denominator, int delay_min, int delay_max,
                            int delay_prob, int drop_prob);
static void setup_signal_handler(void);
static void sigint_handler(int signum);
static void close_socket(int sockfd);

// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
static volatile sig_atomic_t exit_flag = 0;

int main(int argc, char *argv[]) {
  int sockfd;

  Arguments args = {0};

  struct sockaddr_storage server_addr;
  socklen_t server_addr_len;
  struct sockaddr_storage client_addr;
  socklen_t client_addr_len;

  struct sockaddr_storage addr;

  unsigned int seed;

  parse_arguments(argc, argv, &args);
  handle_arguments(argv[0], &args);
  convert_address(args.ip_address, &addr);

  convert_server_address(args.server_ip_address, &server_addr,
                         &server_addr_len);
  get_server_address(&server_addr, args.server_port);

  sockfd = create_socket(addr.ss_family, SOCK_DGRAM, 0);
  bind_socket(sockfd, &addr, args.port);
  setup_signal_handler();

  // set up rand()
  seed = (unsigned int)(time(NULL) ^ getpid());
  srand(seed);

  char client_message[BUFFER_SIZE];
  char server_message[BUFFER_SIZE];

  while (!exit_flag) {
    ssize_t bytes_received;

    memset(client_message, 0, BUFFER_SIZE);
    memset(server_message, 0, BUFFER_SIZE);

    client_addr_len = sizeof(struct sockaddr_storage);

    read_message(sockfd, client_message, BUFFER_SIZE, &bytes_received,
                 &client_addr, &client_addr_len);
    printf("Read message from Client: %s\n", client_message);

    if (simulate_traffic(DENOMINATOR, args.client_cfg.min_delay,
                         args.client_cfg.max_delay, args.client_cfg.delay_prob,
                         args.client_cfg.drop_prob)) {
      printf("Dropped message from client: %s\n\n", client_message);
      continue;
    }

    send_message(sockfd, client_message, &server_addr, server_addr_len);
    printf("Sent message to Server: %s\n", client_message);

    read_server_message(sockfd, server_message, BUFFER_SIZE, &bytes_received);
    printf("Read message from Server: %s\n", server_message);

    if (simulate_traffic(DENOMINATOR, args.server_cfg.min_delay,
                         args.server_cfg.max_delay, args.server_cfg.delay_prob,
                         args.server_cfg.drop_prob)) {
      printf("Dropped message from server: %s\n\n", server_message);

      continue;
    }

    send_message(sockfd, server_message, &client_addr, client_addr_len);
    printf("Sent message to client: %s\n\n", server_message);
  }

  close_socket(sockfd);
  return EXIT_SUCCESS;
}

static int simulate_traffic(int denominator, int delay_min, int delay_max,
                            int delay_prob, int drop_prob) {
  simulate_delay(denominator, delay_min, delay_max, delay_prob);

  return simulate_drop(denominator, drop_prob);
}

static void simulate_delay(int denominator, int delay_min, int delay_max,
                           int delay_prob) {
  int delay_chance;
  int delay_range;
  int delay;
  int sleep_val;

  delay_chance = return_random(denominator);

  if (delay_chance > delay_prob) {
    return;
  }

  delay_range = delay_max - delay_min;
  delay = return_random(delay_range);

  sleep_val = delay + delay_min - 1;

  sleep_milliseconds(sleep_val);
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

  // Validate required flags
  if (!args->ip_address || !args->server_ip_address) {
    usage(argv[0], EXIT_FAILURE, "--target-ip and --server-ip are required");
  }
}

// static void parse_arguments(int argc, char *argv[], Arguments *args) {
//   int opt;

//   opterr = 0;

//   while ((opt = getopt(argc, argv, "h")) != -1) {
//     switch (opt) {
//     case 'h':
//       usage(argv[0], EXIT_SUCCESS, NULL);
//     case '?': {
//       char message[UNKNOWN_OPTION_MESSAGE_LEN];
//       snprintf(message, sizeof(message), "Unknown option '-%c'", optopt);
//       usage(argv[0], EXIT_FAILURE, message);
//     }
//     default:
//       usage(argv[0], EXIT_FAILURE, NULL);
//     }
//   }

//   // After getopt, optind should point to positional args
//   int remaining = argc - optind;

//   if (remaining < ARG_COUNT) {
//     usage(argv[0], EXIT_FAILURE, "Missing required arguments");
//   }

//   if (remaining > ARG_COUNT) {
//     usage(argv[0], EXIT_FAILURE, "Too many arguments");
//   }

//   // Use meaningful indexed constants
//   char **a = &argv[optind];

//   args->ip_address = a[ARG_IP];
//   args->port = parse_port(argv[0], a[ARG_PORT]);

//   args->server_ip_address = a[ARG_SERVER_IP];
//   args->server_port = parse_port(argv[0], a[ARG_SERVER_PORT]);

//   args->server_cfg.min_delay =
//       parse_int(argv[0], a[ARG_S_MIN_DELAY], "server_min_delay");
//   args->server_cfg.max_delay =
//       parse_int(argv[0], a[ARG_S_MAX_DELAY], "server_max_delay");
//   args->server_cfg.delay_prob =
//       parse_int(argv[0], a[ARG_S_DELAY_PROB], "server_delay_prob");
//   args->server_cfg.drop_prob =
//       parse_int(argv[0], a[ARG_S_DROP_PROB], "server_drop_prob");

//   args->client_cfg.min_delay =
//       parse_int(argv[0], a[ARG_C_MIN_DELAY], "client_min_delay");
//   args->client_cfg.max_delay =
//       parse_int(argv[0], a[ARG_C_MAX_DELAY], "client_max_delay");
//   args->client_cfg.delay_prob =
//       parse_int(argv[0], a[ARG_C_DELAY_PROB], "client_delay_prob");
//   args->client_cfg.drop_prob =
//       parse_int(argv[0], a[ARG_C_DROP_PROB], "client_drop_prob");
// }

static void handle_arguments(const char *binary_name, const Arguments *args) {
  // validate server
  if (args->server_cfg.min_delay > args->server_cfg.max_delay) {
    usage(binary_name, EXIT_FAILURE, "Server min_delay > max_delay");
  }

  if (args->server_cfg.delay_prob < 0 ||
      args->server_cfg.delay_prob > DENOMINATOR) {
    usage(binary_name, EXIT_FAILURE, "Server delay_prob must be 0–100}");
  }

  if (args->server_cfg.drop_prob < 0 ||
      args->server_cfg.drop_prob > DENOMINATOR) {
    usage(binary_name, EXIT_FAILURE, "Server drop_prob must be 0–100");
  }

  // validate client
  if (args->client_cfg.min_delay > args->client_cfg.max_delay) {
    usage(binary_name, EXIT_FAILURE, "Client min_delay > max_delay");
  }

  if (args->client_cfg.delay_prob < 0 ||
      args->client_cfg.delay_prob > DENOMINATOR) {
    usage(binary_name, EXIT_FAILURE, "Client delay_prob must be 0–100");
  }

  if (args->client_cfg.drop_prob < 0 ||
      args->client_cfg.drop_prob > DENOMINATOR) {
    usage(binary_name, EXIT_FAILURE, "Client drop_prob must be 0–100");
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
    fprintf(stderr, "%s\n", message);
  }

  fprintf(stderr,
          "Usage: %s [-h] "
          "<client_ip> <client_port> "
          "<server_ip> <server_port> "
          "<server_min_delay> <server_max_delay> "
          "<server_delay_prob> <server_drop_prob> "
          "<client_min_delay> <client_max_delay> "
          "<client_delay_prob> <client_drop_prob>\n",
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
                         ssize_t *bytes_received,
                         struct sockaddr_storage *client_addr,
                         socklen_t *addr_len) {
  size_t n;

  *bytes_received = recvfrom(sockfd, buffer, buffer_size - 1, 0,
                             (struct sockaddr *)client_addr, addr_len);

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

static void read_server_message(int sockfd, char *buffer, size_t buffer_size,
                                ssize_t *bytes_received) {
  size_t n;

  *bytes_received = recvfrom(sockfd, buffer, buffer_size - 1, 0, NULL, NULL);

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
