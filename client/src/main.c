#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static void parse_arguments(int argc, char *argv[], char **address, char **port,
                            char **msg);
static void handle_arguments(const char *binary_name, const char *address,
                             const char *port_str, const char *message,
                             in_port_t *port);
static in_port_t parse_port(const char *binary_name, const char *port_str);
_Noreturn static void usage(const char *program_name, int exit_code,
                            const char *message);
static void convert_address(const char *address, struct sockaddr_storage *addr,
                            socklen_t *addr_len);
static int create_socket(int domain, int type, int protocol);
static void get_server_address(struct sockaddr_storage *addr, in_port_t port);
static void send_message(int sockfd, const char *message,
                         struct sockaddr_storage *addr, socklen_t addr_len);
static void setup_signal_handler(void);
static void sigint_handler(int signum);
static void close_socket(int sockfd);

enum {
  UNKNOWN_OPTION_MESSAGE_LEN = 24,
  BASE_TEN = 10,
  MESSAGE_LEN = 1028,
  SEQ_LEN = 256
};

// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
static volatile sig_atomic_t exit_flag = 0;

int main(int argc, char *argv[]) {
  char *address;
  char *port_str;
  in_port_t port;
  int sockfd;
  int seq;

  struct sockaddr_storage addr;
  socklen_t addr_len;

  char *message;

  address = NULL;
  port_str = NULL;
  message = NULL;

  parse_arguments(argc, argv, &address, &port_str, &message);
  handle_arguments(argv[0], address, port_str, message, &port);
  convert_address(address, &addr, &addr_len);
  sockfd = create_socket(addr.ss_family, SOCK_DGRAM, 0);
  get_server_address(&addr, port);
  setup_signal_handler();

  seq = 0;
  while (!exit_flag) {
    char input_message[MESSAGE_LEN];
    char seq_string[SEQ_LEN];
    char final_message[MESSAGE_LEN];
    int int_parsed;

    scanf("%1027s", input_message);
    int_parsed = snprintf(seq_string, sizeof(seq_string), "%d", seq);

    if (int_parsed < 0) {
      perror("snprintf");
      exit(EXIT_FAILURE);
    }

    strlcpy(final_message, seq_string, MESSAGE_LEN);
    strlcat(final_message, ",", MESSAGE_LEN);
    strlcat(final_message, input_message, MESSAGE_LEN);

    send_message(sockfd, final_message, &addr, addr_len);
    seq++;
  }

  close_socket(sockfd);

  return EXIT_SUCCESS;
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

  printf("Sent %zu bytes: \"%s\"\n", (size_t)bytes_sent, message);
}

static void parse_arguments(int argc, char *argv[], char **address, char **port,
                            char **msg) {
  int opt;

  opterr = 0;

  while ((opt = getopt(argc, argv, "h")) != -1) {
    switch (opt) {
    case 'h': {
      usage(argv[0], EXIT_SUCCESS, NULL);
    }
    case '?': {
      char message[UNKNOWN_OPTION_MESSAGE_LEN];

      snprintf(message, sizeof(message), "Unknown option '-%c'", optopt);
      usage(argv[0], EXIT_FAILURE, message);
    }
    default: {
      usage(argv[0], EXIT_FAILURE, NULL);
    }
    }
  }

  if (optind + 1 >= argc) {
    usage(argv[0], EXIT_FAILURE, "Too little arguments");
  }

  if (optind < argc - 3) {
    usage(argv[0], EXIT_FAILURE, "Too many arguments");
  }

  *address = argv[optind];
  *port = argv[optind + 1];
  *msg = argv[optind + 2];
}

static void handle_arguments(const char *binary_name, const char *address,
                             const char *port_str, const char *message,
                             in_port_t *port) {
  if (address == NULL) {
    usage(binary_name, EXIT_FAILURE, "Address is required");
  }

  if (port_str == NULL) {
    usage(binary_name, EXIT_FAILURE, "Port is required");
  }

  if (message == NULL) {
    usage(binary_name, EXIT_FAILURE, "Message is required");
  }

  *port = parse_port(binary_name, port_str);
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

  fprintf(stderr, "Usage: %s [-h] <address> <port> <message>\n", program_name);
  fputs("Options:\n", stderr);
  fputs("  -h  Display this help message\n", stderr);
  exit(exit_code);
}

static void convert_address(const char *address, struct sockaddr_storage *addr,
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

static void close_socket(int sockfd) {
  if (close(sockfd) == -1) {
    perror("Error closing socket");
    exit(EXIT_FAILURE);
  }
}
