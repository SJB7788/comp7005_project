#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

static void parse_arguments(int argc, char *argv[], char **ip_address,
                            char **port_str);
static void handle_arguments(const char *binary_name, const char *ip_address,
                             const char *port_str, in_port_t *port);
static in_port_t parse_port(const char *binary_name, const char *port_str);
_Noreturn static void usage(const char *program_name, int exit_code,
                            const char *message);
static void convert_address(const char *address, struct sockaddr_storage *addr);
static int create_socket(int domain, int type, int protocol);
static void bind_socket(int sockfd, struct sockaddr_storage *addr,
                        in_port_t port);
static void read_message(int sockfd, char *buffer, size_t buffer_size,
                         ssize_t *bytes_received,
                         struct sockaddr_storage *client_addr,
                         socklen_t *addr_len);
static void handle_packet(char *buffer, char *payload, long *seq);
static void send_message(int sockfd, const char *message,
                         struct sockaddr_storage *addr, socklen_t addr_len);
static void setup_signal_handler(void);
static void sigint_handler(int signum);
static void close_socket(int sockfd);
static void get_timestamp(char *buf, size_t n);
static void log_init(FILE **log_file, const char *filename);
static void log_message(FILE *log_file, const char *event, const char *msg);
static void log_close(FILE *log_file);

enum {
  UNKNOWN_OPTION_MESSAGE_LEN = 24,
  ACK_SIZE = 256,
  BUFFER_SIZE = 1024,
  BASE_TEN = 10,
  LOG_SIZE = 2048,
};

static const struct option long_options[] = {
    {"listen-ip", required_argument, 0, 0},
    {"listen-port", required_argument, 0, 0},

    {0, 0, 0, 0}};

// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
static volatile sig_atomic_t exit_flag = 0;

int main(int argc, char *argv[]) {
  char *address;
  char *port_str;
  in_port_t port;
  int sockfd;

  struct sockaddr_storage client_addr;
  socklen_t client_addr_len;
  struct sockaddr_storage addr;

  char buffer[BUFFER_SIZE];
  ssize_t bytes_received;

  FILE *log_file;

  address = NULL;
  port_str = NULL;
  log_file = NULL;

  parse_arguments(argc, argv, &address, &port_str);
  handle_arguments(argv[0], address, port_str, &port);

  convert_address(address, &addr);

  sockfd = create_socket(addr.ss_family, SOCK_DGRAM, 0);
  bind_socket(sockfd, &addr, port);

  setup_signal_handler();
  log_init(&log_file, "server.log");

  while (!exit_flag) {
    long seq;
    char payload[BUFFER_SIZE];
    char ack[ACK_SIZE];
    char ack_message[BUFFER_SIZE];
    char log_buffer[LOG_SIZE];
    int long_parsed;

    read_message(sockfd, buffer, BUFFER_SIZE, &bytes_received, &client_addr,
                 &client_addr_len);
    handle_packet(buffer, payload, &seq);

    snprintf(log_buffer, sizeof(log_buffer),
             "Received message from proxy. SEQ: %ld, PAYLOAD: %s", seq,
             payload);
    log_message(log_file, "RECEIVE", log_buffer);

    long_parsed = snprintf(ack, sizeof(ack), "%ld", seq);

    if (long_parsed < 0) {
      perror("snprintf");
      exit(EXIT_FAILURE);
    }

    // seq and ack are the same number
    strlcpy(ack_message, ack, ACK_SIZE);
    strlcat(ack_message, "|", BUFFER_SIZE);
    strlcat(ack_message, ack, BUFFER_SIZE);
    send_message(sockfd, ack_message, &client_addr, client_addr_len);
    snprintf(log_buffer, sizeof(log_buffer), "Sent message to proxy: %s",
             ack_message);
    log_message(log_file, "SEND", log_buffer);
  }

  close_socket(sockfd);
  log_close(log_file);
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
}

static void log_init(FILE **log_file, const char *filename) {
  *log_file = fopen(filename, "ae");
  if (*log_file == NULL) {
    perror("fopen");
    exit(EXIT_FAILURE);
  }
}

static void log_message(FILE *log_file, const char *event, const char *msg) {
  char timestamp[LOG_SIZE];
  get_timestamp(timestamp, sizeof(timestamp));

  // log file
  fprintf(log_file, "%s [%s]: %s\n", timestamp, event, msg);
  fflush(log_file);

  // stderr output
  fprintf(stderr, "%s [%s]: %s\n", timestamp, event, msg);
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

static void parse_arguments(int argc, char *argv[], char **ip_address,
                            char **port_str) {
  int opt;
  int option_index = 0;

  opterr = 0;

  while ((opt = getopt_long(argc, argv, "h", long_options, &option_index)) !=
         -1) {
    switch (opt) {
    case 0: {
      const char *optname = long_options[option_index].name;

      if (strcmp(optname, "listen-ip") == 0) {
        *ip_address = optarg;
      } else if (strcmp(optname, "listen-port") == 0) {
        *port_str = optarg;
      }

      break;
    }
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
}

static void handle_arguments(const char *binary_name, const char *ip_address,
                             const char *port_str, in_port_t *port) {
  if (ip_address == NULL) {
    usage(binary_name, EXIT_FAILURE, "IP address is required");
  }

  if (port_str == NULL) {
    usage(binary_name, EXIT_FAILURE, "Port is required");
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

  fprintf(stderr, "Usage: %s [-h]\n --listen-ip <ip>\n --listen-port <port>\n",
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

static int create_socket(int domain, int type, int protocol) {
  int sockfd;

  sockfd = socket(domain, type, protocol);

  if (sockfd == -1) {
    perror("Socket creation failed");
    exit(EXIT_FAILURE);
  }

  return sockfd;
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

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"

// cppcheck-suppress constParameterPointer
static void handle_packet(char *buffer, char *payload, long *seq) {

  const char *token;
  const char *token_payload;
  char *token_ptr;

  token = strtok_r(buffer, "|", &token_ptr);
  *seq = strtol(token, NULL, BASE_TEN);

  token_payload = token_ptr;

  strncpy(payload, token_payload, BUFFER_SIZE - 1);
  payload[BUFFER_SIZE - 1] = '\0';
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

#pragma GCC diagnostic pop
static void close_socket(int sockfd) {
  if (close(sockfd) == -1) {
    perror("Error closing socket");
    exit(EXIT_FAILURE);
  }
}
