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

static void parse_arguments(int argc, char *argv[], char **address,
                            char **port_str, char **timeout_str,
                            char **max_retries_str);
static void handle_arguments(const char *binary_name, const char *address,
                             const char *port_str, const char *timeout_str,
                             const char *max_retries_str, in_port_t *port,
                             int *timeout, int *max_retries);
static in_port_t parse_port(const char *binary_name, const char *port_str);
_Noreturn static void usage(const char *program_name, int exit_code,
                            const char *message);
static void convert_address(const char *address, struct sockaddr_storage *addr,
                            socklen_t *addr_len);
static int create_socket(int domain, int type, int protocol);
static int start_timeout(int sockfd, int timeout_seconds);
static void get_server_address(struct sockaddr_storage *addr, in_port_t port);
static void structure_message(char *message, size_t message_len,
                              char *input_message, long seq_number);
static void send_message(int sockfd, const char *message,
                         struct sockaddr_storage *addr, socklen_t addr_len);
static void read_message(int sockfd, char *buffer, size_t buffer_size,
                         ssize_t *bytes_received);
static void handle_packet(char *buffer, long *seq);
static void setup_signal_handler(void);
static void sigint_handler(int signum);
static void close_socket(int sockfd);
static void get_timestamp(char *buf, size_t n);
static void log_init(FILE **log_file, const char *filename);
static void log_message(FILE *log_file, const char *event, const char *msg);
static void log_close(FILE *log_file);

enum {
  UNKNOWN_OPTION_BUFFER_SIZE = 24,
  BASE_TEN = 10,
  BUFFER_SIZE = 1024,
  SEQ_LEN = 256,
  LOG_SIZE = 128,
};

static const struct option long_options[] = {
    {"target-ip", required_argument, 0, 0},
    {"target-port", required_argument, 0, 0},
    {"timeout", required_argument, 0, 0},
    {"max-retries", required_argument, 0, 0},

    {0, 0, 0, 0}};

// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
static volatile sig_atomic_t exit_flag = 0;

int main(int argc, char *argv[]) {
  char *address;
  char *port_str;
  char *timeout_str;
  char *max_retry_str;

  in_port_t port;
  int timeout;
  int max_retry;
  int sockfd;

  struct sockaddr_storage addr;
  socklen_t addr_len;
  long seq_number;
  int retry_count;

  char input_message[BUFFER_SIZE];
  char final_message[BUFFER_SIZE];

  FILE *log_file;

  address = NULL;
  port_str = NULL;
  timeout_str = NULL;
  max_retry_str = NULL;
  log_file = NULL;
  retry_count = 0;
  seq_number = 0;
  timeout = 0;
  max_retry = 0;

  parse_arguments(argc, argv, &address, &port_str, &timeout_str,
                  &max_retry_str);
  handle_arguments(argv[0], address, port_str, timeout_str, max_retry_str,
                   &port, &timeout, &max_retry);
  convert_address(address, &addr, &addr_len);
  get_server_address(&addr, port);
  sockfd = create_socket(addr.ss_family, SOCK_DGRAM, 0);
  setup_signal_handler();
  log_init(&log_file, "client.log");

  while (!exit_flag) {
    char log_buffer[LOG_SIZE];
    ssize_t bytes_received;

    long ack;
    int status;

    if (retry_count > max_retry) {
      log_message(log_file, "DROP", "Max retry limit reached");
      retry_count = 0;
    }

    // if we are not retransmitting, get user input and structure message
    if (retry_count == 0) {
      // get message payload on stdin
      if (fgets(input_message, sizeof(input_message), stdin) == NULL) {
        fprintf(stderr, "invalid user input");
        continue;
      }

      input_message[strcspn(input_message, "\n")] = '\0';
      structure_message(final_message, BUFFER_SIZE, input_message, seq_number);
    }

    send_message(sockfd, final_message, &addr, addr_len);
    snprintf(log_buffer, sizeof(log_buffer), "Sent message: %s", final_message);
    log_message(log_file, "SEND", log_buffer);

    status = start_timeout(sockfd, timeout);

    if (status == 0) {
      retry_count++;
      snprintf(log_buffer, sizeof(log_buffer),
               "Timeout! Retransmitting message. Retry: %d", retry_count);
      log_message(log_file, "RETRY", log_buffer);
      continue;
    }

    if (status == 1) { // received message before timeout
      char ack_buffer[BUFFER_SIZE];

      read_message(sockfd, ack_buffer, BUFFER_SIZE, &bytes_received);
      handle_packet(ack_buffer, &ack);

      snprintf(log_buffer, sizeof(log_buffer), "Received ack: %ld", ack);
      log_message(log_file, "RECEIVE", log_buffer);

      if (seq_number != ack) {
        retry_count++;
        snprintf(
            log_buffer, sizeof(log_buffer),
            "Packet with SEQ: %ld does not have matching ACK. Retry count: "
            "%d",
            seq_number, retry_count);
        log_message(log_file, "RETRY", log_buffer);
        continue;
      }

      seq_number++;
      retry_count = 0;
      continue;
    }

    perror("timeout");
    exit(EXIT_FAILURE);
  }

  close_socket(sockfd);
  log_close(log_file);

  return EXIT_SUCCESS;
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

static void structure_message(char *message, size_t message_len,
                              char *input_message, long seq_number) {
  char seq_string[SEQ_LEN];
  int long_parsed;

  long_parsed = snprintf(seq_string, sizeof(seq_string), "%ld", seq_number);

  if (long_parsed < 0) {
    perror("snprintf");
    exit(EXIT_FAILURE);
  }

  strlcpy(message, seq_string, message_len);
  strlcat(message, "|", message_len);
  strlcat(message, input_message, message_len);
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

static void read_message(int sockfd, char *buffer, size_t buffer_size,
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

// cppcheck-suppress constParameterPointer
static void handle_packet(char *buffer, long *seq) {

  const char *token;
  char *token_ptr;

  // skip the seq
  strtok_r(buffer, "|", &token_ptr);

  // get the ack
  token = token_ptr;
  *seq = strtol(token, NULL, BASE_TEN);
}

static void parse_arguments(int argc, char *argv[], char **address,
                            char **port_str, char **timeout_str,
                            char **max_retries_str) {
  int opt;
  int option_index = 0;

  opterr = 0;

  while ((opt = getopt_long(argc, argv, "h", long_options, &option_index)) !=
         -1) {
    switch (opt) {

    case 0: {
      const char *optname = long_options[option_index].name;

      if (strcmp(optname, "target-ip") == 0) {
        *address = optarg;
      } else if (strcmp(optname, "target-port") == 0) {
        *port_str = optarg;
      } else if (strcmp(optname, "timeout") == 0) {
        *timeout_str = optarg;
      } else if (strcmp(optname, "max-retries") == 0) {
        *max_retries_str = optarg;
      }

      break;
    }

    case 'h':
      usage(argv[0], EXIT_SUCCESS, NULL);

    case '?': {
      char message[UNKNOWN_OPTION_BUFFER_SIZE];
      snprintf(message, sizeof(message), "Unknown option '-%c'", optopt);
      usage(argv[0], EXIT_FAILURE, message);
    }
    default:
      usage(argv[0], EXIT_FAILURE, NULL);
    }
  }
}

static void handle_arguments(const char *binary_name, const char *address,
                             const char *port_str, const char *timeout_str,
                             const char *max_retries_str, in_port_t *port,
                             int *timeout, int *max_retries) {
  if (address == NULL) {
    usage(binary_name, EXIT_FAILURE, "--target-ip is required");
  }

  if (port_str == NULL) {
    usage(binary_name, EXIT_FAILURE, "--target-port is required");
  }

  if (timeout_str == NULL) {
    usage(binary_name, EXIT_FAILURE, "--timeout is required");
  }

  if (max_retries_str == NULL) {
    usage(binary_name, EXIT_FAILURE, "--max-retires is required");
  }

  *port = parse_port(binary_name, port_str);

  errno = 0;
  *timeout = (int)strtoumax(timeout_str, NULL, BASE_TEN);
  *max_retries = (int)strtoumax(max_retries_str, NULL, BASE_TEN);

  if (errno != 0) {
    perror("strtol");
    exit(EXIT_FAILURE);
  }

  if (*timeout <= 0) {
    usage(binary_name, EXIT_FAILURE, "Timeout must be greater than 0");
  }

  if (*max_retries <= 0) {
    usage(binary_name, EXIT_FAILURE, "Max retries must be greater than 0");
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

  fprintf(
      stderr,
      "Usage: %s [-h]\n --target-ip <ip>\n --target-port <port>\n --timeout "
      "<ms>\n --max-retries <count>\n",
      program_name);
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
    exit(EXIT_FAILURE);
  }

  return sockfd;
}

static int start_timeout(int sockfd, int timeout_seconds) {
  fd_set fds;
  struct timeval tv;
  int result;

  FD_ZERO(&fds);
  FD_SET(sockfd, &fds);

  tv.tv_sec = timeout_seconds;
  tv.tv_usec = 0;

  result = select(sockfd + 1, &fds, NULL, NULL, &tv);

  if (result == -1) {
    perror("select");
    return -1;
  }

  if (result == 0) {
    return 0;
  }
  return 1;
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
