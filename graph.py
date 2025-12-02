import os
import re
import sys

import matplotlib.pyplot as plt

# client regex
SEND_RE = re.compile(r"\[SEND\]")
TIMEOUT_RE = re.compile(r"\[RETRY\]")
RECEIVE_RE = re.compile(r"\[RECEIVE\]")

# proxy regex
RECEIEVE_SERVER_RE = re.compile(r"\[RECEIVE\] \(server\)")
RECEIEVE_CLIENT_RE = re.compile(r"\[RECEIVE\] \(client\)")

DROP_SERVER_RE = re.compile(r"\[DROP\] \(server\)")
DROP_CLIENT_RE = re.compile(r"\[DROP\] \(client\)")

DELAY_SERVER_RE = re.compile(r"\[DELAY\] \(server\)")
DELAY_CLIENT_RE = re.compile(r"\[DELAY\] \(client\)")

SEND_TO_SERVER_RE = re.compile(r"\[SEND\] \(server\).*to server")
SEND_TO_CLIENT_RE = re.compile(r"\[SEND\] \(client\).*to client")


def parse_client_packet(filename):
    cumulative_timeouts = []
    cumulative_successes = []

    timeout_count = 0
    success_count = 0

    with open(filename, "r") as f:
        for line in f:
            line = line.strip()

            # if new packet is sent, append timeout and success count
            if SEND_RE.search(line):
                cumulative_timeouts.append(timeout_count)
                cumulative_successes.append(success_count)
                continue

            # increment timeout count
            if TIMEOUT_RE.search(line):
                timeout_count += 1
                continue

            # increment successful count
            if RECEIVE_RE.search(line):
                success_count += 1
                continue

    return {"timeout": cumulative_timeouts, "success": cumulative_successes}


def parse_proxy_packet(filename):
    # cumulative counters
    drop_server_count = 0
    delay_server_count = 0
    send_server_count = 0

    drop_client_count = 0
    delay_client_count = 0
    send_client_count = 0

    # per-packet cumulative data
    drop_server_list = []
    delay_server_list = []
    send_server_list = []

    drop_client_list = []
    delay_client_list = []
    send_client_list = []

    # packet indices (correct X-axes)
    server_packet_index = 0
    client_packet_index = 0

    with open(filename, "r") as f:
        for line in f:
            line = line.strip()

            if RECEIEVE_SERVER_RE.search(line):
                server_packet_index += 1
                # push server cumulative counts
                drop_server_list.append(drop_server_count)
                delay_server_list.append(delay_server_count)
                send_server_list.append(send_server_count)
                continue

            if RECEIEVE_CLIENT_RE.search(line):
                client_packet_index += 1
                # push client cumulative counts
                drop_client_list.append(drop_client_count)
                delay_client_list.append(delay_client_count)
                send_client_list.append(send_client_count)
                continue

            # SERVER events
            if DROP_SERVER_RE.search(line):
                drop_server_count += 1
            if DELAY_SERVER_RE.search(line):
                delay_server_count += 1
            if SEND_TO_SERVER_RE.search(line):
                send_server_count += 1

            # CLIENT events
            if DROP_CLIENT_RE.search(line):
                drop_client_count += 1
            if DELAY_CLIENT_RE.search(line):
                delay_client_count += 1
            if SEND_TO_CLIENT_RE.search(line):
                send_client_count += 1

    return {
        "drop_server": drop_server_list,
        "delay_server": delay_server_list,
        "send_server": send_server_list,
        "drop_client": drop_client_list,
        "delay_client": delay_client_list,
        "send_client": send_client_list,
    }


def plot_graph(values, title, filename):
    x = list(range(1, len(values) + 1))

    plt.figure(figsize=(10, 6))
    plt.plot(x, values, linestyle="-")

    plt.title(title)
    plt.xlabel("Packet Number")
    plt.ylabel("Cumulative Count")
    plt.grid(True, linestyle="--", alpha=0.5)

    plt.savefig(filename)
    plt.close()
    print("[+] Saved", filename)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 generate_all_graphs.py <client_log> <proxy_log>")
        sys.exit(1)

    client_log = sys.argv[1]
    proxy_log = sys.argv[2]

    # validate files
    for path in [client_log, proxy_log]:
        if not os.path.exists(path):
            print(f"Error: File does not exist: {path}")
            sys.exit(1)

    client_data = parse_client_packet(client_log)
    data = parse_proxy_packet(proxy_log)

    # client timeout graph
    plot_graph(
        client_data["timeout"],
        "Cumulative Retries per Packet",
        "client_timeout_packets.png",
    )

    # client success graph
    plot_graph(
        client_data["success"],
        "Cumulative Successful Packets",
        "client_success_packets.png",
    )

    plot_graph(data["drop_server"], "Server Packet Drops", "proxy_drop_server.png")
    plot_graph(data["delay_server"], "Server Packet Delays", "proxy_delay_server.png")
    plot_graph(
        data["send_server"], "Successful Sends to Server", "proxy_send_server.png"
    )

    plot_graph(data["drop_client"], "Client Packet Drops", "proxy_drop_client.png")
    plot_graph(data["delay_client"], "Client Packet Delays", "proxy_delay_client.png")
    plot_graph(
        data["send_client"], "Successful Sends to Client", "proxy_send_client.png"
    )
