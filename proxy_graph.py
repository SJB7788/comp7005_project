import os
import re
import sys
import time

import matplotlib
import matplotlib.pyplot as plt

matplotlib.use("TkAgg")

RECEIVE_SERVER_RE = re.compile(r"\[RECEIVE\] \(server\)")
RECEIVE_CLIENT_RE = re.compile(r"\[RECEIVE\] \(client\)")

DROP_SERVER_RE = re.compile(r"\[DROP\] \(server\)")
DROP_CLIENT_RE = re.compile(r"\[DROP\] \(client\)")

DELAY_SERVER_RE = re.compile(r"\[DELAY\] \(server\)")
DELAY_CLIENT_RE = re.compile(r"\[DELAY\] \(client\)")

SEND_TO_SERVER_RE = re.compile(r"\[SEND\] \(server\).*to server")
SEND_TO_CLIENT_RE = re.compile(r"\[SEND\] \(client\).*to client")


def setup_graph():
    plt.ion()
    fig, ax = plt.subplots(figsize=(12, 8))

    lines = {}

    # initialize empty lines
    for key in [
        "drop_server",
        "delay_server",
        "send_server",
        "drop_client",
        "delay_client",
        "send_client",
    ]:
        (line,) = ax.plot([], [], label=key.replace("_", " ").title())
        lines[key] = line

    ax.set_xlabel("Packet Number (Receive Events)")
    ax.set_ylabel("Cumulative Count")
    ax.set_title("Live Proxy Events")
    ax.grid(True, linestyle="--", alpha=0.5)
    ax.legend()

    plt.show(block=False)
    plt.pause(0.01)

    return fig, ax, lines


def update_graph(ax, lines, stats):
    for key in lines:
        lines[key].set_xdata(stats["packet_numbers"])
        lines[key].set_ydata(stats[key])

    ax.relim()
    ax.autoscale_view()

    plt.draw()
    plt.pause(0.01)


def process_line(line, stats):
    if RECEIVE_SERVER_RE.search(line) or RECEIVE_CLIENT_RE.search(line):
        # New packet index (shared timeline)
        stats["packet_numbers"].append(len(stats["packet_numbers"]) + 1)

        # Append snapshots of ALL counters
        stats["drop_server"].append(stats["drop_server_count"])
        stats["delay_server"].append(stats["delay_server_count"])
        stats["send_server"].append(stats["send_server_count"])

        stats["drop_client"].append(stats["drop_client_count"])
        stats["delay_client"].append(stats["delay_client_count"])
        stats["send_client"].append(stats["send_client_count"])

        return

    if DROP_SERVER_RE.search(line):
        stats["drop_server_count"] += 1
    if DELAY_SERVER_RE.search(line):
        stats["delay_server_count"] += 1
    if SEND_TO_SERVER_RE.search(line):
        stats["send_server_count"] += 1

    if DROP_CLIENT_RE.search(line):
        stats["drop_client_count"] += 1
    if DELAY_CLIENT_RE.search(line):
        stats["delay_client_count"] += 1
    if SEND_TO_CLIENT_RE.search(line):
        stats["send_client_count"] += 1


def follow_file(filename):
    with open(filename, "r") as f:
        for line in f:  # Read existing content
            yield line.strip()

        while True:  # Then follow new content
            pos = f.tell()
            line = f.readline()

            if not line:
                f.seek(pos)
                time.sleep(0.05)
                continue

            yield line.strip()


def parse_proxy_packet(filename):
    drop_server_count = 0
    delay_server_count = 0
    send_server_count = 0

    drop_client_count = 0
    delay_client_count = 0
    send_client_count = 0

    drop_server_list = []
    delay_server_list = []
    send_server_list = []

    drop_client_list = []
    delay_client_list = []
    send_client_list = []

    server_packet_index = 0
    client_packet_index = 0

    with open(filename, "r") as f:
        for line in f:
            line = line.strip()

            if RECEIVE_SERVER_RE.search(line):
                server_packet_index += 1
                drop_server_list.append(drop_server_count)
                delay_server_list.append(delay_server_count)
                send_server_list.append(send_server_count)
                continue

            if RECEIVE_CLIENT_RE.search(line):
                client_packet_index += 1
                drop_client_list.append(drop_client_count)
                delay_client_list.append(delay_client_count)
                send_client_list.append(send_client_count)
                continue

            # server events
            if DROP_SERVER_RE.search(line):
                drop_server_count += 1
            if DELAY_SERVER_RE.search(line):
                delay_server_count += 1
            if SEND_TO_SERVER_RE.search(line):
                send_server_count += 1

            # client events
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


# for saving graphs at the end
def plot_graph(values, title, filename):
    x = list(range(1, len(values) + 1))
    plt.ioff()

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
    if len(sys.argv) != 2:
        print("Usage: python3 proxy_graph.py <proxy_log>")
        sys.exit(1)

    logfile = sys.argv[1]

    if not os.path.exists(logfile):
        print("Error: file does not exist:", logfile)
        sys.exit(1)

    stats = {
        "packet_numbers": [],
        "drop_server": [],
        "delay_server": [],
        "send_server": [],
        "drop_client": [],
        "delay_client": [],
        "send_client": [],
        "drop_server_count": 0,
        "delay_server_count": 0,
        "send_server_count": 0,
        "drop_client_count": 0,
        "delay_client_count": 0,
        "send_client_count": 0,
    }

    fig, ax, lines = setup_graph()
    update_graph(ax, lines, stats)

    print("Following log file:", logfile)
    print("Graph updating live (receive-indexed)...")

    try:
        for line in follow_file(logfile):
            process_line(line, stats)
            update_graph(ax, lines, stats)

    except KeyboardInterrupt:
        print("\nStopping. Saving graph...")

    finally:
        plt.close(fig)
        data = parse_proxy_packet(logfile)

        plot_graph(data["drop_server"], "Server Packet Drops", "proxy_drop_server.png")
        plot_graph(
            data["delay_server"], "Server Packet Delays", "proxy_delay_server.png"
        )
        plot_graph(
            data["send_server"], "Successful Sends to Server", "proxy_send_server.png"
        )

        plot_graph(data["drop_client"], "Client Packet Drops", "proxy_drop_client.png")
        plot_graph(
            data["delay_client"], "Client Packet Delays", "proxy_delay_client.png"
        )
        plot_graph(
            data["send_client"], "Successful Sends to Client", "proxy_send_client.png"
        )
        sys.exit(0)
