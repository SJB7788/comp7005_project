import os
import re
import sys
import time

import matplotlib
import matplotlib.pyplot as plt

matplotlib.use("TkAgg")

SEND_RE = re.compile(r"\[SEND\]")
TIMEOUT_RE = re.compile(r"\[RETRY\]")
RECEIVE_RE = re.compile(r"\[RECEIVE\]")


def setup_graph():
    plt.ion()
    fig, ax = plt.subplots(figsize=(10, 6))

    (timeout_line,) = ax.plot([], [], label="Cumulative Timeouts")
    (success_line,) = ax.plot([], [], label="Cumulative Successes")

    ax.set_xlabel("Packet Number")
    ax.set_ylabel("Cumulative Count")
    ax.set_title("Live Packet Status")
    ax.grid(True, linestyle="--", alpha=0.5)
    ax.legend()

    plt.show(block=False)
    plt.pause(0.01)

    return fig, ax, timeout_line, success_line


def update_graph(ax, timeout_line, success_line, stats):
    timeout_line.set_xdata(stats["packet_numbers"])
    timeout_line.set_ydata(stats["cumulative_timeouts"])

    success_line.set_xdata(stats["packet_numbers"])
    success_line.set_ydata(stats["cumulative_successes"])

    ax.relim()
    ax.autoscale_view()

    plt.draw()
    plt.pause(0.01)


def process_line(line, stats):
    if SEND_RE.search(line):
        # new packet → store current cumulative counters
        stats["packet_numbers"].append(len(stats["packet_numbers"]) + 1)
        stats["cumulative_timeouts"].append(stats["timeout_count"])
        stats["cumulative_successes"].append(stats["success_count"])

    elif TIMEOUT_RE.search(line):
        stats["timeout_count"] += 1

    elif RECEIVE_RE.search(line):
        stats["success_count"] += 1


def follow_file(filename):
    with open(filename, "r") as f:
        for line in f:
            yield line.strip()

        while True:
            pos = f.tell()
            line = f.readline()

            if not line:
                f.seek(pos)
                time.sleep(0.05)
                continue

            yield line.strip()


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
        print("Usage: python3 client_graph.py <client_log>")
        sys.exit(1)

    logfile = sys.argv[1]

    if not os.path.exists(logfile):
        print("Error: file does not exist:", logfile)
        sys.exit(1)

    stats = {
        "packet_numbers": [],
        "cumulative_timeouts": [],
        "cumulative_successes": [],
        "timeout_count": 0,
        "success_count": 0,
    }

    fig, ax, timeout_line, success_line = setup_graph()
    update_graph(ax, timeout_line, success_line, stats)

    print("Following log file:", logfile)
    print("Graph updating live...")

    try:
        for line in follow_file(logfile):
            print(line)
            process_line(line, stats)
            update_graph(ax, timeout_line, success_line, stats)

    except KeyboardInterrupt:
        print("\nStopping. Saving graph...")

    finally:
        plt.close(fig)
        data = parse_client_packet(logfile)

        plot_graph(data["timeout"], "Cumulative timeout", "client_timeout_graph.png")
        plot_graph(data["success"], "Cumulative success", "client_success_graph.png")
