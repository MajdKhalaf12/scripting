import sys
import fingerprint
import ping_sweeper

def main():
    if len(sys.argv) != 3:
        print("Usage: python wrapper.py <network> <netmask>")
        sys.exit(1)

    network = sys.argv[1]
    netmask = sys.argv[2]

    live_hosts = ping_sweeper.ping_sweep(network, netmask)
    print(f"Ping sweep completed. Found {len(live_hosts)} live hosts")

    for host in live_hosts:
        open_ports = ping_sweeper.port_scan(host, list(range(1, 1024)))
        print(f"Host {host} has {len(open_ports)} open ports: {open_ports}")

        for port in open_ports:
            host_infos = fingerprint.scan_host(host, str(port))
            for host_info in host_infos:
                fingerprint.output_to_csv("scan_results.csv", host_info)
                print("\nScan results:")
                for k, v in host_info.items():
                    print(f"{k}: {v}")
                print("\n")

if __name__ == "__main__":
    main()