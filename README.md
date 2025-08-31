
# xdp-inspector

High-performance network packet inspector using eBPF/XDP with SQL analytics via DuckDB.

Capture packets at line rate with near-zero CPU overhead, store them in Parquet format, and analyze network traffic using SQL queries.

## Features

- 🚀 **Line-rate packet processing** using XDP (eXpress Data Path)
- 📊 **SQL analytics** on packet data via DuckDB
- 💾 **Columnar storage** using Apache Arrow/Parquet for efficient queries
- 🔍 **Dual-stack support** for IPv4 and IPv6 traffic
- ⚡ **Zero-copy** packet inspection in kernel space
- 📈 **Built-in analytics** for top talkers, flows, and protocol distribution

## Performance

TODO

## Quick Start

### Installation

```bash
# Install dependencies (Debian/Ubuntu)
sudo ln -sf /usr/include/asm-generic/ /usr/include/asm && \
sudo apt-get install -y \
    linux-headers-$(uname -r) \
    libbpf-dev \
    llvm \
    clang \
    gcc-multilib \
    build-essential \
    linux-tools-common \
    linux-tools-$(uname -r) \
    linux-tools-generic

# Clone and build
git clone https://github.com/jnfrati/xdp-inspector
cd xdp-inspector
go generate ./...
go build .

# Or using task (if you have it installed)
task build
```

### Basic Usage

```bash
# Record packets for 30 seconds on interface [REPLACE: your interface, e.g., eth0]
sudo ./xdp-inspector record --interface eth0 --duration 30s --output traffic.parquet

# Analyze captured traffic
./xdp-inspector stats top -f traffic.parquet      # Top talkers by bytes
./xdp-inspector stats flows -f traffic.parquet    # Flow aggregation  
./xdp-inspector stats traffic -f traffic.parquet  # Protocol breakdown
```

## Current Limitations

- Captures ingress traffic only (egress support planned for v0.2)
- LRU stats map limited to IPv4 addresses
- Single interface capture per instance
- No real-time streaming analytics (batch processing only)

## Requirements

- Linux kernel 5.11+ (for ringbuf support)
- Go 1.22+
- Root/CAP_NET_ADMIN privileges for XDP attachment
- Network interface that supports XDP

## Roadmap

- [ ] Egress traffic capture using TC (Traffic Control)
- [ ] Packet sampling configuration
- [ ] TBD


## Acknowledgments

- [XDP Tutorial](https://github.com/xdp-project/xdp-tutorial) for the parsing helpers
- [Cilium eBPF](https://github.com/cilium/ebpf) for the Go eBPF library
- [DuckDB](https://duckdb.org/) for blazing-fast SQL analytics

## License

MIT License - see [LICENSE](LICENSE) file for details

## Author

Nicolas Frati - [@jnfrati](https://github.com/jnfrati)

---

**Note**: This tool requires root privileges and directly interacts with kernel networking stack. Use with appropriate caution in production environments.
