# Paqet Deployment Script

An interactive deployment wizard for [paqet](https://github.com/hanselime/paqet) - a packet-level proxy tool that operates at the raw socket layer for enhanced traffic obfuscation.

## Features

- **Cross-Platform Support**: Works on Linux (Debian, RHEL, Arch) and macOS
- **Interactive Wizard**: Step-by-step guided configuration
- **Auto-Detection**: Automatically detects network interface, IP, gateway MAC
- **Server/Client Modes**: Full support for both deployment roles
- **Performance Profiles**: Pre-configured KCP tuning options for different use cases
- **Port Forwarding**: Configure TCP/UDP port forwarding rules on client
- **Service Management**: Automatic systemd (Linux) and launchd (macOS) service creation
- **Firewall Rules**: Auto-applies required iptables rules on Linux servers
- **Health Checks**: Validates deployment with connectivity tests

## Requirements

- **Operating System**: Linux (Debian/Ubuntu, RHEL/CentOS/Fedora, Arch) or macOS
- **Architecture**: x86_64 (amd64) or ARM64 (aarch64)
- **Dependencies**:
  - `curl` (for downloading)
  - `libpcap` (installed automatically)
- **Privileges**: Root/sudo access required

## Quick Start

### Download and Run

```bash
# Download the script
curl -O https://raw.githubusercontent.com/your-repo/paqet-script/main/deploy-paqet.sh

# Make executable
chmod +x deploy-paqet.sh

# Run the wizard
sudo ./deploy-paqet.sh
```

### Command Line Options

```
Usage: deploy-paqet.sh [OPTIONS]

Options:
  --install-dir DIR    Custom installation directory (default: /opt/paqet)
  --skip-download      Skip binary download (use existing binary)
  -h, --help           Show help message
```

## Deployment Guide

### Server Deployment

1. Run the script and select **Server**
2. Configure network settings (interface, IP, gateway MAC)
3. Choose listening port (default: 9999)
4. **Copy the generated Secret Key** - you'll need this for clients
5. Select encryption algorithm (AES-128 recommended)
6. Choose performance profile
7. Allow service creation and iptables rules

The server will be ready to accept connections once deployment completes.

### Client Deployment

1. Run the script and select **Client**
2. Configure network settings
3. Enter the **Server IP/hostname** and **port**
4. Enter the **Secret Key** from your server
5. Configure SOCKS5 proxy port (default: 1080)
6. Optionally configure port forwarding rules
7. Select encryption (must match server)
8. Choose performance profile

Test the connection:
```bash
curl https://httpbin.org/ip --proxy socks5h://127.0.0.1:1080
```

## Performance Tuning

### Performance Profiles

The script offers three pre-configured profiles:

| Profile | Mode | Connections | Use Case |
|---------|------|-------------|----------|
| **High Speed** | fast3 | 2 | Maximum throughput, streaming, downloads |
| **Balanced** | fast2 | 1 | General use, lower resource consumption |
| **Advanced** | manual | configurable | Expert tuning for specific conditions |

### Profile Comparison Table

| Setting | High Speed | Balanced | Effect |
|---------|------------|----------|--------|
| `mode` | fast3 | fast2 | Controls retransmit aggressiveness |
| `conn` | 2 | 1 | Parallel connections |
| `mtu` | 1400 | 1350 | Packet size |
| `sndwnd` | 2048 | 1024 | Send window |
| `rcvwnd` | 2048 | 1024 | Receive window |
| `smuxbuf` | 8 MB | 4 MB | Multiplexer buffer |
| `streambuf` | 4 MB | 2 MB | Stream buffer |

## KCP Parameter Reference

### Mode Presets

| Mode | nodelay | interval | resend | nc | Description |
|------|---------|----------|--------|-----|-------------|
| `normal` | 0 | 40ms | 2 | 0 | Conservative, minimal CPU |
| `fast` | 0 | 30ms | 2 | 1 | Moderate speed |
| `fast2` | 1 | 20ms | 2 | 1 | Fast, recommended |
| `fast3` | 1 | 10ms | 2 | 1 | Fastest preset |
| `manual` | - | - | - | - | Custom configuration |

### KCP Parameters Effect Table

| Parameter | Range | Higher Value Effect | Lower Value Effect | Resource Impact |
|-----------|-------|---------------------|--------------------|--------------------|
| `conn` | 1-256 | More throughput, parallelism | Less overhead | Memory, CPU |
| `mtu` | 50-1500 | Less overhead per packet | Less fragmentation | Network |
| `sndwnd` | 32-65535 | More data in flight | Less memory | Memory |
| `rcvwnd` | 32-65535 | Handle bursts better | Less memory | Memory |
| `smuxbuf` | 1-64 MB | Better multiplexing | Less memory | Memory |
| `streambuf` | 1-64 MB | Handle large transfers | Less memory | Memory |

### Manual Mode Parameters

When using `mode: manual`, you can fine-tune these parameters:

| Parameter | Values | Description |
|-----------|--------|-------------|
| `nodelay` | 0, 1 | 0=disable, 1=enable low-latency mode |
| `interval` | 5-100ms | Internal update timer (lower = faster, more CPU) |
| `resend` | 0, 1, 2 | Fast retransmit trigger (0=off, 1=most aggressive) |
| `nocongestion` | 0, 1 | 0=congestion control on, 1=off (max speed) |

### Recommended Settings by Scenario

| Scenario | Mode | conn | sndwnd/rcvwnd | Notes |
|----------|------|------|---------------|-------|
| **Streaming/Downloads** | fast3 | 2-4 | 2048-4096 | Max throughput |
| **Low Latency Gaming** | fast3 | 1 | 512-1024 | Minimize buffer |
| **High Latency Network** | fast2 | 2 | 2048-4096 | Large windows help |
| **Limited Bandwidth** | fast | 1 | 512 | Reduce overhead |
| **Server with Many Clients** | fast2 | 1 | 1024 | Balance resources |

## Configuration Files

### Server Configuration Example

```yaml
role: server

log:
  level: info

listen:
  addr: ":9999"

network:
  interface: eth0
  ipv4:
    addr: "192.168.1.100:9999"
    router_mac: "aa:bb:cc:dd:ee:ff"
  tcp:
    local_flag: ["PA"]

transport:
  protocol: kcp
  conn: 2
  kcp:
    mode: fast3
    block: aes
    key: "your-secret-key-here"
    mtu: 1400
    sndwnd: 2048
    rcvwnd: 2048
    smuxbuf: 8388608
    streambuf: 4194304
```

### Client Configuration Example

```yaml
role: client

log:
  level: info

socks5:
  - listen: "127.0.0.1:1080"

forward:
  - listen: "127.0.0.1:8080"
    target: "192.168.1.50:80"
    protocol: "tcp"

network:
  interface: eth0
  ipv4:
    addr: "192.168.1.200:0"
    router_mac: "aa:bb:cc:dd:ee:ff"
  tcp:
    local_flag: ["PA"]
    remote_flag: ["PA"]

server:
  addr: "server.example.com:9999"

transport:
  protocol: kcp
  conn: 2
  kcp:
    mode: fast3
    block: aes
    key: "your-secret-key-here"
    mtu: 1400
    sndwnd: 2048
    rcvwnd: 2048
    smuxbuf: 8388608
    streambuf: 4194304
```

## Service Management

### Linux (systemd)

```bash
# Start/Stop/Restart
sudo systemctl start paqet
sudo systemctl stop paqet
sudo systemctl restart paqet

# Check status
sudo systemctl status paqet

# View logs
sudo journalctl -u paqet -f

# Enable/Disable auto-start
sudo systemctl enable paqet
sudo systemctl disable paqet
```

### macOS (launchd)

```bash
# Load/Unload service
sudo launchctl load /Library/LaunchDaemons/com.paqet.daemon.plist
sudo launchctl unload /Library/LaunchDaemons/com.paqet.daemon.plist

# View logs
tail -f /var/log/paqet.log
tail -f /var/log/paqet.error.log
```

### Manual Execution

```bash
sudo /opt/paqet/paqet run -c /opt/paqet/config.yaml
```

## Firewall Configuration

### Linux Server (iptables)

The script automatically applies these rules on Linux servers:

```bash
# Prevent connection tracking (required for raw socket operation)
iptables -t raw -A PREROUTING -p tcp --dport 9999 -j NOTRACK
iptables -t raw -A OUTPUT -p tcp --sport 9999 -j NOTRACK

# Drop kernel RST packets (paqet handles its own TCP)
iptables -t mangle -A OUTPUT -p tcp --sport 9999 --tcp-flags RST RST -j DROP
```

### Manual Removal

```bash
# Remove rules (replace -A with -D)
sudo iptables -t raw -D PREROUTING -p tcp --dport 9999 -j NOTRACK
sudo iptables -t raw -D OUTPUT -p tcp --sport 9999 -j NOTRACK
sudo iptables -t mangle -D OUTPUT -p tcp --sport 9999 --tcp-flags RST RST -j DROP
```

## Troubleshooting

### Common Issues

#### Connection Failed / Secret Key Mismatch

```
Error: handshake failed
```

**Solution**: Ensure the secret key on client exactly matches the server's key. Re-copy the key from server deployment output.

#### Gateway MAC Not Detected

```
Could not auto-detect gateway MAC address
```

**Solution**: Find it manually:
```bash
# Linux
ip neigh show | grep <gateway-ip>
arp -n | grep <gateway-ip>

# macOS
arp -a | grep <gateway-ip>
```

#### Permission Denied / Raw Socket Error

```
Error: operation not permitted
```

**Solution**: paqet requires root privileges:
```bash
sudo /opt/paqet/paqet run -c /opt/paqet/config.yaml
```

#### SOCKS5 Proxy Not Listening

**Check if process is running:**
```bash
pgrep -f "paqet.*run"
ss -tln | grep 1080
```

**Check logs:**
```bash
sudo journalctl -u paqet -f
```

#### Server Unreachable

1. Verify server is running: `systemctl status paqet`
2. Check firewall allows the port: `sudo iptables -L -n`
3. Test basic connectivity: `ping <server-ip>`
4. Verify iptables rules are applied: `sudo iptables -t raw -L -n`

### Debug Mode

Run with debug logging:
```bash
# Edit config.yaml
log:
  level: debug

# Or run manually with verbose output
sudo /opt/paqet/paqet run -c /opt/paqet/config.yaml
```

### Log Locations

| Platform | Log Location |
|----------|--------------|
| Linux (systemd) | `journalctl -u paqet` |
| macOS (launchd) | `/var/log/paqet.log` |

## Uninstallation

```bash
# Stop and disable service
sudo systemctl stop paqet
sudo systemctl disable paqet

# Remove files
sudo rm -rf /opt/paqet
sudo rm /etc/systemd/system/paqet.service
sudo systemctl daemon-reload

# Remove iptables rules (Linux server)
sudo iptables -t raw -D PREROUTING -p tcp --dport 9999 -j NOTRACK
sudo iptables -t raw -D OUTPUT -p tcp --sport 9999 -j NOTRACK
sudo iptables -t mangle -D OUTPUT -p tcp --sport 9999 --tcp-flags RST RST -j DROP
```

## Security Considerations

- **Secret Key**: Treat the secret key like a password. Anyone with the key can connect to your server.
- **Encryption**: Always use AES encryption in production. "None" should only be used for testing.
- **Firewall**: Only expose the paqet port to trusted networks if possible.
- **Updates**: Regularly check for paqet updates for security patches.

## License

This deployment script is provided as-is. See [paqet repository](https://github.com/hanselime/paqet) for the main project license.

## Links

- [Paqet Repository](https://github.com/hanselime/paqet)
- [KCP Protocol](https://github.com/skywind3000/kcp)
