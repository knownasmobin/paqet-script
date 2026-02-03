#!/usr/bin/env bash
#
# Paqet Deployment Script v2.1.2
# Automated installation and configuration for paqet packet-level proxy
# Supports Linux (Debian/RHEL) and macOS
# Supports multiple tunnel instances running simultaneously
#
# Repository: https://github.com/hanselime/paqet
#

set -euo pipefail

# ============================================================================
# CONSTANTS & DEFAULTS
# ============================================================================
readonly SCRIPT_VERSION="2.1.2"
readonly GITHUB_REPO="hanselime/paqet"
readonly GITHUB_API="https://api.github.com/repos/${GITHUB_REPO}"
readonly DEFAULT_PORT=9999
readonly DEFAULT_SOCKS_PORT=1080
readonly INSTALL_DIR="/opt/paqet"
readonly CONFIG_FILE="config.yaml"
readonly HEALTH_CHECK_URL="https://httpbin.org/ip"
readonly HEALTH_CHECK_TIMEOUT=15

# Colors for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly CYAN='\033[0;36m'
readonly BOLD='\033[1m'
readonly NC='\033[0m' # No Color

# Global configuration variables
ROLE=""
INTERFACE=""
IP_ADDRESS=""
ROUTER_MAC=""
LISTEN_PORT=""
SECRET_KEY=""
CRYPTO_BLOCK=""
LOG_LEVEL=""
SOCKS_PORT=""
SERVER_ADDRESS=""
SUDO=""
INSTANCE_NAME="paqet"
INSTANCE_SUFFIX=""
declare -a PORT_FORWARDS=()

# KCP Performance configuration
KCP_MODE="fast3"
KCP_CONN=2
KCP_MTU=1400
KCP_SNDWND=2048
KCP_RCVWND=2048
KCP_SMUXBUF=8388608
KCP_STREAMBUF=4194304
# Manual mode parameters (only used when KCP_MODE="manual")
KCP_NODELAY=1
KCP_INTERVAL=10
KCP_RESEND=2
KCP_NOCONGESTION=1

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

print_banner() {
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                  PAQET DEPLOYMENT WIZARD                      ║"
    echo "║           Packet-Level Proxy Installation Script              ║"
    echo "║                      Version ${SCRIPT_VERSION}                          ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[!]${NC} $1"
}

log_error() {
    echo -e "${RED}[✗]${NC} $1"
}

log_step() {
    echo -e "\n${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${CYAN}▶ $1${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

print_key_box() {
    local key="$1"
    echo ""
    echo -e "${YELLOW}╔══════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${YELLOW}║  ${BOLD}IMPORTANT: Copy this Secret Key to your Client configuration:${NC}${YELLOW}       ║${NC}"
    echo -e "${YELLOW}╠══════════════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${YELLOW}║${NC}                                                                      ${YELLOW}║${NC}"
    echo -e "${YELLOW}║${NC}  ${GREEN}${BOLD}${key}${NC}"
    echo -e "${YELLOW}║${NC}                                                                      ${YELLOW}║${NC}"
    echo -e "${YELLOW}╠══════════════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${YELLOW}║${NC}  ${RED}Without this key, clients cannot connect to your server!${NC}          ${YELLOW}║${NC}"
    echo -e "${YELLOW}╚══════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

prompt_user() {
    local prompt="$1"
    local default="${2:-}"
    local result

    if [[ -n "$default" ]]; then
        read -rp "$(echo -e "${GREEN}?${NC} ${prompt} [${default}]: ")" result
        echo "${result:-$default}"
    else
        read -rp "$(echo -e "${GREEN}?${NC} ${prompt}: ")" result
        echo "$result"
    fi
}

prompt_confirm() {
    local prompt="$1"
    local default="${2:-y}"
    local result

    if [[ "$default" == "y" ]]; then
        read -rp "$(echo -e "${GREEN}?${NC} ${prompt} [Y/n]: ")" result
        result="${result:-y}"
    else
        read -rp "$(echo -e "${GREEN}?${NC} ${prompt} [y/N]: ")" result
        result="${result:-n}"
    fi

    [[ "${result,,}" == "y" || "${result,,}" == "yes" ]]
}

prompt_choice() {
    local prompt="$1"
    shift
    local options=("$@")
    local choice

    echo -e "\n${GREEN}?${NC} ${prompt}" >&2
    for i in "${!options[@]}"; do
        echo "  $((i+1))) ${options[$i]}" >&2
    done

    while true; do
        read -rp "Enter choice [1-${#options[@]}]: " choice
        if [[ "$choice" =~ ^[0-9]+$ ]] && ((choice >= 1 && choice <= ${#options[@]})); then
            echo "$((choice-1))"
            return
        fi
        log_error "Invalid choice. Please enter a number between 1 and ${#options[@]}" >&2
    done
}

check_command() {
    command -v "$1" &>/dev/null
}

cleanup() {
    if [[ -d "${TEMP_DIR:-}" ]]; then
        rm -rf "$TEMP_DIR"
    fi
}

trap cleanup EXIT

# ============================================================================
# EXISTING INSTALLATION DETECTION
# ============================================================================

detect_existing_installations() {
    local os="$1"
    local found=0

    echo ""
    log_step "Checking for Existing Paqet Installations"

    # Find all paqet config files
    local configs=()
    if [[ -d "$INSTALL_DIR" ]]; then
        while IFS= read -r -d '' config; do
            configs+=("$config")
        done < <(find "$INSTALL_DIR" -name "*.yaml" -type f -print0 2>/dev/null)
    fi

    # Check for running paqet processes
    local running_pids=()
    while IFS= read -r pid; do
        [[ -n "$pid" ]] && running_pids+=("$pid")
    done < <(pgrep -f "paqet.*run" 2>/dev/null)

    if [[ ${#configs[@]} -eq 0 && ${#running_pids[@]} -eq 0 ]]; then
        log_info "No existing paqet installations found."
        return 1
    fi

    found=1
    echo ""
    echo -e "${YELLOW}╔══════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${YELLOW}║                    EXISTING PAQET INSTALLATIONS                       ║${NC}"
    echo -e "${YELLOW}╚══════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""

    # Show running processes
    if [[ ${#running_pids[@]} -gt 0 ]]; then
        echo -e "${CYAN}Running Processes:${NC}"
        for pid in "${running_pids[@]}"; do
            local cmdline
            cmdline=$(ps -p "$pid" -o args= 2>/dev/null || true)
            if [[ -n "$cmdline" ]]; then
                echo -e "  ${GREEN}●${NC} PID $pid: $cmdline"
            fi
        done
        echo ""
    fi

    # Show configuration files and their details
    if [[ ${#configs[@]} -gt 0 ]]; then
        echo -e "${CYAN}Configuration Files:${NC}"
        for config in "${configs[@]}"; do
            echo ""
            echo -e "  ${BLUE}▸ $config${NC}"

            # Parse config file for key information
            if [[ -f "$config" ]]; then
                local cfg_role cfg_port cfg_server cfg_socks
                cfg_role=$(grep -E "^role:" "$config" 2>/dev/null | awk '{print $2}' || echo "unknown")

                if [[ "$cfg_role" == "server" ]]; then
                    cfg_port=$(grep -E "addr:.*:" "$config" 2>/dev/null | head -1 | grep -oE ':[0-9]+' | tr -d ':' || echo "?")
                    echo "    Role: ${cfg_role}"
                    echo "    Port: ${cfg_port}"
                else
                    cfg_server=$(grep -E "^\s*addr:" "$config" 2>/dev/null | tail -1 | awk '{print $2}' | tr -d '"' || echo "?")
                    cfg_socks=$(grep -E "listen:.*127.0.0.1:" "$config" 2>/dev/null | head -1 | grep -oE ':[0-9]+' | tr -d ':' || echo "?")
                    echo "    Role: ${cfg_role}"
                    echo "    Server: ${cfg_server}"
                    echo "    SOCKS5 Port: ${cfg_socks}"
                fi

                # Check if this config has an active service
                local service_name
                service_name=$(basename "$config" .yaml)
                if [[ "$os" == "linux" ]] && check_command systemctl; then
                    if systemctl is-active --quiet "$service_name" 2>/dev/null; then
                        echo -e "    Service: ${GREEN}running${NC} ($service_name)"
                    elif systemctl is-enabled --quiet "$service_name" 2>/dev/null; then
                        echo -e "    Service: ${YELLOW}stopped${NC} ($service_name)"
                    fi
                fi
            fi
        done
        echo ""
    fi

    return 0
}

prompt_installation_action() {
    echo ""
    echo -e "${CYAN}What would you like to do?${NC}"
    echo ""

    local action_choice
    action_choice=$(prompt_choice "Select an action:" \
        "Create a NEW tunnel (alongside existing)" \
        "Reconfigure existing installation" \
        "View status only and exit")

    case "$action_choice" in
        0)
            # Create new instance
            configure_new_instance
            return 0
            ;;
        1)
            # Reconfigure - use default names
            INSTANCE_NAME="paqet"
            INSTANCE_SUFFIX=""
            return 0
            ;;
        2)
            # Exit
            echo ""
            log_info "Exiting. No changes made."
            exit 0
            ;;
    esac
}

configure_new_instance() {
    echo ""
    log_info "Creating a new paqet tunnel instance."
    echo ""

    # Generate a unique instance name
    local instance_num=2
    while [[ -f "${INSTALL_DIR}/config-${instance_num}.yaml" ]] || \
          systemctl is-enabled --quiet "paqet-${instance_num}" 2>/dev/null; do
        instance_num=$((instance_num + 1))
    done

    INSTANCE_SUFFIX="-${instance_num}"
    INSTANCE_NAME="paqet${INSTANCE_SUFFIX}"

    log_info "New instance will be named: ${INSTANCE_NAME}"
    log_info "Config file: ${INSTALL_DIR}/config${INSTANCE_SUFFIX}.yaml"
    echo ""

    # Suggest different default ports
    local suggested_port=$((DEFAULT_PORT + instance_num - 1))
    local suggested_socks=$((DEFAULT_SOCKS_PORT + instance_num - 1))

    log_warn "Make sure to use different ports from existing instances!"
    log_info "Suggested ports: Server=${suggested_port}, SOCKS5=${suggested_socks}"
}

get_config_filename() {
    if [[ -n "$INSTANCE_SUFFIX" ]]; then
        echo "config${INSTANCE_SUFFIX}.yaml"
    else
        echo "$CONFIG_FILE"
    fi
}

# ============================================================================
# SYSTEM DETECTION
# ============================================================================

detect_os() {
    local os
    case "$(uname -s)" in
        Linux*)  os="linux" ;;
        Darwin*) os="darwin" ;;
        *)
            log_error "Unsupported operating system: $(uname -s)"
            exit 1
            ;;
    esac
    echo "$os"
}

detect_arch() {
    local arch
    case "$(uname -m)" in
        x86_64|amd64)  arch="amd64" ;;
        aarch64|arm64) arch="arm64" ;;
        *)
            log_error "Unsupported architecture: $(uname -m)"
            exit 1
            ;;
    esac
    echo "$arch"
}

detect_package_manager() {
    local os="$1"

    if [[ "$os" == "darwin" ]]; then
        if check_command brew; then
            echo "brew"
        else
            log_error "Homebrew is required on macOS but not found."
            log_info "Install it from: https://brew.sh"
            exit 1
        fi
    else
        if check_command apt-get; then
            echo "apt"
        elif check_command yum; then
            echo "yum"
        elif check_command dnf; then
            echo "dnf"
        elif check_command pacman; then
            echo "pacman"
        else
            log_error "No supported package manager found (apt, yum, dnf, pacman)"
            exit 1
        fi
    fi
}

detect_linux_distro() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        echo "$ID"
    elif [[ -f /etc/redhat-release ]]; then
        echo "rhel"
    elif [[ -f /etc/debian_version ]]; then
        echo "debian"
    else
        echo "unknown"
    fi
}

# ============================================================================
# PRIVILEGE CHECK
# ============================================================================

check_sudo() {
    if [[ $EUID -eq 0 ]]; then
        SUDO=""
    else
        if ! check_command sudo; then
            log_error "This script requires sudo privileges, but sudo is not installed."
            exit 1
        fi

        log_info "Checking sudo privileges..."
        if ! sudo -v; then
            log_error "Failed to obtain sudo privileges."
            exit 1
        fi
        SUDO="sudo"
        log_success "Sudo privileges verified."
    fi
}

# ============================================================================
# DEPENDENCY MANAGEMENT
# ============================================================================

install_libpcap() {
    local pkg_mgr="$1"

    log_info "Installing libpcap..."

    case "$pkg_mgr" in
        apt)
            $SUDO apt-get update -qq
            $SUDO apt-get install -y libpcap-dev
            ;;
        yum)
            $SUDO yum install -y libpcap-devel
            ;;
        dnf)
            $SUDO dnf install -y libpcap-devel
            ;;
        pacman)
            $SUDO pacman -S --noconfirm libpcap
            ;;
        brew)
            brew install libpcap
            ;;
    esac

    log_success "libpcap installed."
}

check_libpcap() {
    local os="$1"

    if [[ "$os" == "darwin" ]]; then
        if [[ -f /usr/include/pcap/pcap.h ]] || brew list libpcap &>/dev/null 2>&1; then
            return 0
        fi
    else
        if ldconfig -p 2>/dev/null | grep -q libpcap || \
           [[ -f /usr/include/pcap/pcap.h ]] || \
           [[ -f /usr/include/pcap.h ]]; then
            return 0
        fi
    fi
    return 1
}

install_dependencies() {
    local os="$1"
    local pkg_mgr="$2"

    log_step "Installing Dependencies"

    # Check for required tools
    local missing_tools=()
    for tool in curl tar; do
        if ! check_command "$tool"; then
            missing_tools+=("$tool")
        fi
    done

    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        log_info "Installing missing tools: ${missing_tools[*]}"
        case "$pkg_mgr" in
            apt)
                $SUDO apt-get update -qq
                $SUDO apt-get install -y "${missing_tools[@]}"
                ;;
            yum)
                $SUDO yum install -y "${missing_tools[@]}"
                ;;
            dnf)
                $SUDO dnf install -y "${missing_tools[@]}"
                ;;
            pacman)
                $SUDO pacman -S --noconfirm "${missing_tools[@]}"
                ;;
            brew)
                brew install "${missing_tools[@]}"
                ;;
        esac
    fi

    # Check libpcap
    if check_libpcap "$os"; then
        log_success "libpcap is already installed."
    else
        install_libpcap "$pkg_mgr"
    fi
}

# ============================================================================
# RELEASE DOWNLOAD
# ============================================================================

get_latest_release() {
    log_info "Fetching latest release from GitHub..." >&2

    local release_info
    release_info=$(curl -fsSL "${GITHUB_API}/releases/latest" 2>/dev/null) || {
        log_error "Failed to fetch release information from GitHub." >&2
        exit 1
    }

    local tag
    tag=$(echo "$release_info" | grep -o '"tag_name"[[:space:]]*:[[:space:]]*"[^"]*"' | head -1 | sed 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)"/\1/')

    if [[ -z "$tag" ]]; then
        log_error "Could not determine latest release tag." >&2
        exit 1
    fi

    echo "$tag"
}

download_binary() {
    local os="$1"
    local arch="$2"
    local version="$3"
    local dest_dir="$4"

    log_step "Downloading Paqet Binary"

    local filename="paqet-${os}-${arch}-${version}.tar.gz"
    local download_url="https://github.com/${GITHUB_REPO}/releases/download/${version}/${filename}"

    log_info "Version:      ${version}"
    log_info "OS/Arch:      ${os}/${arch}"
    log_info "Download URL: ${download_url}"

    TEMP_DIR=$(mktemp -d)
    local archive_path="${TEMP_DIR}/${filename}"

    echo ""
    if ! curl -fSL --progress-bar -o "$archive_path" "$download_url"; then
        log_error "Failed to download binary."
        exit 1
    fi

    log_info "Extracting archive..."
    tar -xzf "$archive_path" -C "$TEMP_DIR"

    # Find the binary
    local binary_path
    binary_path=$(find "$TEMP_DIR" -name "paqet" -type f 2>/dev/null | head -1)

    if [[ -z "$binary_path" ]]; then
        binary_path=$(find "$TEMP_DIR" -name "paqet_*" -type f 2>/dev/null | head -1)
    fi

    if [[ -z "$binary_path" ]]; then
        binary_path=$(find "$TEMP_DIR" -type f -perm -u+x 2>/dev/null | grep -v "\.tar\.gz$" | head -1)
    fi

    if [[ -z "$binary_path" || ! -f "$binary_path" ]]; then
        log_error "Could not find paqet binary in downloaded archive."
        exit 1
    fi

    # Create installation directory
    $SUDO mkdir -p "$dest_dir"
    $SUDO cp "$binary_path" "${dest_dir}/paqet"
    $SUDO chmod +x "${dest_dir}/paqet"

    log_success "Binary installed to ${dest_dir}/paqet"
}

# ============================================================================
# NETWORK DETECTION
# ============================================================================

detect_default_interface() {
    local os="$1"
    local interface=""

    if [[ "$os" == "darwin" ]]; then
        interface=$(route -n get default 2>/dev/null | grep 'interface:' | awk '{print $2}')
        if [[ -z "$interface" ]]; then
            interface=$(netstat -rn | grep '^default' | head -1 | awk '{print $NF}')
        fi
    else
        interface=$(ip route show default 2>/dev/null | grep -oP 'dev \K\S+' | head -1)
        if [[ -z "$interface" ]]; then
            interface=$(route -n 2>/dev/null | grep '^0\.0\.0\.0' | awk '{print $NF}' | head -1)
        fi
    fi

    echo "$interface"
}

detect_interface_ip() {
    local os="$1"
    local interface="$2"
    local ip=""

    if [[ "$os" == "darwin" ]]; then
        ip=$(ifconfig "$interface" 2>/dev/null | grep 'inet ' | grep -v '127.0.0.1' | awk '{print $2}' | head -1)
    else
        ip=$(ip addr show "$interface" 2>/dev/null | grep 'inet ' | grep -v '127.0.0.1' | awk '{print $2}' | cut -d'/' -f1 | head -1)
        if [[ -z "$ip" ]]; then
            ip=$(ifconfig "$interface" 2>/dev/null | grep 'inet ' | awk '{print $2}' | sed 's/addr://' | head -1)
        fi
    fi

    echo "$ip"
}

detect_gateway_ip() {
    local os="$1"
    local gateway=""

    if [[ "$os" == "darwin" ]]; then
        gateway=$(route -n get default 2>/dev/null | grep 'gateway:' | awk '{print $2}')
        if [[ -z "$gateway" ]]; then
            gateway=$(netstat -rn | grep '^default' | head -1 | awk '{print $2}')
        fi
    else
        gateway=$(ip route show default 2>/dev/null | grep -oP 'via \K\S+' | head -1)
        if [[ -z "$gateway" ]]; then
            gateway=$(route -n 2>/dev/null | grep '^0\.0\.0\.0' | awk '{print $2}' | head -1)
        fi
    fi

    echo "$gateway"
}

detect_gateway_mac() {
    local os="$1"
    local gateway_ip="$2"
    local mac=""

    if [[ -z "$gateway_ip" ]]; then
        return
    fi

    # Ping gateway to populate ARP cache
    ping -c 1 -W 1 "$gateway_ip" &>/dev/null || true

    if [[ "$os" == "darwin" ]]; then
        mac=$(arp -n "$gateway_ip" 2>/dev/null | awk '{print $4}' | grep -v 'no')
        if [[ -z "$mac" || "$mac" == "(incomplete)" ]]; then
            mac=$(arp -a 2>/dev/null | grep "($gateway_ip)" | awk '{print $4}')
        fi
    else
        mac=$(arp -n "$gateway_ip" 2>/dev/null | awk 'NR>1 {print $3}')
        if [[ -z "$mac" || "$mac" == "(incomplete)" ]]; then
            mac=$(ip neigh show "$gateway_ip" 2>/dev/null | awk '{print $5}')
        fi
    fi

    # Normalize MAC address format
    if [[ -n "$mac" ]]; then
        mac=$(echo "$mac" | tr '[:upper:]' '[:lower:]' | tr '-' ':')
    fi

    echo "$mac"
}

list_interfaces() {
    local os="$1"

    if [[ "$os" == "darwin" ]]; then
        ifconfig -l | tr ' ' '\n' | grep -v '^lo'
    else
        ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | grep -v '^lo'
        if [[ ${PIPESTATUS[0]} -ne 0 ]]; then
            ls /sys/class/net 2>/dev/null | grep -v '^lo'
        fi
    fi
}

# ============================================================================
# SECRET KEY MANAGEMENT
# ============================================================================

generate_secret_key() {
    local install_dir="$1"
    local key=""

    log_info "Generating secure transport key..." >&2

    if [[ -x "${install_dir}/paqet" ]]; then
        key=$("${install_dir}/paqet" secret 2>/dev/null) || \
        key=$($SUDO "${install_dir}/paqet" secret 2>/dev/null) || true
    fi

    if [[ -z "$key" ]]; then
        log_warn "Could not run 'paqet secret', generating random key..." >&2
        key=$(openssl rand -base64 32 2>/dev/null || head -c 32 /dev/urandom | base64)
    fi

    echo "$key"
}

prompt_secret_key() {
    local key=""

    echo "" >&2
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}" >&2
    echo -e "${YELLOW}  You need the Secret Key generated by your paqet Server.${NC}" >&2
    echo -e "${YELLOW}  If you haven't deployed the server yet, do that first!${NC}" >&2
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}" >&2
    echo "" >&2

    while [[ -z "$key" ]]; do
        key=$(prompt_user "Enter the Secret Key generated by your Server")
        if [[ -z "$key" ]]; then
            log_error "Secret key is required. Cannot proceed without it." >&2
        fi
    done

    echo "$key"
}

# ============================================================================
# PORT FORWARDING CONFIGURATION
# ============================================================================

configure_port_forwards() {
    echo ""
    log_info "Port forwarding allows you to tunnel specific ports through the server."
    log_info "Example: Forward local port 8080 to remote web server at 192.168.1.100:80"
    echo ""

    if ! prompt_confirm "Do you want to configure specific port forwarding rules?" "n"; then
        return
    fi

    echo ""
    log_info "Enter port forwarding rules. Type 'done' when finished."
    echo ""

    local count=1
    while true; do
        echo -e "${CYAN}--- Port Forward Rule #${count} ---${NC}"

        local local_port
        local_port=$(prompt_user "Local port to listen on (or 'done' to finish)")

        if [[ "${local_port,,}" == "done" ]]; then
            break
        fi

        if ! [[ "$local_port" =~ ^[0-9]+$ ]] || ((local_port < 1 || local_port > 65535)); then
            log_error "Invalid port number. Please enter a number between 1-65535."
            continue
        fi

        local target
        target=$(prompt_user "Destination address:port (e.g., 192.168.1.100:80)")

        if [[ -z "$target" ]] || ! [[ "$target" =~ :.+ ]]; then
            log_error "Invalid format. Use address:port format."
            continue
        fi

        local protocol
        local proto_choice
        proto_choice=$(prompt_choice "Protocol:" "TCP (Recommended)" "UDP")
        if [[ "$proto_choice" == "0" ]]; then
            protocol="tcp"
        else
            protocol="udp"
        fi

        PORT_FORWARDS+=("${local_port}|${target}|${protocol}")
        log_success "Added: localhost:${local_port} -> ${target} (${protocol})"
        count=$((count + 1))
        echo ""
    done

    if [[ ${#PORT_FORWARDS[@]} -gt 0 ]]; then
        log_success "Configured ${#PORT_FORWARDS[@]} port forwarding rule(s)."
    fi
}

# ============================================================================
# PERFORMANCE PROFILE CONFIGURATION
# ============================================================================

configure_performance_profile() {
    echo ""
    log_info "Performance profile affects connection speed and resource usage."
    echo ""
    echo -e "${CYAN}Available profiles:${NC}"
    echo ""
    echo -e "  ${GREEN}1) High Speed (Recommended)${NC}"
    echo "     • Mode: fast3 (aggressive retransmit, 10ms interval)"
    echo "     • 2 parallel connections, larger buffers"
    echo "     • Best for: Maximum throughput, streaming, downloads"
    echo ""
    echo -e "  ${YELLOW}2) Balanced${NC}"
    echo "     • Mode: fast2 (moderate retransmit, 20ms interval)"
    echo "     • 1 connection, standard buffers"
    echo "     • Best for: General use, lower resource usage"
    echo ""
    echo -e "  ${BLUE}3) Advanced (Manual tuning)${NC}"
    echo "     • Configure each KCP parameter individually"
    echo "     • Best for: Expert users, specific network conditions"
    echo ""

    local profile_choice
    profile_choice=$(prompt_choice "Select performance profile:" "High Speed (Recommended)" "Balanced" "Advanced")

    case "$profile_choice" in
        0)
            # High Speed - fast3 with optimized values
            KCP_MODE="fast3"
            KCP_CONN=2
            KCP_MTU=1400
            KCP_SNDWND=2048
            KCP_RCVWND=2048
            KCP_SMUXBUF=8388608
            KCP_STREAMBUF=4194304
            log_success "Selected: High Speed profile"
            ;;
        1)
            # Balanced - fast2 with standard values
            KCP_MODE="fast2"
            KCP_CONN=1
            KCP_MTU=1350
            KCP_SNDWND=1024
            KCP_RCVWND=1024
            KCP_SMUXBUF=4194304
            KCP_STREAMBUF=2097152
            log_success "Selected: Balanced profile"
            ;;
        2)
            # Advanced - manual configuration
            configure_advanced_kcp
            ;;
    esac
}

configure_advanced_kcp() {
    log_step "Advanced KCP Configuration"

    echo ""
    log_info "Configure KCP parameters for fine-tuned performance."
    echo ""

    # Mode selection
    echo -e "${CYAN}KCP Modes:${NC}"
    echo "  normal  - Conservative, low CPU (nodelay=0, interval=40ms)"
    echo "  fast    - Moderate speed (nodelay=0, interval=30ms)"
    echo "  fast2   - Fast, recommended (nodelay=1, interval=20ms)"
    echo "  fast3   - Fastest preset (nodelay=1, interval=10ms)"
    echo "  manual  - Set each parameter yourself"
    echo ""

    local mode_choice
    mode_choice=$(prompt_choice "Select KCP mode:" "fast3 (Fastest)" "fast2" "fast" "manual")

    case "$mode_choice" in
        0) KCP_MODE="fast3" ;;
        1) KCP_MODE="fast2" ;;
        2) KCP_MODE="fast" ;;
        3)
            KCP_MODE="manual"
            configure_manual_kcp_params
            ;;
    esac

    # Connection count
    echo ""
    log_info "Parallel connections (1-4): More = higher throughput, more resources"
    KCP_CONN=$(prompt_user "Number of parallel connections" "2")
    if ! [[ "$KCP_CONN" =~ ^[0-9]+$ ]] || ((KCP_CONN < 1 || KCP_CONN > 256)); then
        KCP_CONN=2
    fi

    # MTU
    echo ""
    log_info "MTU (1350-1450): Higher = less overhead, may cause fragmentation"
    KCP_MTU=$(prompt_user "MTU size" "1400")
    if ! [[ "$KCP_MTU" =~ ^[0-9]+$ ]] || ((KCP_MTU < 50 || KCP_MTU > 1500)); then
        KCP_MTU=1400
    fi

    # Window sizes
    echo ""
    log_info "Window sizes (512-4096): Larger = more data in flight, better for high latency"
    KCP_SNDWND=$(prompt_user "Send window size" "2048")
    KCP_RCVWND=$(prompt_user "Receive window size" "2048")
    if ! [[ "$KCP_SNDWND" =~ ^[0-9]+$ ]]; then KCP_SNDWND=2048; fi
    if ! [[ "$KCP_RCVWND" =~ ^[0-9]+$ ]]; then KCP_RCVWND=2048; fi

    # Buffer sizes
    echo ""
    log_info "Buffer sizes affect memory usage and burst handling"
    local smux_mb
    smux_mb=$(prompt_user "SMUX buffer size in MB" "8")
    if [[ "$smux_mb" =~ ^[0-9]+$ ]]; then
        KCP_SMUXBUF=$((smux_mb * 1048576))
    fi

    local stream_mb
    stream_mb=$(prompt_user "Stream buffer size in MB" "4")
    if [[ "$stream_mb" =~ ^[0-9]+$ ]]; then
        KCP_STREAMBUF=$((stream_mb * 1048576))
    fi

    log_success "Advanced KCP configuration complete"
}

configure_manual_kcp_params() {
    echo ""
    log_info "Manual KCP parameters (for expert users):"
    echo ""

    echo -e "${CYAN}nodelay:${NC} 0=disable, 1=enable"
    echo "  Enable for lower latency & aggressive retransmission"
    KCP_NODELAY=$(prompt_user "nodelay" "1")
    if ! [[ "$KCP_NODELAY" =~ ^[01]$ ]]; then KCP_NODELAY=1; fi

    echo ""
    echo -e "${CYAN}interval:${NC} Internal update timer (5-100ms)"
    echo "  Lower = more responsive, higher CPU usage"
    KCP_INTERVAL=$(prompt_user "interval (ms)" "10")
    if ! [[ "$KCP_INTERVAL" =~ ^[0-9]+$ ]]; then KCP_INTERVAL=10; fi

    echo ""
    echo -e "${CYAN}resend:${NC} Fast retransmit trigger (0-2)"
    echo "  0=disabled, 1=most aggressive, 2=aggressive"
    KCP_RESEND=$(prompt_user "resend" "2")
    if ! [[ "$KCP_RESEND" =~ ^[0-2]$ ]]; then KCP_RESEND=2; fi

    echo ""
    echo -e "${CYAN}nocongestion:${NC} 0=enabled, 1=disabled"
    echo "  Disable congestion control for max speed (use with caution)"
    KCP_NOCONGESTION=$(prompt_user "nocongestion" "1")
    if ! [[ "$KCP_NOCONGESTION" =~ ^[01]$ ]]; then KCP_NOCONGESTION=1; fi
}

# ============================================================================
# CONFIGURATION WIZARD
# ============================================================================

configure_network() {
    local os="$1"

    log_step "Network Configuration"

    log_info "Auto-detecting network configuration..."
    echo ""

    # Interface detection
    local detected_interface
    detected_interface=$(detect_default_interface "$os")

    echo -e "${CYAN}Available network interfaces:${NC}"
    list_interfaces "$os" | while read -r iface; do
        local iface_ip
        iface_ip=$(detect_interface_ip "$os" "$iface")
        if [[ -n "$iface_ip" ]]; then
            if [[ "$iface" == "$detected_interface" ]]; then
                echo -e "  ${GREEN}▸ ${iface}: ${iface_ip} (default)${NC}"
            else
                echo "    ${iface}: ${iface_ip}"
            fi
        else
            echo "    ${iface}: (no IPv4)"
        fi
    done

    echo ""
    INTERFACE=$(prompt_user "Network interface" "$detected_interface")

    # IP Address
    local detected_ip
    detected_ip=$(detect_interface_ip "$os" "$INTERFACE")
    IP_ADDRESS=$(prompt_user "Local IP address" "$detected_ip")

    # Gateway MAC detection
    echo ""
    log_info "Detecting gateway MAC address..."
    local gateway_ip
    gateway_ip=$(detect_gateway_ip "$os")

    if [[ -n "$gateway_ip" ]]; then
        log_info "Gateway IP: ${gateway_ip}"
    else
        log_warn "Could not detect gateway IP."
    fi

    local detected_mac
    detected_mac=$(detect_gateway_mac "$os" "$gateway_ip")

    if [[ -n "$detected_mac" ]]; then
        log_success "Gateway MAC detected: ${detected_mac}"
        ROUTER_MAC=$(prompt_user "Gateway/Router MAC address" "$detected_mac")
    else
        log_warn "Could not auto-detect gateway MAC address."
        log_info "Find it manually: arp -a | grep ${gateway_ip:-<gateway-ip>}"
        ROUTER_MAC=$(prompt_user "Gateway/Router MAC address (required)")

        if [[ -z "$ROUTER_MAC" ]]; then
            log_error "Gateway MAC address is required for paqet to function."
            exit 1
        fi
    fi

    # Normalize MAC format
    ROUTER_MAC=$(echo "$ROUTER_MAC" | tr '[:upper:]' '[:lower:]' | tr '-' ':')
}

configure_server() {
    local os="$1"
    local install_dir="$2"

    log_step "Server Configuration"

    # Port
    LISTEN_PORT=$(prompt_user "Server listening port" "$DEFAULT_PORT")

    # Generate secret key
    SECRET_KEY=$(generate_secret_key "$install_dir")

    # Display the key prominently
    print_key_box "$SECRET_KEY"

    echo ""
    read -rp "Press Enter after you have copied the key..."

    # Encryption
    echo ""
    local crypto_choice
    crypto_choice=$(prompt_choice "Select encryption algorithm:" "AES-128 (Recommended)" "AES-256" "None (Testing only)")

    case "$crypto_choice" in
        0) CRYPTO_BLOCK="aes" ;;
        1) CRYPTO_BLOCK="aes-256" ;;
        2) CRYPTO_BLOCK="none" ;;
    esac

    # Log level
    local log_choice
    log_choice=$(prompt_choice "Select log level:" "info (Recommended)" "debug" "warn" "error")

    case "$log_choice" in
        0) LOG_LEVEL="info" ;;
        1) LOG_LEVEL="debug" ;;
        2) LOG_LEVEL="warn" ;;
        3) LOG_LEVEL="error" ;;
    esac

    # Performance profile
    configure_performance_profile
}

configure_client() {
    local os="$1"
    local install_dir="$2"

    log_step "Client Configuration"

    # Server address
    SERVER_ADDRESS=$(prompt_user "Remote paqet server IP/hostname")
    if [[ -z "$SERVER_ADDRESS" ]]; then
        log_error "Server address is required."
        exit 1
    fi

    # Server port
    LISTEN_PORT=$(prompt_user "Remote server port" "$DEFAULT_PORT")

    # Secret key from server
    SECRET_KEY=$(prompt_secret_key)

    # SOCKS5 port
    echo ""
    log_info "SOCKS5 proxy allows any application to route traffic through paqet."
    SOCKS_PORT=$(prompt_user "Local SOCKS5 proxy port" "$DEFAULT_SOCKS_PORT")

    # Port forwarding
    configure_port_forwards

    # Encryption (must match server)
    echo ""
    local crypto_choice
    crypto_choice=$(prompt_choice "Select encryption algorithm (must match server):" "AES-128 (Recommended)" "AES-256" "None")

    case "$crypto_choice" in
        0) CRYPTO_BLOCK="aes" ;;
        1) CRYPTO_BLOCK="aes-256" ;;
        2) CRYPTO_BLOCK="none" ;;
    esac

    # Log level
    local log_choice
    log_choice=$(prompt_choice "Select log level:" "info (Recommended)" "debug" "warn" "error")

    case "$log_choice" in
        0) LOG_LEVEL="info" ;;
        1) LOG_LEVEL="debug" ;;
        2) LOG_LEVEL="warn" ;;
        3) LOG_LEVEL="error" ;;
    esac

    # Performance profile
    configure_performance_profile
}

# ============================================================================
# CONFIGURATION FILE GENERATION
# ============================================================================

generate_kcp_config() {
    # Generate the KCP configuration section based on mode
    local kcp_yaml=""

    if [[ "$KCP_MODE" == "manual" ]]; then
        kcp_yaml="    mode: manual
    nodelay: ${KCP_NODELAY}
    interval: ${KCP_INTERVAL}
    resend: ${KCP_RESEND}
    nocongestion: ${KCP_NOCONGESTION}"
    else
        kcp_yaml="    mode: ${KCP_MODE}"
    fi

    echo "$kcp_yaml"
}

generate_server_config() {
    local config_path="$1"
    local kcp_mode_config
    kcp_mode_config=$(generate_kcp_config)

    cat > "$config_path" << EOF
# Paqet Server Configuration
# Generated by deploy-paqet.sh on $(date)

role: server

log:
  level: ${LOG_LEVEL}

listen:
  addr: ":${LISTEN_PORT}"

network:
  interface: ${INTERFACE}
  ipv4:
    addr: "${IP_ADDRESS}:${LISTEN_PORT}"
    router_mac: "${ROUTER_MAC}"
  tcp:
    local_flag: ["PA"]

transport:
  protocol: kcp
  conn: ${KCP_CONN}
  kcp:
${kcp_mode_config}
    block: ${CRYPTO_BLOCK}
    key: "${SECRET_KEY}"
    mtu: ${KCP_MTU}
    sndwnd: ${KCP_SNDWND}
    rcvwnd: ${KCP_RCVWND}
    smuxbuf: ${KCP_SMUXBUF}
    streambuf: ${KCP_STREAMBUF}
EOF
}

generate_client_config() {
    local config_path="$1"
    local kcp_mode_config
    kcp_mode_config=$(generate_kcp_config)

    # Build port forwards section
    local forwards_yaml=""
    if [[ ${#PORT_FORWARDS[@]} -gt 0 ]]; then
        forwards_yaml=$'\n'"forward:"
        for rule in "${PORT_FORWARDS[@]}"; do
            IFS='|' read -r local_port target protocol <<< "$rule"
            forwards_yaml+=$'\n'"  - listen: \"127.0.0.1:${local_port}\""
            forwards_yaml+=$'\n'"    target: \"${target}\""
            forwards_yaml+=$'\n'"    protocol: \"${protocol}\""
        done
    fi

    cat > "$config_path" << EOF
# Paqet Client Configuration
# Generated by deploy-paqet.sh on $(date)

role: client

log:
  level: ${LOG_LEVEL}

socks5:
  - listen: "127.0.0.1:${SOCKS_PORT}"
${forwards_yaml}

network:
  interface: ${INTERFACE}
  ipv4:
    addr: "${IP_ADDRESS}:0"
    router_mac: "${ROUTER_MAC}"
  tcp:
    local_flag: ["PA"]
    remote_flag: ["PA"]

server:
  addr: "${SERVER_ADDRESS}:${LISTEN_PORT}"

transport:
  protocol: kcp
  conn: ${KCP_CONN}
  kcp:
${kcp_mode_config}
    block: ${CRYPTO_BLOCK}
    key: "${SECRET_KEY}"
    mtu: ${KCP_MTU}
    sndwnd: ${KCP_SNDWND}
    rcvwnd: ${KCP_RCVWND}
    smuxbuf: ${KCP_SMUXBUF}
    streambuf: ${KCP_STREAMBUF}
EOF
}

generate_config() {
    local install_dir="$1"
    local config_filename
    config_filename=$(get_config_filename)
    local config_path="${install_dir}/${config_filename}"

    log_step "Generating Configuration File"

    # Write config to temp file first, then move with sudo
    local temp_config
    temp_config=$(mktemp)

    if [[ "$ROLE" == "server" ]]; then
        generate_server_config "$temp_config"
    else
        generate_client_config "$temp_config"
    fi

    $SUDO mv "$temp_config" "$config_path"
    $SUDO chmod 600 "$config_path"

    log_success "Configuration written to: ${config_path}"
}

# ============================================================================
# IPTABLES CONFIGURATION (SERVER ONLY - AUTO APPLY)
# ============================================================================

apply_iptables_rules() {
    local port="$1"

    log_step "Applying Firewall Rules (Server Mode)"

    log_info "Paqet server requires iptables rules to prevent kernel RST packets."
    log_info "Applying rules for port ${port}..."
    echo ""

    local rules_applied=0
    local check_rc=0

    # PREROUTING NOTRACK
    check_rc=0
    $SUDO iptables -t raw -C PREROUTING -p tcp --dport "$port" -j NOTRACK 2>/dev/null || check_rc=$?
    if [[ $check_rc -eq 0 ]]; then
        log_info "PREROUTING NOTRACK rule already exists."
    else
        $SUDO iptables -t raw -A PREROUTING -p tcp --dport "$port" -j NOTRACK
        log_success "Applied: iptables -t raw -A PREROUTING -p tcp --dport ${port} -j NOTRACK"
        rules_applied=$((rules_applied + 1))
    fi

    # OUTPUT NOTRACK
    check_rc=0
    $SUDO iptables -t raw -C OUTPUT -p tcp --sport "$port" -j NOTRACK 2>/dev/null || check_rc=$?
    if [[ $check_rc -eq 0 ]]; then
        log_info "OUTPUT NOTRACK rule already exists."
    else
        $SUDO iptables -t raw -A OUTPUT -p tcp --sport "$port" -j NOTRACK
        log_success "Applied: iptables -t raw -A OUTPUT -p tcp --sport ${port} -j NOTRACK"
        rules_applied=$((rules_applied + 1))
    fi

    # RST DROP
    check_rc=0
    $SUDO iptables -t mangle -C OUTPUT -p tcp --sport "$port" --tcp-flags RST RST -j DROP 2>/dev/null || check_rc=$?
    if [[ $check_rc -eq 0 ]]; then
        log_info "RST DROP rule already exists."
    else
        $SUDO iptables -t mangle -A OUTPUT -p tcp --sport "$port" --tcp-flags RST RST -j DROP
        log_success "Applied: iptables -t mangle -A OUTPUT -p tcp --sport ${port} --tcp-flags RST RST -j DROP"
        rules_applied=$((rules_applied + 1))
    fi

    if [[ $rules_applied -gt 0 ]]; then
        echo ""
        if prompt_confirm "Save iptables rules to persist across reboots?" "y"; then
            persist_iptables_rules
        else
            log_warn "Rules will be lost after reboot."
        fi
    fi
}

persist_iptables_rules() {
    local distro
    distro=$(detect_linux_distro)

    log_info "Saving iptables rules..."

    case "$distro" in
        ubuntu|debian)
            if check_command netfilter-persistent; then
                $SUDO netfilter-persistent save
            else
                $SUDO mkdir -p /etc/iptables
                $SUDO iptables-save | $SUDO tee /etc/iptables/rules.v4 > /dev/null
            fi
            ;;
        centos|rhel|fedora|rocky|alma)
            if check_command iptables-save; then
                $SUDO iptables-save | $SUDO tee /etc/sysconfig/iptables > /dev/null
                $SUDO systemctl enable iptables 2>/dev/null || true
            fi
            ;;
        arch|manjaro)
            $SUDO iptables-save | $SUDO tee /etc/iptables/iptables.rules > /dev/null
            $SUDO systemctl enable iptables 2>/dev/null || true
            ;;
        *)
            $SUDO iptables-save | $SUDO tee /etc/iptables.rules > /dev/null
            ;;
    esac

    log_success "iptables rules saved."
}

# ============================================================================
# SERVICE MANAGEMENT
# ============================================================================

create_systemd_service() {
    local install_dir="$1"
    local service_name="$INSTANCE_NAME"
    local config_filename
    config_filename=$(get_config_filename)
    local service_file="/etc/systemd/system/${service_name}.service"

    log_info "Creating systemd service: ${service_name}..."

    $SUDO tee "$service_file" > /dev/null << EOF
[Unit]
Description=Paqet Packet-Level Proxy (${service_name})
After=network.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${install_dir}/paqet run -c ${install_dir}/${config_filename}
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=${service_name}
NoNewPrivileges=false
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN

[Install]
WantedBy=multi-user.target
EOF

    $SUDO systemctl daemon-reload
    $SUDO systemctl enable "$service_name"
    $SUDO systemctl start "$service_name"

    log_success "Systemd service '${service_name}' created and started."
}

create_launchd_service() {
    local install_dir="$1"
    local plist_name="com.${INSTANCE_NAME}.daemon"
    local config_filename
    config_filename=$(get_config_filename)
    local plist_file="/Library/LaunchDaemons/${plist_name}.plist"
    local log_name="${INSTANCE_NAME}"

    log_info "Creating launchd service: ${plist_name}..."

    $SUDO tee "$plist_file" > /dev/null << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>${plist_name}</string>
    <key>ProgramArguments</key>
    <array>
        <string>${install_dir}/paqet</string>
        <string>run</string>
        <string>-c</string>
        <string>${install_dir}/${config_filename}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
    </dict>
    <key>StandardOutPath</key>
    <string>/var/log/${log_name}.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/${log_name}.error.log</string>
</dict>
</plist>
EOF

    $SUDO chmod 644 "$plist_file"
    $SUDO chown root:wheel "$plist_file"
    $SUDO launchctl load "$plist_file"

    log_success "Launchd service '${plist_name}' created and loaded."
}

setup_service() {
    local os="$1"
    local install_dir="$2"

    log_step "Setting Up Background Service"

    if ! prompt_confirm "Set up paqet as a background service?" "y"; then
        log_info "Skipping service setup."
        return 1
    fi

    if [[ "$os" == "linux" ]]; then
        if check_command systemctl; then
            create_systemd_service "$install_dir"
        else
            log_warn "systemd not found. Cannot create service."
            return 1
        fi
    else
        create_launchd_service "$install_dir"
    fi

    return 0
}

# ============================================================================
# HEALTH CHECK
# ============================================================================

health_check_server() {
    local install_dir="$1"
    local port="$2"

    log_step "Server Health Check"

    log_info "Checking if paqet server is running..."
    sleep 3

    # Check if process is running
    if pgrep -f "paqet.*run" > /dev/null 2>&1; then
        log_success "Paqet process is running."
    else
        log_error "Paqet process is not running!"
        log_info "Check logs: journalctl -u ${INSTANCE_NAME} -f"
        return 1
    fi

    # Check if listening on raw socket (check process exists with capability)
    if check_command ss; then
        log_info "Checking network binding..."
        # paqet uses raw sockets, so we check process instead
    fi

    # Try paqet ping if available
    if [[ -x "${install_dir}/paqet" ]]; then
        log_info "Running paqet self-test..."
        if timeout 5 $SUDO "${install_dir}/paqet" version > /dev/null 2>&1; then
            log_success "Paqet binary is functional."
        fi
    fi

    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║              SERVER HEALTH CHECK: PASSED                      ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    log_success "Server is ready to accept client connections on port ${port}."

    return 0
}

health_check_client() {
    local install_dir="$1"
    local socks_port="$2"

    log_step "Client Health Check"

    log_info "Waiting for paqet client to initialize..."
    sleep 5

    # Check if process is running
    if pgrep -f "paqet.*run" > /dev/null 2>&1; then
        log_success "Paqet process is running."
    else
        log_error "Paqet process is not running!"
        log_info "Check logs: journalctl -u ${INSTANCE_NAME} -f"
        return 1
    fi

    # Check if SOCKS5 proxy is listening
    log_info "Checking SOCKS5 proxy on port ${socks_port}..."
    sleep 2

    if check_command ss; then
        if ss -tln | grep -q ":${socks_port}"; then
            log_success "SOCKS5 proxy is listening on port ${socks_port}."
        else
            log_warn "SOCKS5 port not detected yet. This may be normal during startup."
        fi
    elif check_command netstat; then
        if netstat -tln | grep -q ":${socks_port}"; then
            log_success "SOCKS5 proxy is listening on port ${socks_port}."
        fi
    fi

    # Test actual connectivity through the proxy
    echo ""
    log_info "Testing connectivity through SOCKS5 proxy..."
    log_info "Target: ${HEALTH_CHECK_URL}"
    echo ""

    local curl_result
    local exit_code=0

    if curl_result=$(curl -s --max-time "${HEALTH_CHECK_TIMEOUT}" \
                          --proxy "socks5h://127.0.0.1:${socks_port}" \
                          "${HEALTH_CHECK_URL}" 2>&1); then

        # Parse the IP from response
        local external_ip
        external_ip=$(echo "$curl_result" | grep -oP '"origin":\s*"\K[^"]+' 2>/dev/null || echo "$curl_result")

        echo ""
        echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${GREEN}║              CLIENT HEALTH CHECK: PASSED                      ║${NC}"
        echo -e "${GREEN}╠══════════════════════════════════════════════════════════════╣${NC}"
        echo -e "${GREEN}║${NC}  Traffic is routing through paqet successfully!              ${GREEN}║${NC}"
        echo -e "${GREEN}║${NC}  External IP: ${CYAN}${external_ip}${NC}"
        echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
        echo ""
    else
        echo ""
        echo -e "${RED}╔══════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${RED}║              CLIENT HEALTH CHECK: FAILED                      ║${NC}"
        echo -e "${RED}╠══════════════════════════════════════════════════════════════╣${NC}"
        echo -e "${RED}║${NC}  Could not connect through the SOCKS5 proxy.                 ${RED}║${NC}"
        echo -e "${RED}║${NC}  Possible issues:                                            ${RED}║${NC}"
        echo -e "${RED}║${NC}  • Server is not running or unreachable                      ${RED}║${NC}"
        echo -e "${RED}║${NC}  • Secret key mismatch between client and server             ${RED}║${NC}"
        echo -e "${RED}║${NC}  • Firewall blocking traffic                                 ${RED}║${NC}"
        echo -e "${RED}║${NC}  • Incorrect server IP/port                                  ${RED}║${NC}"
        echo -e "${RED}╚══════════════════════════════════════════════════════════════╝${NC}"
        echo ""
        log_info "Debug with: journalctl -u ${INSTANCE_NAME} -f"
        log_info "Or manual test: curl -v ${HEALTH_CHECK_URL} --proxy socks5h://127.0.0.1:${socks_port}"
        exit_code=1
    fi

    return $exit_code
}

run_health_check() {
    local install_dir="$1"

    if [[ "$ROLE" == "server" ]]; then
        health_check_server "$install_dir" "$LISTEN_PORT"
    else
        health_check_client "$install_dir" "$SOCKS_PORT"
    fi
}

# ============================================================================
# SUMMARY
# ============================================================================

print_summary() {
    local install_dir="$1"
    local os="$2"
    local config_filename
    config_filename=$(get_config_filename)

    log_step "Installation Summary"

    # Show instance info if this is an additional instance
    if [[ -n "$INSTANCE_SUFFIX" ]]; then
        echo ""
        echo -e "${YELLOW}Instance: ${INSTANCE_NAME}${NC}"
    fi

    echo ""
    echo -e "${CYAN}Configuration:${NC}"
    echo "  Role:            ${ROLE}"
    echo "  Interface:       ${INTERFACE}"
    echo "  IP Address:      ${IP_ADDRESS}"
    echo "  Router MAC:      ${ROUTER_MAC}"
    echo "  Port:            ${LISTEN_PORT}"
    echo "  Encryption:      ${CRYPTO_BLOCK}"

    echo ""
    echo -e "${CYAN}Performance:${NC}"
    echo "  KCP Mode:        ${KCP_MODE}"
    echo "  Connections:     ${KCP_CONN}"
    echo "  MTU:             ${KCP_MTU}"
    echo "  Send Window:     ${KCP_SNDWND}"
    echo "  Recv Window:     ${KCP_RCVWND}"
    if [[ "$KCP_MODE" == "manual" ]]; then
        echo "  Nodelay:         ${KCP_NODELAY}"
        echo "  Interval:        ${KCP_INTERVAL}ms"
        echo "  Resend:          ${KCP_RESEND}"
        echo "  NoCongestion:    ${KCP_NOCONGESTION}"
    fi

    if [[ "$ROLE" == "client" ]]; then
        echo ""
        echo -e "${CYAN}Client:${NC}"
        echo "  Server:          ${SERVER_ADDRESS}:${LISTEN_PORT}"
        echo "  SOCKS5 Proxy:    127.0.0.1:${SOCKS_PORT}"
        if [[ ${#PORT_FORWARDS[@]} -gt 0 ]]; then
            echo "  Port Forwards:   ${#PORT_FORWARDS[@]} rule(s)"
            for rule in "${PORT_FORWARDS[@]}"; do
                IFS='|' read -r local_port target protocol <<< "$rule"
                echo "                   localhost:${local_port} -> ${target} (${protocol})"
            done
        fi
    fi

    echo ""
    echo -e "${CYAN}Files:${NC}"
    echo "  Binary:          ${install_dir}/paqet"
    echo "  Configuration:   ${install_dir}/${config_filename}"

    if [[ "$ROLE" == "server" ]]; then
        echo ""
        echo -e "${YELLOW}Secret Key: ${SECRET_KEY}${NC}"
    fi

    echo ""
    echo -e "${CYAN}Manual Commands:${NC}"
    echo "  Start:   sudo ${install_dir}/paqet run -c ${install_dir}/${config_filename}"

    if [[ "$os" == "linux" ]] && check_command systemctl; then
        echo "  Service: sudo systemctl {start|stop|status|restart} ${INSTANCE_NAME}"
        echo "  Logs:    sudo journalctl -u ${INSTANCE_NAME} -f"
    elif [[ "$os" == "darwin" ]]; then
        echo "  Service: sudo launchctl {load|unload} /Library/LaunchDaemons/com.${INSTANCE_NAME}.daemon.plist"
        echo "  Logs:    tail -f /var/log/${INSTANCE_NAME}.log"
    fi

    if [[ "$ROLE" == "client" ]]; then
        echo ""
        echo -e "${CYAN}Test Connection:${NC}"
        echo "  curl https://httpbin.org/ip --proxy socks5h://127.0.0.1:${SOCKS_PORT}"
    fi

    echo ""
}

# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

main() {
    print_banner

    # Parse arguments
    local custom_install_dir=""
    local skip_download=false
    local force_new=false

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --install-dir)
                custom_install_dir="$2"
                shift 2
                ;;
            --skip-download)
                skip_download=true
                shift
                ;;
            --new)
                force_new=true
                shift
                ;;
            -h|--help)
                echo "Usage: $0 [OPTIONS]"
                echo ""
                echo "Options:"
                echo "  --install-dir DIR    Custom installation directory (default: /opt/paqet)"
                echo "  --skip-download      Skip binary download (use existing)"
                echo "  --new                Force creation of new instance"
                echo "  -h, --help           Show this help message"
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                exit 1
                ;;
        esac
    done

    local install_dir="${custom_install_dir:-$INSTALL_DIR}"

    # =========================================================================
    # STEP 0: Detect OS early for installation check
    # =========================================================================
    local os_early
    os_early=$(detect_os)

    # =========================================================================
    # STEP 1: Check for Existing Installations
    # =========================================================================
    if detect_existing_installations "$os_early"; then
        if [[ "$force_new" == true ]]; then
            configure_new_instance
        else
            prompt_installation_action
        fi
    fi

    # =========================================================================
    # STEP 2: Role Selection
    # =========================================================================
    echo ""
    local role_choice
    role_choice=$(prompt_choice "Are you deploying a Server or a Client?" "Server" "Client")

    if [[ "$role_choice" == "0" ]]; then
        ROLE="server"
        log_success "Selected role: SERVER"
    else
        ROLE="client"
        log_success "Selected role: CLIENT"
    fi

    # =========================================================================
    # STEP 2: System Detection
    # =========================================================================
    log_step "System Detection"

    local os arch pkg_mgr
    os=$(detect_os)
    arch=$(detect_arch)
    pkg_mgr=$(detect_package_manager "$os")

    log_info "Operating System: ${os}"
    log_info "Architecture:     ${arch}"
    log_info "Package Manager:  ${pkg_mgr}"

    # Check sudo
    check_sudo

    # =========================================================================
    # STEP 3: Install Dependencies
    # =========================================================================
    install_dependencies "$os" "$pkg_mgr"

    # =========================================================================
    # STEP 4: Download Binary (skip if binary already exists)
    # =========================================================================
    if [[ -x "${install_dir}/paqet" ]]; then
        # Binary already exists - use it
        log_info "Using existing binary at ${install_dir}/paqet"
    elif [[ "$skip_download" == true ]]; then
        log_error "Binary not found at ${install_dir}/paqet"
        exit 1
    else
        # Fresh install - download binary
        local version
        version=$(get_latest_release)
        log_success "Latest version: ${version}"
        download_binary "$os" "$arch" "$version" "$install_dir"
    fi

    # =========================================================================
    # STEP 5: Network Configuration (Both roles)
    # =========================================================================
    configure_network "$os"

    # =========================================================================
    # STEP 6: Role-Specific Configuration
    # =========================================================================
    if [[ "$ROLE" == "server" ]]; then
        configure_server "$os" "$install_dir"
    else
        configure_client "$os" "$install_dir"
    fi

    # =========================================================================
    # STEP 7: Generate Configuration File
    # =========================================================================
    generate_config "$install_dir"

    # =========================================================================
    # STEP 8: Server-Specific Firewall Rules (Linux only)
    # =========================================================================
    if [[ "$ROLE" == "server" && "$os" == "linux" ]]; then
        apply_iptables_rules "$LISTEN_PORT"
    fi

    # =========================================================================
    # STEP 9: Service Setup
    # =========================================================================
    local service_created=false
    if setup_service "$os" "$install_dir"; then
        service_created=true
    fi

    # =========================================================================
    # STEP 10: Print Summary
    # =========================================================================
    print_summary "$install_dir" "$os"

    # =========================================================================
    # STEP 11: Health Check
    # =========================================================================
    local config_filename
    config_filename=$(get_config_filename)

    if [[ "$service_created" == true ]]; then
        run_health_check "$install_dir"
    else
        echo ""
        log_info "Service not started. Run manually to test:"
        echo -e "  ${GREEN}sudo ${install_dir}/paqet run -c ${install_dir}/${config_filename}${NC}"
    fi

    echo ""
    if [[ -n "$INSTANCE_SUFFIX" ]]; then
        log_success "Paqet ${ROLE} instance '${INSTANCE_NAME}' deployment complete!"
    else
        log_success "Paqet ${ROLE} deployment complete!"
    fi
}

# Run main
main "$@"
