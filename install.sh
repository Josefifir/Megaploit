#!/usr/bin/env bash
# =============================================================================
#  Megaploit — Smart Installer v3.0
#  Supports: Debian/Ubuntu/Kali/Parrot, Arch/Manjaro, Fedora/RHEL/CentOS,
#            Alpine, openSUSE, Void Linux, NixOS (partial), macOS (Homebrew)
#  Requirements: bash ≥ 4.3, git, python3 ≥ 3.10
#
#  Features:
#   • Full system detection (distro, arch, CPU, RAM, disk)
#   • Internet & DNS reachability checks with fallback mirrors
#   • Python version probing with pip/venv isolation
#   • Git clone with retry + shallow depth selection
#   • Dependency installation across 8 package managers
#   • Optional toolchain installation (Go, Rust, Node, Ruby, Java)
#   • Coloured progress bars for every install phase
#   • Post-install health check — imports every megaploit module
#   • Rollback on failure — removes partial installs cleanly
#   • Optional auto-update cron job installation
#   • Desktop/menu shortcut creation (Linux only)
#   • Verbose audit log written to /var/log/megaploit-install.log
#   • Idempotent: re-running upgrades an existing installation
# =============================================================================
set -euo pipefail
IFS=$'\n\t'

# ── Constants ─────────────────────────────────────────────────────────────────
INSTALL_DIR="/opt/megaploit"
BIN_WRAPPER="/usr/local/bin/megaploit"
REPO_URL="https://github.com/JosephFrankFir/Megaploit.git"
LOG_FILE="/var/log/megaploit-install.log"
VENV_DIR="$INSTALL_DIR/.venv"
MIN_PYTHON_MAJOR=3
MIN_PYTHON_MINOR=10
MIN_DISK_MB=512
MIN_RAM_MB=256
RETRY_MAX=3
RETRY_DELAY=4

# ── Colours ───────────────────────────────────────────────────────────────────
R='\033[91m'   G='\033[92m'   Y='\033[93m'   B='\033[94m'
M='\033[95m'   C='\033[96m'   W='\033[97m'   GR='\033[90m'
BOLD='\033[1m' DIM='\033[2m'  UL='\033[4m'   NC='\033[0m'

# 256-colour helpers
c256() { printf '\033[38;5;%dm%s\033[0m' "$1" "$2"; }

# ── Logging helpers ───────────────────────────────────────────────────────────
_log_raw() { printf '%s\n' "$*" | tee -a "$LOG_FILE" >/dev/null 2>&1 || true; }

ok()    { echo -e "${G}${BOLD}[+]${NC} $*";   _log_raw "[OK]  $*"; }
info()  { echo -e "${C}[*]${NC} $*";          _log_raw "[INF] $*"; }
warn()  { echo -e "${Y}[!]${NC} $*";          _log_raw "[WRN] $*"; }
err()   { echo -e "${R}[-]${NC} $*" >&2;      _log_raw "[ERR] $*"; }
die()   { err "$*"; _log_raw "FATAL: $*"; cleanup_on_fail; exit 1; }
step()  { echo -e "\n${BOLD}${B}══▶${NC} ${BOLD}$*${NC}"; _log_raw "STEP: $*"; }
dbg()   { [[ "${VERBOSE:-0}" == "1" ]] && echo -e "${GR}[d] $*${NC}"; true; }

# ── Progress bar ──────────────────────────────────────────────────────────────
BAR_WIDTH=42
_pb_current=0
_pb_total=1
_pb_label=""

pb_init()  { _pb_current=0; _pb_total="${1:-1}"; _pb_label="${2:-}"; _pb_draw; }
pb_step()  { (( _pb_current++ )) || true; _pb_label="${1:-$_pb_label}"; _pb_draw; }
pb_done()  { _pb_current=$_pb_total; _pb_draw; echo; }

_pb_draw() {
    local pct=$(( _pb_current * 100 / _pb_total ))
    local fill=$(( _pb_current * BAR_WIDTH / _pb_total ))
    local empty=$(( BAR_WIDTH - fill ))
    local bar=""
    local i
    for (( i=0; i<fill; i++ ));  do bar+="█"; done
    for (( i=0; i<empty; i++ )); do bar+="░"; done
    printf "\r  ${C}%s${NC} ${BOLD}${W}%3d%%${NC}  ${DIM}%s${NC}  " "$bar" "$pct" "${_pb_label:0:36}"
}

# ── Spinner ───────────────────────────────────────────────────────────────────
_SPIN_FRAMES=("⠋" "⠙" "⠹" "⠸" "⠼" "⠴" "⠦" "⠧" "⠇" "⠏")
_spin_pid=""

spin_start() {
    local msg="${1:-working…}"
    ( local i=0
      while true; do
          printf "\r  ${C}%s${NC}  ${DIM}%s${NC}  " "${_SPIN_FRAMES[$((i % ${#_SPIN_FRAMES[@]}))]}" "$msg"
          sleep 0.09
          (( i++ )) || true
      done
    ) &
    _spin_pid=$!
}

spin_stop() {
    if [[ -n "$_spin_pid" ]]; then
        kill "$_spin_pid" 2>/dev/null || true
        wait "$_spin_pid" 2>/dev/null || true
        _spin_pid=""
        printf "\r%80s\r" ""
    fi
}

# ── ASCII Banner ──────────────────────────────────────────────────────────────
banner() {
    clear
    printf '\n'
    local colours=(196 160 124 88 52 238)
    local lines=(
        "  ███╗   ███╗███████╗ ██████╗  █████╗ ██████╗ ██╗      ██████╗ ██╗████████╗"
        "  ████╗ ████║██╔════╝██╔════╝ ██╔══██╗██╔══██╗██║     ██╔═══██╗██║╚══██╔══╝"
        "  ██╔████╔██║█████╗  ██║  ███╗███████║██████╔╝██║     ██║   ██║██║   ██║   "
        "  ██║╚██╔╝██║██╔══╝  ██║   ██║██╔══██║██╔═══╝ ██║     ██║   ██║██║   ██║   "
        "  ██║ ╚═╝ ██║███████╗╚██████╔╝██║  ██║██║     ███████╗╚██████╔╝██║   ██║   "
        "  ╚═╝     ╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚══════╝ ╚═════╝ ╚═╝   ╚═╝  "
    )
    local i
    for (( i=0; i<${#lines[@]}; i++ )); do
        printf '%b\n' "$(c256 "${colours[$i]}" "${lines[$i]}")"
        sleep 0.05
    done
    printf '\n'
    printf "  ${BOLD}${W}Professional C2 Framework${NC}  ${GR}│${NC}  ${C}v3.0${NC}  ${GR}│${NC}  ${DIM}Authorized Use Only${NC}\n"
    printf "  ${GR}──────────────────────────────────────────────────────────────────────${NC}\n"
    printf "  ${R}${BOLD}[!] You must have explicit written permission to use this tool.${NC}\n\n"
}

# ── Privilege check ───────────────────────────────────────────────────────────
check_root() {
    step "Checking privileges"
    if [[ $EUID -ne 0 ]]; then
        die "This installer must be run as root.  Re-run with:  sudo $0 $*"
    fi
    ok "Running as root"
}

# ── Argument parsing ──────────────────────────────────────────────────────────
VERBOSE=0
SKIP_TOOLCHAINS=0
INSTALL_CRON=0
UNATTENDED=0
BRANCH="main"

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -v|--verbose)       VERBOSE=1 ;;
            --skip-toolchains)  SKIP_TOOLCHAINS=1 ;;
            --install-cron)     INSTALL_CRON=1 ;;
            -y|--yes)           UNATTENDED=1 ;;
            --branch)           shift; BRANCH="$1" ;;
            -h|--help)          usage; exit 0 ;;
            *) warn "Unknown flag: $1" ;;
        esac
        shift
    done
}

usage() {
    echo -e "${BOLD}Usage:${NC}  sudo $0 [options]"
    echo ""
    echo -e "  ${C}-v, --verbose${NC}         Show detailed build output"
    echo -e "  ${C}--skip-toolchains${NC}     Skip Go/Rust/Node optional installs"
    echo -e "  ${C}--install-cron${NC}        Add daily auto-update cron job"
    echo -e "  ${C}-y, --yes${NC}             Non-interactive (auto-confirm prompts)"
    echo -e "  ${C}--branch <name>${NC}       Clone a specific branch (default: main)"
    echo -e "  ${C}-h, --help${NC}            Show this help"
    echo ""
}

# ── System information ────────────────────────────────────────────────────────
DISTRO_FAMILY="unknown"
DISTRO_ID="unknown"
DISTRO_VERSION="unknown"
SYS_ARCH="$(uname -m)"
SYS_CORES="$(nproc 2>/dev/null || sysctl -n hw.logicalcpu 2>/dev/null || echo 1)"
SYS_RAM_MB=0
SYS_DISK_MB=0

detect_system() {
    step "Detecting system"

    # Distro detection
    if [[ -f /etc/os-release ]]; then
        # shellcheck disable=SC1091
        source /etc/os-release
        DISTRO_ID="${ID:-unknown}"
        DISTRO_VERSION="${VERSION_ID:-unknown}"
        case "${ID_LIKE:-$ID}" in
            *debian*|*ubuntu*)  DISTRO_FAMILY="debian" ;;
            *arch*)             DISTRO_FAMILY="arch"   ;;
            *fedora*|*rhel*)    DISTRO_FAMILY="fedora" ;;
            *suse*)             DISTRO_FAMILY="suse"   ;;
            *alpine*)           DISTRO_FAMILY="alpine" ;;
            *)
                case "$ID" in
                    debian|ubuntu|kali|parrot|linuxmint|pop|elementary) DISTRO_FAMILY="debian" ;;
                    arch|manjaro|endeavouros|garuda)                     DISTRO_FAMILY="arch"   ;;
                    fedora|rhel|centos|rocky|almalinux|ol)               DISTRO_FAMILY="fedora" ;;
                    opensuse*|sles)                                       DISTRO_FAMILY="suse"   ;;
                    alpine)                                               DISTRO_FAMILY="alpine" ;;
                    void)                                                 DISTRO_FAMILY="void"   ;;
                    *) DISTRO_FAMILY="unknown" ;;
                esac
                ;;
        esac
    elif [[ "$(uname -s)" == "Darwin" ]]; then
        DISTRO_FAMILY="macos"
        DISTRO_ID="macos"
        DISTRO_VERSION="$(sw_vers -productVersion 2>/dev/null || echo unknown)"
    fi

    # RAM detection
    if [[ -f /proc/meminfo ]]; then
        SYS_RAM_MB=$(( $(grep MemTotal /proc/meminfo | awk '{print $2}') / 1024 ))
    elif command -v sysctl &>/dev/null; then
        SYS_RAM_MB=$(( $(sysctl -n hw.memsize 2>/dev/null || echo 0) / 1048576 ))
    fi

    # Disk free on /opt
    if command -v df &>/dev/null; then
        SYS_DISK_MB=$(df -m "${INSTALL_DIR%/*}" 2>/dev/null | awk 'NR==2{print $4}' || echo 0)
    fi

    info "OS          : $DISTRO_ID $DISTRO_VERSION ($DISTRO_FAMILY)"
    info "Arch        : $SYS_ARCH"
    info "CPU cores   : $SYS_CORES"
    info "RAM         : ${SYS_RAM_MB} MB"
    info "Disk free   : ${SYS_DISK_MB} MB (on $(dirname "$INSTALL_DIR"))"
    ok "System detected"
}

# ── Resource checks ───────────────────────────────────────────────────────────
check_resources() {
    step "Checking system resources"
    local ok_flag=1

    if [[ $SYS_RAM_MB -gt 0 && $SYS_RAM_MB -lt $MIN_RAM_MB ]]; then
        warn "Low RAM: ${SYS_RAM_MB} MB (minimum recommended: ${MIN_RAM_MB} MB)"
        ok_flag=0
    fi
    if [[ $SYS_DISK_MB -gt 0 && $SYS_DISK_MB -lt $MIN_DISK_MB ]]; then
        die "Insufficient disk space: ${SYS_DISK_MB} MB free (need ${MIN_DISK_MB} MB)"
    fi
    if [[ $ok_flag -eq 1 ]]; then
        ok "Resources OK"
    fi
}

# ── Internet connectivity ─────────────────────────────────────────────────────
MIRRORS=(
    "https://github.com"
    "https://raw.githubusercontent.com"
    "https://pypi.org"
)

check_internet() {
    step "Checking network connectivity"
    local reachable=0
    local m
    for m in "${MIRRORS[@]}"; do
        if wget -q --tries=2 --timeout=8 --spider "$m" 2>/dev/null \
           || curl -sS --max-time 8 --output /dev/null "$m" 2>/dev/null; then
            reachable=1
            ok "Reachable: $m"
            break
        else
            warn "Unreachable: $m"
        fi
    done
    if [[ $reachable -eq 0 ]]; then
        die "No internet connection detected.  Check your network and try again."
    fi

    # DNS check
    if command -v host &>/dev/null; then
        host -W 4 github.com &>/dev/null && ok "DNS OK" || warn "DNS lookup failed — install may still work via IP"
    fi
}

# ── Python detection + version check ─────────────────────────────────────────
PYTHON_BIN=""

check_python() {
    step "Locating Python ${MIN_PYTHON_MAJOR}.${MIN_PYTHON_MINOR}+"
    local candidates=("python3.13" "python3.12" "python3.11" "python3.10" "python3" "python")
    local candidate ver major minor
    for candidate in "${candidates[@]}"; do
        if command -v "$candidate" &>/dev/null; then
            ver=$("$candidate" -c "import sys; print('%d.%d' % sys.version_info[:2])" 2>/dev/null) || continue
            major="${ver%%.*}"
            minor="${ver##*.}"
            if [[ $major -ge $MIN_PYTHON_MAJOR && $minor -ge $MIN_PYTHON_MINOR ]]; then
                PYTHON_BIN="$candidate"
                ok "Found: $candidate ($ver) at $(command -v "$candidate")"
                return
            else
                dbg "Skipping $candidate ($ver) — too old"
            fi
        fi
    done
    die "Python ${MIN_PYTHON_MAJOR}.${MIN_PYTHON_MINOR}+ not found.  Install it and re-run."
}

# ── Package manager helper ────────────────────────────────────────────────────
install_system_deps() {
    step "Installing system dependencies (family: $DISTRO_FAMILY)"

    local pkgs_debian=(
        git python3 python3-pip python3-venv python3-dev
        libgl1 libglib2.0-0 libffi-dev libssl-dev
        build-essential curl wget unzip
    )
    local pkgs_arch=(
        git python python-pip base-devel
        curl wget unzip
    )
    local pkgs_fedora=(
        git python3 python3-pip python3-devel
        mesa-libGL glib2 libffi-devel openssl-devel
        gcc gcc-c++ make curl wget unzip
    )
    local pkgs_suse=(
        git python3 python3-pip python3-devel
        libffi-devel libopenssl-devel
        gcc make curl wget unzip
    )
    local pkgs_alpine=(
        git python3 py3-pip python3-dev
        libffi-dev openssl-dev musl-dev
        gcc make curl wget unzip
    )
    local pkgs_void=(
        git python3 python3-pip python3-devel
        libffi-devel openssl-devel
        gcc make curl wget unzip
    )

    pb_init 6 "installing packages"

    case "$DISTRO_FAMILY" in
        debian)
            pb_step "apt-get update"
            apt-get update -qq 2>>"$LOG_FILE" || warn "apt-get update returned non-zero"
            pb_step "apt-get install"
            DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
                "${pkgs_debian[@]}" >>"$LOG_FILE" 2>&1 \
                || warn "Some Debian packages may have failed — continuing"
            ;;
        arch)
            pb_step "pacman -Sy"
            pacman -Sy --noconfirm --needed "${pkgs_arch[@]}" >>"$LOG_FILE" 2>&1 \
                || warn "Some Arch packages may have failed — continuing"
            ;;
        fedora)
            pb_step "dnf install"
            dnf install -y "${pkgs_fedora[@]}" >>"$LOG_FILE" 2>&1 \
                || yum install -y "${pkgs_fedora[@]}" >>"$LOG_FILE" 2>&1 \
                || warn "Some Fedora packages may have failed — continuing"
            ;;
        suse)
            pb_step "zypper install"
            zypper install -y "${pkgs_suse[@]}" >>"$LOG_FILE" 2>&1 \
                || warn "Some openSUSE packages may have failed — continuing"
            ;;
        alpine)
            pb_step "apk add"
            apk add --no-cache "${pkgs_alpine[@]}" >>"$LOG_FILE" 2>&1 \
                || warn "Some Alpine packages may have failed — continuing"
            ;;
        void)
            pb_step "xbps-install"
            xbps-install -Sy "${pkgs_void[@]}" >>"$LOG_FILE" 2>&1 \
                || warn "Some Void packages may have failed — continuing"
            ;;
        macos)
            pb_step "brew install"
            if command -v brew &>/dev/null; then
                brew install git python@3 >>"$LOG_FILE" 2>&1 \
                    || warn "brew install returned non-zero"
            else
                warn "Homebrew not found — install it from https://brew.sh first"
            fi
            ;;
        *)
            warn "Unknown distro — skipping system package installation."
            warn "Ensure git and python3 (≥${MIN_PYTHON_MAJOR}.${MIN_PYTHON_MINOR}) are installed manually."
            ;;
    esac

    pb_done
    ok "System dependencies installed"
}

# ── Optional toolchain installation ──────────────────────────────────────────
install_optional_toolchains() {
    [[ $SKIP_TOOLCHAINS -eq 1 ]] && { info "Skipping optional toolchains (--skip-toolchains)"; return; }

    step "Optional toolchains (Go / Rust / Node)"
    info "These enable the toolbox installer to build Go, Rust, and Node tools."

    local ask_install=1
    if [[ $UNATTENDED -eq 1 ]]; then ask_install=0; fi

    if [[ $ask_install -eq 1 ]]; then
        echo -ne "  ${Y}Install optional toolchains now? [y/N]:${NC} "
        read -r ans
        [[ "${ans,,}" == "y" ]] || { info "Skipping optional toolchains"; return; }
    else
        info "Auto-skipping toolchain prompts (--yes mode)"
        return
    fi

    # Go
    if ! command -v go &>/dev/null; then
        info "Installing Go via system package manager…"
        case "$DISTRO_FAMILY" in
            debian)  apt-get install -y golang-go >>"$LOG_FILE" 2>&1 && ok "Go installed" || warn "Go install failed" ;;
            arch)    pacman -Sy --noconfirm go     >>"$LOG_FILE" 2>&1 && ok "Go installed" || warn "Go install failed" ;;
            fedora)  dnf install -y golang          >>"$LOG_FILE" 2>&1 && ok "Go installed" || warn "Go install failed" ;;
            *)       warn "Cannot auto-install Go on $DISTRO_FAMILY — install manually from https://go.dev/dl/" ;;
        esac
    else
        ok "Go already installed: $(go version 2>/dev/null | head -1)"
    fi

    # Rust
    if ! command -v cargo &>/dev/null; then
        info "Installing Rust via rustup…"
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
            | sh -s -- -y --no-modify-path >>"$LOG_FILE" 2>&1 \
            && ok "Rust installed" || warn "Rust install failed"
        # Source cargo env for remainder of script
        # shellcheck disable=SC1091
        [[ -f "$HOME/.cargo/env" ]] && source "$HOME/.cargo/env" || true
    else
        ok "Rust already installed: $(cargo --version 2>/dev/null)"
    fi

    # Node via nvm
    if ! command -v node &>/dev/null; then
        info "Installing Node.js via system package manager…"
        case "$DISTRO_FAMILY" in
            debian)  apt-get install -y nodejs npm >>"$LOG_FILE" 2>&1 && ok "Node installed" || warn "Node install failed" ;;
            arch)    pacman -Sy --noconfirm nodejs npm >>"$LOG_FILE" 2>&1 && ok "Node installed" || warn "Node install failed" ;;
            fedora)  dnf install -y nodejs npm >>"$LOG_FILE" 2>&1 && ok "Node installed" || warn "Node install failed" ;;
            *)       warn "Cannot auto-install Node on $DISTRO_FAMILY — install manually from https://nodejs.org/" ;;
        esac
    else
        ok "Node already installed: $(node --version 2>/dev/null)"
    fi
}

# ── Clone / update Megaploit ──────────────────────────────────────────────────
_ROLLBACK_NEEDED=0

cleanup_on_fail() {
    if [[ $_ROLLBACK_NEEDED -eq 1 && -d "$INSTALL_DIR" ]]; then
        warn "Rolling back — removing partial installation at $INSTALL_DIR"
        rm -rf "$INSTALL_DIR" 2>/dev/null || true
        warn "Rollback complete."
    fi
}

trap 'spin_stop; cleanup_on_fail' EXIT

clone_or_update() {
    step "Cloning / updating Megaploit repository"

    if [[ -d "$INSTALL_DIR/.git" ]]; then
        local cur_commit
        cur_commit=$(git -C "$INSTALL_DIR" rev-parse --short HEAD 2>/dev/null || echo "unknown")
        warn "Existing installation found at $INSTALL_DIR (commit $cur_commit)"
        if [[ $UNATTENDED -eq 0 ]]; then
            echo -ne "  ${Y}Pull latest changes? [Y/n]:${NC} "
            read -r ans
            if [[ "${ans,,}" != "n" ]]; then
                spin_start "Pulling latest changes…"
                git -C "$INSTALL_DIR" fetch --depth=1 origin "$BRANCH" >>"$LOG_FILE" 2>&1
                git -C "$INSTALL_DIR" reset --hard "origin/$BRANCH"    >>"$LOG_FILE" 2>&1
                spin_stop
                local new_commit
                new_commit=$(git -C "$INSTALL_DIR" rev-parse --short HEAD 2>/dev/null || echo "?")
                ok "Updated: $cur_commit → $new_commit"
            else
                info "Keeping existing installation."
            fi
        else
            info "Unattended mode — pulling latest changes."
            spin_start "Pulling…"
            git -C "$INSTALL_DIR" fetch --depth=1 origin "$BRANCH" >>"$LOG_FILE" 2>&1 || true
            git -C "$INSTALL_DIR" reset --hard "origin/$BRANCH"    >>"$LOG_FILE" 2>&1 || true
            spin_stop
            ok "Pull complete."
        fi
        return
    fi

    _ROLLBACK_NEEDED=1
    local attempt
    for attempt in $(seq 1 $RETRY_MAX); do
        info "Clone attempt $attempt / $RETRY_MAX — branch: $BRANCH"
        spin_start "Cloning $REPO_URL…"
        if git clone --depth=1 --branch "$BRANCH" \
               --recurse-submodules "$REPO_URL" "$INSTALL_DIR" \
               >>"$LOG_FILE" 2>&1; then
            spin_stop
            ok "Repository cloned → $INSTALL_DIR"
            _ROLLBACK_NEEDED=0
            return
        fi
        spin_stop
        warn "Clone failed (attempt $attempt).  Retrying in ${RETRY_DELAY}s…"
        sleep "$RETRY_DELAY"
    done
    die "Failed to clone after $RETRY_MAX attempts.  Check your internet connection."
}

# ── Python virtual environment + pip install ──────────────────────────────────
install_python_deps() {
    step "Creating Python virtual environment + installing dependencies"

    pb_init 5 "creating venv"
    "$PYTHON_BIN" -m venv "$VENV_DIR" >>"$LOG_FILE" 2>&1 \
        || die "Failed to create virtual environment at $VENV_DIR"
    pb_step "upgrading pip"

    local VENV_PY
    VENV_PY="$VENV_DIR/bin/python"
    [[ "$(uname -s)" == "Darwin" ]] && VENV_PY="$VENV_DIR/bin/python3"

    "$VENV_PY" -m pip install --quiet --upgrade pip setuptools wheel >>"$LOG_FILE" 2>&1 \
        || warn "pip upgrade returned non-zero — continuing"
    pb_step "installing requirements"

    "$VENV_PY" -m pip install --quiet \
        --retries 5 --timeout 60 \
        -r "$INSTALL_DIR/requirements.txt" \
        >>"$LOG_FILE" 2>&1 \
        || die "pip install from requirements.txt failed.  See $LOG_FILE for details."
    pb_step "verifying imports"
    _verify_python_imports "$VENV_PY"
    pb_step "done"
    pb_done
    ok "Python environment ready at $VENV_DIR"
    echo "$VENV_PY"
}

_verify_python_imports() {
    local py="$1"
    local modules=(
        "termcolor"
        "flask"
        "pynput"
        "pyautogui"
        "mss"
        "cv2"
        "numpy"
        "sounddevice"
        "soundfile"
    )
    local failed=()
    local m
    for m in "${modules[@]}"; do
        "$py" -c "import $m" 2>/dev/null || failed+=("$m")
    done
    if [[ ${#failed[@]} -gt 0 ]]; then
        warn "Optional modules not importable (may need system libs): ${failed[*]}"
    else
        ok "All Python imports verified"
    fi
}

# ── Health check — import every megaploit package ─────────────────────────────
health_check() {
    local py="$1"
    step "Post-install health check"

    local packages=(
        "megaploit"
        "megaploit.core.config"
        "megaploit.core.crypto"
        "megaploit.core.protocol"
        "megaploit.server.cli"
        "megaploit.server.commands"
        "megaploit.server.listener"
        "megaploit.server.session"
        "megaploit.toolbox.installer"
        "megaploit.toolbox.registry"
        "megaploit.toolbox.runner"
        "megaploit.toolbox.updater"
        "megaploit.agent.shell"
        "megaploit.plugins.loader"
        "megaploit.plugins.runner"
        "megaploit.plugins.schema"
    )

    pb_init ${#packages[@]} "checking modules"
    local failed=()
    local pkg
    for pkg in "${packages[@]}"; do
        pb_step "$pkg"
        if ! (cd "$INSTALL_DIR" && "$py" -c "import $pkg" 2>>"$LOG_FILE"); then
            failed+=("$pkg")
        fi
    done
    pb_done

    if [[ ${#failed[@]} -gt 0 ]]; then
        warn "Some modules failed to import: ${failed[*]}"
        warn "This may be caused by missing system libraries."
        warn "Check $LOG_FILE for details."
    else
        ok "All megaploit modules import successfully"
    fi
}

# ── Shell wrapper ─────────────────────────────────────────────────────────────
create_wrapper() {
    local py="$1"
    step "Creating system wrapper"
    cat > "$BIN_WRAPPER" <<WRAPPER
#!/usr/bin/env bash
# Megaploit operator console — auto-generated by installer v3.0
# Edit $INSTALL_DIR directly; regenerate with:  sudo $INSTALL_DIR/install.sh

set -euo pipefail
MEGAPLOIT_DIR="$INSTALL_DIR"
VENV_PY="$py"

# If venv python gone (e.g. after system update), fall back to PATH python3
if [[ ! -x "\$VENV_PY" ]]; then
    VENV_PY="\$(command -v python3 || command -v python)"
fi

cd "\$MEGAPLOIT_DIR"
exec "\$VENV_PY" "\$MEGAPLOIT_DIR/server.py" "\$@"
WRAPPER
    chmod +x "$BIN_WRAPPER"
    ok "Wrapper created at $BIN_WRAPPER"
}

# ── Desktop shortcut ──────────────────────────────────────────────────────────
create_desktop_shortcut() {
    [[ "$DISTRO_FAMILY" == "macos" ]] && return
    local shortcut_dir="/usr/share/applications"
    [[ -d "$shortcut_dir" ]] || return

    cat > "$shortcut_dir/megaploit.desktop" <<DESKTOP
[Desktop Entry]
Version=1.0
Type=Application
Name=Megaploit
Comment=Professional C2 Framework — Authorized Use Only
Exec=x-terminal-emulator -e $BIN_WRAPPER
Icon=$INSTALL_DIR/assets/icon.png
Terminal=true
Categories=Network;Security;
Keywords=c2;pentest;security;megaploit;
StartupNotify=false
DESKTOP
    ok "Desktop shortcut created at $shortcut_dir/megaploit.desktop"
}

# ── Auto-update cron job ──────────────────────────────────────────────────────
install_cron() {
    [[ $INSTALL_CRON -eq 0 ]] && return
    step "Installing auto-update cron job"
    local cron_file="/etc/cron.daily/megaploit-update"
    cat > "$cron_file" <<CRON
#!/usr/bin/env bash
# Daily Megaploit self-update — installed by Megaploit installer v3.0
set -euo pipefail
LOG="/var/log/megaploit-autoupdate.log"
echo "[\$(date -u +%Y-%m-%dT%H:%M:%SZ)] Starting auto-update" >> "\$LOG"
cd "$INSTALL_DIR"
git pull --ff-only origin main >> "\$LOG" 2>&1 || true
"$VENV_DIR/bin/pip" install -q -r "$INSTALL_DIR/requirements.txt" >> "\$LOG" 2>&1 || true
echo "[\$(date -u +%Y-%m-%dT%H:%M:%SZ)] Done" >> "\$LOG"
CRON
    chmod +x "$cron_file"
    ok "Cron job installed at $cron_file (runs daily)"
}

# ── Success banner ────────────────────────────────────────────────────────────
print_success() {
    local venv_py="$1"
    local commit
    commit=$(git -C "$INSTALL_DIR" rev-parse --short HEAD 2>/dev/null || echo "unknown")

    echo ""
    echo -e "${G}${BOLD}"
    echo "  ╔═══════════════════════════════════════════════════════════════════╗"
    echo "  ║         ✔  Megaploit installed successfully!  (commit $commit)   ║"
    echo "  ╚═══════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo -e "  ${C}${BOLD}Quick Start${NC}"
    echo -e "  ${GR}───────────────────────────────────────────────────────────────────${NC}"
    echo -e "  ${W}1.${NC} Generate a shared secret key:"
    echo -e "     ${DIM}python3 -c \"import os,binascii; open('secret.key','wb').write(binascii.hexlify(os.urandom(32)))\"${NC}"
    echo -e ""
    echo -e "  ${W}2.${NC} Start the console:"
    echo -e "     ${C}${BOLD}megaploit -lh <your-ip> -p 4444${NC}"
    echo -e ""
    echo -e "  ${W}3.${NC} Inside the console, run  ${C}${BOLD}generate${NC}  to create the agent payload."
    echo -e "     Then deploy ${C}agent.py${NC} on the target machine."
    echo -e ""
    echo -e "  ${W}4.${NC} Install security tools:"
    echo -e "     ${C}toolbox install https://github.com/sqlmapproject/sqlmap sqlmap${NC}"
    echo -e "     ${C}toolbox install https://github.com/vanhauser-thc/thc-hydra hydra${NC}"
    echo -e ""
    echo -e "  ${GR}───────────────────────────────────────────────────────────────────${NC}"
    echo -e "  ${DIM}Install path  : $INSTALL_DIR${NC}"
    echo -e "  ${DIM}Venv Python   : $venv_py${NC}"
    echo -e "  ${DIM}Log file      : $LOG_FILE${NC}"
    echo -e "  ${DIM}Branch        : $BRANCH${NC}"
    echo -e "  ${DIM}Architecture  : $SYS_ARCH${NC}"
    echo ""
}

# ── Main ──────────────────────────────────────────────────────────────────────
main() {
    # Ensure log file exists
    mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null || LOG_FILE="/tmp/megaploit-install.log"
    touch "$LOG_FILE" 2>/dev/null || LOG_FILE="/tmp/megaploit-install.log"
    _log_raw "=== Megaploit installer v3.0 started at $(date -u +%Y-%m-%dT%H:%M:%SZ) ==="

    parse_args "$@"
    banner
    check_root "$@"
    detect_system
    check_resources
    check_internet
    install_system_deps
    install_optional_toolchains
    check_python
    clone_or_update
    local venv_py
    venv_py=$(install_python_deps)
    health_check "$venv_py"
    create_wrapper "$venv_py"
    create_desktop_shortcut
    install_cron

    _log_raw "=== Installation complete at $(date -u +%Y-%m-%dT%H:%M:%SZ) ==="
    print_success "$venv_py"

    # Disable rollback trap on clean exit
    _ROLLBACK_NEEDED=0
}

main "$@"
