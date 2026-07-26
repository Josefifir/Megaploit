#!/usr/bin/env bash
# =============================================================================
#  Megaploit installer
#  Supports: Debian/Ubuntu/Kali/Parrot, Arch/Manjaro, Fedora/RHEL/CentOS
#  Requirements: bash ≥ 4, git, python3 ≥ 3.10
# =============================================================================
set -euo pipefail

# ── Colours ──────────────────────────────────────────────────────────────────
R='\e[91m'   G='\e[92m'   Y='\e[93m'   B='\e[94m'
C='\e[96m'   W='\e[97m'   DIM='\e[2m'  BOLD='\e[1m'  NC='\e[0m'

ok()   { echo -e "${G}[+]${NC} $*"; }
info() { echo -e "${C}[*]${NC} $*"; }
warn() { echo -e "${Y}[!]${NC} $*"; }
err()  { echo -e "${R}[-]${NC} $*" >&2; }
die()  { err "$*"; exit 1; }

banner() {
  clear
  echo -e "${R}${BOLD}"
  cat <<'EOF'
  ███╗   ███╗███████╗ ██████╗  █████╗ ██████╗ ██╗      ██████╗ ██╗████████╗
  ████╗ ████║██╔════╝██╔════╝ ██╔══██╗██╔══██╗██║     ██╔═══██╗██║╚══██╔══╝
  ██╔████╔██║█████╗  ██║  ███╗███████║██████╔╝██║     ██║   ██║██║   ██║
  ██║╚██╔╝██║██╔══╝  ██║   ██║██╔══██║██╔═══╝ ██║     ██║   ██║██║   ██║
  ██║ ╚═╝ ██║███████╗╚██████╔╝██║  ██║██║     ███████╗╚██████╔╝██║   ██║
  ╚═╝     ╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚══════╝ ╚═════╝ ╚═╝   ╚═╝
EOF
  echo -e "${NC}"
  echo -e "  ${DIM}Professional C2 Framework · For Authorized Security Research Only${NC}"
  echo -e "  ${DIM}https://github.com/JosephFrankFir/Megaploit${NC}"
  echo ""
  echo -e "  ${R}[!] You must have explicit written permission to use this tool on any system.${NC}"
  echo ""
}

# ── Privilege check ───────────────────────────────────────────────────────────
check_root() {
  if [[ $EUID -ne 0 ]]; then
    die "This installer must be run as root.  Use: sudo ./install.sh"
  fi
}

# ── Internet check ────────────────────────────────────────────────────────────
check_internet() {
  info "Checking internet connectivity…"
  if ! wget -q --tries=3 --timeout=10 --spider https://github.com 2>/dev/null; then
    die "No internet connection detected.  Check your network and try again."
  fi
  ok "Internet OK"
}

# ── Python version check ──────────────────────────────────────────────────────
check_python() {
  local py=""
  for cmd in python3 python; do
    if command -v "$cmd" &>/dev/null; then
      local ver
      ver=$("$cmd" -c "import sys; print('%d.%d' % sys.version_info[:2])" 2>/dev/null)
      local major minor
      major=${ver%%.*}; minor=${ver##*.}
      if [[ $major -ge 3 && $minor -ge 10 ]]; then
        py="$cmd"
        ok "Python $ver found at $(command -v $cmd)"
        break
      fi
    fi
  done
  if [[ -z "$py" ]]; then
    die "Python 3.10+ is required but not found.  Install it and try again."
  fi
  echo "$py"
}

# ── Detect distro family ──────────────────────────────────────────────────────
detect_distro() {
  if command -v apt-get &>/dev/null; then
    echo "debian"
  elif command -v pacman &>/dev/null; then
    echo "arch"
  elif command -v dnf &>/dev/null; then
    echo "fedora"
  elif command -v yum &>/dev/null; then
    echo "rhel"
  else
    echo "unknown"
  fi
}

# ── System package installation ───────────────────────────────────────────────
install_system_deps() {
  local distro="$1"
  info "Installing system dependencies for family: $distro"

  case "$distro" in
    debian)
      apt-get update -qq
      apt-get install -y --no-install-recommends \
        git python3 python3-pip python3-venv \
        libgl1 libglib2.0-0 \
        2>/dev/null
      ;;
    arch)
      pacman -Sy --noconfirm --needed \
        git python python-pip \
        2>/dev/null
      ;;
    fedora)
      dnf install -y \
        git python3 python3-pip \
        mesa-libGL glib2 \
        2>/dev/null
      ;;
    rhel)
      yum install -y \
        git python3 python3-pip \
        2>/dev/null
      ;;
    *)
      warn "Unknown distro — skipping system package installation."
      warn "Make sure git and python3 (≥3.10) are installed manually."
      ;;
  esac
  ok "System dependencies installed"
}

# ── Clone or update Megaploit ─────────────────────────────────────────────────
INSTALL_DIR="/opt/megaploit"
BIN_WRAPPER="/usr/local/bin/megaploit"
REPO_URL="https://github.com/JosephFrankFir/Megaploit.git"

clone_or_update() {
  if [[ -d "$INSTALL_DIR/.git" ]]; then
    warn "Existing installation found at $INSTALL_DIR"
    echo -ne "  ${Y}Replace it? [y/N]:${NC} "
    read -r answer
    [[ "${answer,,}" == "y" ]] || { info "Keeping existing installation."; return; }
    info "Removing old installation…"
    rm -rf "$INSTALL_DIR"
  fi

  info "Cloning Megaploit → $INSTALL_DIR"
  git clone --depth=1 "$REPO_URL" "$INSTALL_DIR"
  ok "Repository cloned"
}

# ── Python dependencies ───────────────────────────────────────────────────────
install_python_deps() {
  local py="$1"
  info "Installing Python dependencies from requirements.txt…"
  "$py" -m pip install --quiet --upgrade pip
  "$py" -m pip install --quiet -r "$INSTALL_DIR/requirements.txt"
  ok "Python dependencies installed"
}

# ── Shell wrapper ─────────────────────────────────────────────────────────────
create_wrapper() {
  local py="$1"
  info "Creating shell wrapper at $BIN_WRAPPER"
  cat > "$BIN_WRAPPER" <<WRAPPER
#!/usr/bin/env bash
# Megaploit operator console wrapper
exec "$py" "$INSTALL_DIR/server.py" "\$@"
WRAPPER
  chmod +x "$BIN_WRAPPER"
  ok "Wrapper created — you can now run:  megaploit -lh <ip> -p <port>"
}

# ── Success banner ────────────────────────────────────────────────────────────
print_success() {
  echo ""
  echo -e "${G}${BOLD}"
  echo "  ╔══════════════════════════════════════════════════════════════╗"
  echo "  ║           ✔  Megaploit installed successfully!              ║"
  echo "  ╚══════════════════════════════════════════════════════════════╝"
  echo -e "${NC}"
  echo -e "  ${C}Usage:${NC}"
  echo -e "    ${BOLD}megaploit -lh <your-ip> -p <port>${NC}"
  echo ""
  echo -e "  ${C}Quick start:${NC}"
  echo -e "    1. Generate a shared secret key:"
  echo -e "       ${DIM}python3 -c \"import os,binascii; open('secret.key','wb').write(binascii.hexlify(os.urandom(32)))\"${NC}"
  echo -e "    2. Start the console:"
  echo -e "       ${BOLD}megaploit -lh 192.168.1.10 -p 4444${NC}"
  echo -e "    3. Inside the console, run  ${BOLD}generate${NC}  to create the agent payload."
  echo ""
}

# ── Main ──────────────────────────────────────────────────────────────────────
main() {
  banner
  check_root
  check_internet

  local distro
  distro=$(detect_distro)
  install_system_deps "$distro"

  local py
  py=$(check_python)

  clone_or_update
  install_python_deps "$py"
  create_wrapper "$py"
  print_success
}

main "$@"
