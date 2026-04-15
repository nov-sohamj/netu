#!/usr/bin/env bash
set -euo pipefail

# ─────────────────────────────────────────────
# netu setup script
# Builds, installs, and registers netu as a
# system service on Linux, macOS, and Windows (WSL/Git Bash).
# ─────────────────────────────────────────────

INSTALL_DIR="/usr/local/bin"
SERVICE_NAME="netu"
SERVICE_ADDR="0.0.0.0:8080"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# ── Helpers ──────────────────────────────────

info()  { echo "[INFO]  $*"; }
warn()  { echo "[WARN]  $*"; }
error() { echo "[ERROR] $*" >&2; exit 1; }

detect_os() {
    case "$(uname -s)" in
        Linux*)  echo "linux" ;;
        Darwin*) echo "macos" ;;
        MINGW*|MSYS*|CYGWIN*) echo "windows" ;;
        *) error "Unsupported OS: $(uname -s)" ;;
    esac
}

check_deps() {
    if ! command -v go &>/dev/null; then
        error "Go is not installed. Install it from https://go.dev/dl/"
    fi
    info "Go found: $(go version)"
}

# ── Build ────────────────────────────────────

build() {
    info "Building netu..."
    cd "$SCRIPT_DIR"
    go build -o netu .
    info "Build complete: $SCRIPT_DIR/netu"
}

# ── Install ──────────────────────────────────

install_binary() {
    info "Installing netu to $INSTALL_DIR ..."
    sudo cp "$SCRIPT_DIR/netu" "$INSTALL_DIR/netu"
    sudo chmod +x "$INSTALL_DIR/netu"
    info "Installed: $INSTALL_DIR/netu"
}

# ── Service setup: Linux (systemd) ──────────

setup_linux_service() {
    if ! command -v systemctl &>/dev/null; then
        warn "systemd not found — skipping service registration."
        warn "You can run the service manually: netu serve --addr $SERVICE_ADDR"
        return
    fi

    info "Creating systemd service..."

    sudo tee /etc/systemd/system/netu.service > /dev/null <<UNIT
[Unit]
Description=netu — lightweight network toolkit
After=network.target

[Service]
Type=simple
ExecStart=$INSTALL_DIR/netu serve --addr $SERVICE_ADDR
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
UNIT

    sudo systemctl daemon-reload
    sudo systemctl enable netu.service
    sudo systemctl start netu.service
    info "systemd service enabled and started."
    info "Manage with: sudo systemctl {start|stop|restart|status} netu"
}

# ── Service setup: macOS (launchd) ──────────

setup_macos_service() {
    PLIST_PATH="$HOME/Library/LaunchAgents/com.netu.agent.plist"

    info "Creating launchd agent..."
    mkdir -p "$HOME/Library/LaunchAgents"

    cat > "$PLIST_PATH" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.netu.agent</string>
    <key>ProgramArguments</key>
    <array>
        <string>$INSTALL_DIR/netu</string>
        <string>serve</string>
        <string>--addr</string>
        <string>$SERVICE_ADDR</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/tmp/netu.out.log</string>
    <key>StandardErrorPath</key>
    <string>/tmp/netu.err.log</string>
</dict>
</plist>
PLIST

    launchctl load "$PLIST_PATH"
    info "launchd agent loaded."
    info "Manage with:"
    info "  launchctl load   $PLIST_PATH"
    info "  launchctl unload $PLIST_PATH"
}

# ── Service setup: Windows (NSSM or manual) ──

setup_windows_service() {
    if command -v nssm &>/dev/null; then
        info "Registering Windows service via NSSM..."
        nssm install netu "$INSTALL_DIR/netu.exe" serve --addr "$SERVICE_ADDR"
        nssm start netu
        info "Windows service registered and started."
        info "Manage with: nssm {start|stop|restart|remove} netu"
    else
        warn "NSSM not found — skipping Windows service registration."
        warn "Install NSSM (https://nssm.cc) to register as a service, or run manually:"
        warn "  netu serve --addr $SERVICE_ADDR"
    fi
}

# ── Uninstall ────────────────────────────────

uninstall() {
    OS="$(detect_os)"
    info "Uninstalling netu..."

    case "$OS" in
        linux)
            if command -v systemctl &>/dev/null; then
                sudo systemctl stop netu.service 2>/dev/null || true
                sudo systemctl disable netu.service 2>/dev/null || true
                sudo rm -f /etc/systemd/system/netu.service
                sudo systemctl daemon-reload
                info "systemd service removed."
            fi
            ;;
        macos)
            PLIST_PATH="$HOME/Library/LaunchAgents/com.netu.agent.plist"
            launchctl unload "$PLIST_PATH" 2>/dev/null || true
            rm -f "$PLIST_PATH"
            info "launchd agent removed."
            ;;
        windows)
            if command -v nssm &>/dev/null; then
                nssm stop netu 2>/dev/null || true
                nssm remove netu confirm 2>/dev/null || true
                info "Windows service removed."
            fi
            ;;
    esac

    sudo rm -f "$INSTALL_DIR/netu"
    info "netu uninstalled."
}

# ── Main ─────────────────────────────────────

usage() {
    echo "Usage: $0 [install|uninstall]"
    echo ""
    echo "  install     Build, install binary, and register system service (default)"
    echo "  uninstall   Stop service and remove netu"
}

main() {
    local action="${1:-install}"

    case "$action" in
        install)
            OS="$(detect_os)"
            info "Detected OS: $OS"
            check_deps
            build
            install_binary

            case "$OS" in
                linux)   setup_linux_service ;;
                macos)   setup_macos_service ;;
                windows) setup_windows_service ;;
            esac

            echo ""
            info "Setup complete!"
            info "CLI usage:     netu --help"
            info "Service API:   http://localhost:${SERVICE_ADDR##*:}/health"
            ;;
        uninstall)
            uninstall
            ;;
        -h|--help)
            usage
            ;;
        *)
            usage
            exit 1
            ;;
    esac
}

main "$@"
