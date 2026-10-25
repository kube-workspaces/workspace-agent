#!/usr/bin/env bash
# Install a verified release archive. No network access and no enrollment keys.
set -euo pipefail
if [[ $# != 1 || ! $1 =~ ^[a-z_][a-z0-9_-]*$ || $EUID != 0 ]]; then
  printf 'Usage (root): bash install.sh DESKTOP_USER\n' >&2
  exit 2
fi
desktop_user=$1
if [[ $(id -u "$desktop_user") == 0 ]]; then
  printf 'The desktop worker must run as an ordinary user.\n' >&2
  exit 2
fi
source_dir=$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")
install -D -m 0755 "$source_dir/kw-agent" /usr/local/bin/kw-agent
install -D -m 0755 "$source_dir/workspace-agent-session" /usr/local/libexec/workspace-agent-session
install -D -m 0644 "$source_dir/workspace-agent.desktop" /etc/xdg/autostart/workspace-agent.desktop
install -d -m 0755 /etc/systemd/user /etc/workspace-agent/public
# QGA management staging/replay state is machine-owned, never desktop-writable.
install -d -o root -g root -m 0700 /var/lib/workspace-agent
{
  printf '[Unit]\nConditionUser=%s\n' "$desktop_user"
  printf 'Description=Kube Workspaces GNOME Wayland desktop agent\n'
  printf 'After=graphical-session.target\nPartOf=graphical-session.target\n'
  printf 'ConditionPathExists=/etc/workspace-agent/public/binding.json\n\n'
  printf '[Service]\nType=simple\n'
  printf 'ExecStart=/usr/local/bin/kw-agent serve --data-dir /etc/workspace-agent --bind 0.0.0.0 --port 44787 --capture-video --capture-audio --input --clipboard --resize\n'
  printf 'Restart=on-failure\nRestartSec=5\nTimeoutStopSec=10\n'
  printf 'NoNewPrivileges=true\nUMask=0077\n'
} > /etc/systemd/user/workspace-agent.service
chmod 0644 /etc/systemd/user/workspace-agent.service
# The GNOME autostart entry imports the actual console environment and starts
# this user unit. No root capture daemon, login shell profile or lingering user.
/usr/local/bin/kw-agent --version
