#!/usr/bin/env bash
set -Eeuo pipefail
source "$(dirname "$0")/common.sh"
require_root
: "${NEW_SSH_PORT:?}"
: "${FIREWALL_ALLOWED_SERVICES:=}" "${FIREWALL_ALLOWED_PORTS_B64:=}" "${FIREWALL_IPV6_MODE:=auto}"
[[ "$FIREWALL_IPV6_MODE" == auto || "$FIREWALL_IPV6_MODE" == enabled || "$FIREWALL_IPV6_MODE" == disabled ]] \
  || fail FIREWALL_POLICY_INVALID "FIREWALL_IPV6_MODE 无效"
command -v ufw >/dev/null || { apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y ufw; }

# VPS Secure Init: deny unsolicited inbound traffic and allow outbound traffic.
ufw default deny incoming
ufw default allow outgoing

if [[ "$FIREWALL_IPV6_MODE" != auto ]]; then
  ufw_defaults=/etc/default/ufw
  [[ -f "$ufw_defaults" ]] || fail UFW_IPV6_CONFIG_MISSING "缺少 /etc/default/ufw"
  ipv6_backup="${ufw_defaults}.vps-secure-init.bak"
  cp -a "$ufw_defaults" "$ipv6_backup"
  restore_ipv6() { cp -a "$ipv6_backup" "$ufw_defaults" 2>/dev/null || true; rm -f "$ipv6_backup"; }
  trap restore_ipv6 ERR
  ipv6_value=yes
  [[ "$FIREWALL_IPV6_MODE" == disabled ]] && ipv6_value=no
  if grep -q '^IPV6=' "$ufw_defaults"; then
    sed -i -E "s/^IPV6=.*/IPV6=${ipv6_value}/" "$ufw_defaults"
  else
    printf 'IPV6=%s\n' "$ipv6_value" >> "$ufw_defaults"
  fi
fi

# Transition phase: the controller deliberately opens several short-lived
# SSH/SCP sessions in quick succession (mkdir + 3 uploads + execution +
# verification). `ufw limit` would rate-limit the controller itself before
# fail2ban/finalize can complete. Keep both rescue and managed SSH ports as
# ordinary ALLOW rules until fail2ban has been configured successfully.
# Remove legacy LIMIT rules first so rerunning 0.1.3 can repair a host left by
# 0.1.2 in FIREWALL_VERIFIED state.
ufw delete limit "${NEW_SSH_PORT}/tcp" >/dev/null 2>&1 || true
ufw delete limit 22/tcp >/dev/null 2>&1 || true
ufw allow "${NEW_SSH_PORT}/tcp" comment 'VPS Secure Init: managed SSH access'
ufw allow 22/tcp comment 'VPS Secure Init: temporary rescue SSH access'

IFS=',' read -r -a services <<< "$FIREWALL_ALLOWED_SERVICES"
for service in "${services[@]}"; do
  [[ -z "$service" ]] && continue
  case "$service" in
    http) ufw allow 80/tcp comment 'VPS Secure Init: HTTP service' ;;
    https) ufw allow 443/tcp comment 'VPS Secure Init: HTTPS service' ;;
    *) fail FIREWALL_POLICY_INVALID "不支持的服务规则: $service" ;;
  esac
done

if [[ -n "$FIREWALL_ALLOWED_PORTS_B64" ]]; then
  command -v base64 >/dev/null 2>&1 || fail FIREWALL_RULE_DECODE_FAILED "系统缺少 base64 命令"
  rules_file=$(mktemp)
  if ! printf '%s' "$FIREWALL_ALLOWED_PORTS_B64" | base64 -d > "$rules_file"; then
    rm -f "$rules_file"
    fail FIREWALL_RULE_DECODE_FAILED "无法解码自定义防火墙规则"
  fi
  while IFS=$'\t' read -r rule_port rule_protocol rule_source rule_comment; do
    [[ -n "$rule_port" ]] || continue
    [[ "$rule_port" =~ ^[1-9][0-9]*(:[1-9][0-9]*)?$ ]] || fail FIREWALL_POLICY_INVALID "自定义端口格式无效"
    [[ "$rule_protocol" == tcp || "$rule_protocol" == udp ]] || fail FIREWALL_POLICY_INVALID "自定义协议无效"
    if [[ "$rule_source" == any ]]; then
      if [[ -n "$rule_comment" ]]; then
        ufw allow "${rule_port}/${rule_protocol}" comment "$rule_comment"
      else
        ufw allow "${rule_port}/${rule_protocol}"
      fi
    elif [[ -n "$rule_comment" ]]; then
      ufw allow from "$rule_source" to any port "$rule_port" proto "$rule_protocol" comment "$rule_comment"
    else
      ufw allow from "$rule_source" to any port "$rule_port" proto "$rule_protocol"
    fi
  done < "$rules_file"
  rm -f "$rules_file"
fi
ufw --force enable

ufw status | awk -v p="${NEW_SSH_PORT}/tcp" '$1 == p && $2 == "ALLOW" {ok=1} END {exit ok ? 0 : 1}' \
  || fail UFW_RULE_MISSING "UFW 中缺少新 SSH 端口的过渡期 ALLOW 规则"
ufw status | awk '$1 == "22/tcp" && $2 == "ALLOW" {ok=1} END {exit ok ? 0 : 1}' \
  || fail UFW_RULE_MISSING "UFW 中缺少 22 端口救援 ALLOW 规则"

if [[ -n "${ipv6_backup:-}" ]]; then
  rm -f "$ipv6_backup"
  trap - ERR
fi

emit firewall ok
