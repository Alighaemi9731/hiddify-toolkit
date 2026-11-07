# shellcheck shell=bash
# shellcheck disable=SC2034
MOD_ID="cdn-same-ip"
MOD_TITLE="Allow CDN domains pointing to this server"
MOD_DESC="Hiddify 12: accept CDN and Auto CDN domains resolving to the origin IP. DNS and Direct-mode checks remain enabled. Survives Apply Config; guard repairs after panel package replacement."
MOD_GUARD=yes

_csi_target() {
  local -a files=()
  local file
  while IFS= read -r file; do files+=("$file"); done < <(
    find /opt/hiddify-manager -path '*/site-packages/hiddifypanel/panel/admin/DomainAdmin.py' -type f 2>/dev/null
  )
  [ "${#files[@]}" -eq 1 ] || { err "Expected one installed DomainAdmin.py, found ${#files[@]}"; return 1; }
  printf '%s\n' "${files[0]}"
}
_csi_python() {
  local file="$1" base
  base="${file%%/lib/python*}"
  [ -x "$base/bin/python" ] || return 1
  "$base/bin/python" "$HT_ROOT/lib/cdn_same_ip.py" "${2:-check}" "$file"
}
_csi_edit() {
  local action="$1" file result active=0
  file="$(_csi_target)" || return 1
  if [ "$action" = apply ]; then
    case "$(cat /opt/hiddify-manager/VERSION 2>/dev/null)" in 12.*) ;; *) err "This patch supports Hiddify 12 only"; return 1 ;; esac
  fi
  systemctl is-active --quiet hiddify-panel && active=1
  result="$(_csi_python "$file" "$action")" || return 1
  if [ "$result" = changed ] && [ "$active" = 1 ]; then
    systemctl restart hiddify-panel || return 1
    local attempt
    for attempt in {1..15}; do
      if systemctl is-active --quiet hiddify-panel && curl -s --max-time 2 -o /dev/null http://127.0.0.1:9000/; then
        ok "$action completed; panel responds"; return 0
      fi
      sleep 1
    done
    err "Panel did not respond after restart"; return 1
  fi
  ok "$action: $result"
}
mod_apply() { _csi_edit apply; }
mod_verify() { local file; file="$(_csi_target)" && _csi_python "$file" check; }
mod_revert() { _csi_edit revert; }
mod_reassert() {
  # Never restart a healthy panel if its source is already patched.
  mod_verify >/dev/null 2>&1 && return 0
  # Avoid restarting the panel during its own Apply/update window.
  local lock=/opt/hiddify-manager/log/0-install.lock
  if [ -f "$lock" ] && [ "$(find "$lock" -mmin -20 2>/dev/null)" ]; then return 0; fi
  _csi_edit apply
}
mod_status() {
  if mod_verify >/dev/null 2>&1; then
    echo 'APPLIED  CDN and Auto CDN accept the origin IP; DNS/Direct checks preserved'
  else
    echo 'ABSENT  stock CDN origin-IP validation, or unsupported panel layout'
  fi
}
