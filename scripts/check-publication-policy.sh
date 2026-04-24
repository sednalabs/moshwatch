#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later

set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/check-publication-policy.sh [--staged|--worktree|--print-config]

Checks public MoshWatch files against maintainer-configured local publication
policy patterns. The pattern file is local operator configuration, not
repository content. Configure one of these paths:

  MOSHWATCH_PUBLICATION_POLICY_PATTERNS=/path/to/patterns.txt
  .git/info/moshwatch-publication-policy-patterns.txt
  ~/.config/moshwatch/publication-policy-patterns.txt

Add "moshwatch-publication-policy-ok" to an exceptional line only after review.
EOF
}

mode="--worktree"
if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
  usage
  exit 0
elif [[ "${1:-}" == "--staged" || "${1:-}" == "--worktree" || "${1:-}" == "--print-config" ]]; then
  mode="$1"
elif [[ $# -gt 0 ]]; then
  usage >&2
  exit 2
fi

repo_root="$(git rev-parse --show-toplevel)"
git_info_patterns="$repo_root/.git/info/moshwatch-publication-policy-patterns.txt"
user_patterns="${XDG_CONFIG_HOME:-$HOME/.config}/moshwatch/publication-policy-patterns.txt"

pattern_file="${MOSHWATCH_PUBLICATION_POLICY_PATTERNS:-}"
if [[ -z "$pattern_file" && -f "$git_info_patterns" ]]; then
  pattern_file="$git_info_patterns"
fi
if [[ -z "$pattern_file" && -f "$user_patterns" ]]; then
  pattern_file="$user_patterns"
fi

if [[ "$mode" == "--print-config" ]]; then
  if [[ -n "$pattern_file" ]]; then
    printf 'pattern_file=%s\n' "$pattern_file"
  else
    printf 'pattern_file=\n'
  fi
  exit 0
fi

if [[ -z "$pattern_file" || ! -s "$pattern_file" ]]; then
  cat >&2 <<'EOF'
Publication policy check is enabled, but no local policy pattern file was found.

Create .git/info/moshwatch-publication-policy-patterns.txt, set
MOSHWATCH_PUBLICATION_POLICY_PATTERNS, or add
~/.config/moshwatch/publication-policy-patterns.txt.
EOF
  exit 2
fi

is_excluded_path() {
  case "$1" in
    .git/*|target/*|vendor/mosh/*|.githooks/*) return 0 ;;
    scripts/check-publication-policy.sh) return 0 ;;
    *) return 1 ;;
  esac
}

report_match() {
  local path="$1"
  local matches="$2"
  if [[ -n "$matches" ]]; then
    printf '%s\n' "$matches" | sed "s#^#$path:#"
  fi
}

found=0
if [[ "$mode" == "--staged" ]]; then
  while IFS= read -r -d '' path; do
    if is_excluded_path "$path"; then
      continue
    fi
    matches="$(
      git show ":$path" 2>/dev/null \
        | grep -n -I -E -f "$pattern_file" \
        | grep -v 'moshwatch-publication-policy-ok' || true
    )"
    if [[ -n "$matches" ]]; then
      report_match "$path" "$matches"
      found=1
    fi
  done < <(git diff --cached --name-only -z --diff-filter=ACMR)
else
  matches="$(
    git grep -n -I -E -f "$pattern_file" -- \
      ':(exclude).githooks/**' \
      ':(exclude)scripts/check-publication-policy.sh' \
      ':(exclude)target/**' \
      ':(exclude)vendor/mosh/**' \
      | grep -v 'moshwatch-publication-policy-ok' || true
  )"
  if [[ -n "$matches" ]]; then
    printf '%s\n' "$matches"
    found=1
  fi
fi

if [[ "$found" -ne 0 ]]; then
  cat >&2 <<'EOF'

Publication policy check failed.

This repository should stay product-neutral. Use neutral diagnostic/export
terminology for public-facing files.
EOF
  exit 1
fi
