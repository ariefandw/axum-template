#!/usr/bin/env bash
# Find public functions that nothing calls.
#
# Rust's `dead_code` lint exempts `pub` items, because in a library they are the
# public API. This crate is an application, so an uncalled `pub fn` is almost
# always a feature that was written and never wired up — the single most common
# defect in this repository's history: an audit service with no callers, a
# notification service with no callers, a scopes column nothing read, a storage
# connectivity check nothing invoked.
#
# The check is deliberately crude: it counts identifier occurrences. One
# occurrence means the declaration and nothing else.
set -uo pipefail
cd "$(dirname "$0")/.."

# Trait methods and impls of external traits are legitimately "uncalled" here.
ALLOW='^(from|fmt|default|clone|drop|new|main|name|check_ready|put_bytes|head|presign_get|presign_put|put_file|open|delete)$'

dead=()
while read -r fn; do
    [[ "$fn" =~ $ALLOW ]] && continue
    count=$(grep -rho "\b${fn}\b" src/ tests/ --include='*.rs' | wc -l)
    [ "$count" -le 1 ] && dead+=("$fn")
done < <(grep -rhoE '^[[:space:]]*pub (async )?fn [a-z_][a-z0-9_]*' src/ --include='*.rs' \
         | grep -oE '[a-z_][a-z0-9_]*$' | sort -u)

if [ ${#dead[@]} -gt 0 ]; then
    echo "Public functions with no callers:"
    printf '  %s\n' "${dead[@]}"
    echo
    echo "Either wire them up or delete them. A capability that exists but is"
    echo "never invoked is the defect this project keeps rediscovering."
    exit 1
fi

echo "No uncalled public functions."
