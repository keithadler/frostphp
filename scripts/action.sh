#!/usr/bin/env bash
# Entry point for the GitHub Action. Annotates the pull request on the exact
# lines that reached for something the policy does not grant.
set -euo pipefail

cd "$FROSTPHP_ACTION_PATH"
composer install --no-interaction --no-progress --no-dev --quiet
cd - >/dev/null

args=()
if [[ -n "${FROSTPHP_POLICY:-}" ]]; then
  args+=(--policy "$FROSTPHP_POLICY")
fi
if [[ -n "${FROSTPHP_ARGS:-}" ]]; then
  # shellcheck disable=SC2206
  args+=(${FROSTPHP_ARGS})
fi

read -r -a paths <<< "${FROSTPHP_PATHS:-.}"

set +e
php "$FROSTPHP_ACTION_PATH/bin/frostphp" "${paths[@]}" --format github "${args[@]}"
status=$?
set -e

# The annotations above are the report; print a readable summary too.
php "$FROSTPHP_ACTION_PATH/bin/frostphp" "${paths[@]}" "${args[@]}" || true

exit $status
