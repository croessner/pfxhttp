#!/usr/bin/env bash
set -euo pipefail

readonly blocker_exit=77
readonly compose_file="test/e2e/postfix/compose.yml"
readonly postfix_image="${PFXHTTP_E2E_POSTFIX_IMAGE:-chrroessner/postfix:latest}"

block() {
    printf 'PFXHTTP_POSTFIX_E2E_BLOCKED: code=%s reason=%s\n' "$1" "$2" >&2
    exit "${blocker_exit}"
}

fail() {
    printf 'PFXHTTP_POSTFIX_E2E_FAILED: %s\n' "$1" >&2
    exit 1
}

command -v docker >/dev/null 2>&1 || block docker-unavailable "docker command is unavailable"
docker info >/dev/null 2>&1 || block docker-daemon-unavailable "docker daemon is unavailable"
docker compose version >/dev/null 2>&1 || block compose-unavailable "docker compose is unavailable"

for image in "${postfix_image}" golang:1.26.9-alpine3.24 alpine:3.23; do
    docker image inspect "${image}" >/dev/null 2>&1 || \
        block image-unavailable "required local image is unavailable; see test/e2e/postfix/README.md"
done

runtime_dir="$(mktemp -d /tmp/pfxhttp-postfix-e2e.XXXXXX)"
export PFXHTTP_E2E_RUNTIME="${runtime_dir}"
export PFXHTTP_E2E_POSTFIX_IMAGE="${postfix_image}"
export PFXHTTP_E2E_AUTH_SECRET="pfxhttp-e2e-${RANDOM}-$$-$(date +%s)"
export COMPOSE_PROJECT_NAME="pfxhttp-postfix-e2e-$$"

compose() {
    docker compose -f "${compose_file}" "$@"
}

cleanup_complete=false

best_effort_cleanup() {
    [[ "${cleanup_complete}" == true ]] && return
    compose down --volumes --remove-orphans --rmi local >/dev/null 2>&1 || true
    rm -rf "${runtime_dir}" || true
}
trap best_effort_cleanup EXIT INT TERM

checked_cleanup() {
    compose down --volumes --remove-orphans --rmi local
    rm -rf "${runtime_dir}"
    cleanup_complete=true
}

wait_for_file() {
    local path="$1"
    local attempt
    for attempt in {1..200}; do
        [[ -f "${path}" ]] && return 0
        sleep 0.05
    done

    return 1
}

compose build backend pfxhttp probe
compose up -d backend pfxhttp postfix
compose run --rm probe wait

postfix_version="$(compose exec -T postfix postconf -h mail_version | tr -d '\r')"
printf 'Postfix version: %s (%s)\n' "${postfix_version}" "${postfix_image}"

compose exec -T postfix postconf -m | grep -qx socketmap || \
    block postfix-socketmap-unavailable "Postfix does not advertise socketmap support"
compose exec -T postfix postconf -a | grep -qx dovecot || \
    block postfix-dovecot-unavailable "Postfix does not advertise dovecot SASL support"
compose exec -T postfix postconf -M 2526/inet >/dev/null
compose exec -T postfix postconf -M 2527/inet >/dev/null
compose exec -T postfix postconf -M 2528/inet >/dev/null

map_key="map-$RANDOM-$$"
map_result="$(compose exec -T postfix postmap -q "${map_key}" socketmap:inet:pfxhttp:23450:map | tr -d '\r\n')"
[[ "${map_result}" == mapped ]] || fail "real postmap lookup returned an unexpected value"
printf 'real postmap -q lookup: PASS\n'

compose run --rm probe policy-reuse
compose run --rm probe smtp-auth

compose run --rm probe socketmap-reuse-idle &
socketmap_idle_pid=$!
compose run --rm probe mixed
wait "${socketmap_idle_pid}"

compose run --rm probe overload-budget
compose run --rm probe grpc-budget

rm -f "${runtime_dir}/ready" "${runtime_dir}/drained"
compose run --rm --name "${COMPOSE_PROJECT_NAME}-lifecycle" probe lifecycle &
lifecycle_pid=$!
wait_for_file "${runtime_dir}/ready" || fail "lifecycle probe did not become ready"
compose stop --timeout 6 pfxhttp
wait "${lifecycle_pid}"
[[ -f "${runtime_dir}/drained" ]] || fail "persistent connections were not drained"

compose up -d pfxhttp
compose run --rm probe wait
map_key="restart-$RANDOM-$$"
map_result="$(compose exec -T postfix postmap -q "${map_key}" socketmap:inet:pfxhttp:23450:map | tr -d '\r\n')"
[[ "${map_result}" == mapped ]] || fail "post-restart postmap lookup returned an unexpected value"
compose run --rm probe policy-reuse
compose run --rm probe smtp-auth-eventually
printf 'graceful restart and public-boundary reprobe: PASS\n'

log_file="${runtime_dir}/compose.log"
umask 077
compose logs --no-color pfxhttp backend >"${log_file}"
for forbidden in "${PFXHTTP_E2E_AUTH_SECRET}" synthetic-password synthetic-key budget-user e2e-user recipient@example.test; do
    if grep -Fq "${forbidden}" "${log_file}"; then
        fail "secret or client-identity marker appeared in captured container logs"
    fi
done
rm -f "${log_file}"

checked_cleanup
printf 'secret-safe captured-log scan and owned-artifact cleanup: PASS\n'
printf 'Postfix public interoperability and mixed-load lane: PASS\n'
