#!/bin/bash

INTERFACE="en0"  # change based on system

CURRDIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)
CONFIG_FILE="${CURRDIR}/suricata/config.yaml"
RULES_FILE="${CURRDIR}/suricata/rules/local.rules"
READINESS_FILE="${CURRDIR}/suricata/suricata_ready"
SOCK_FILE=""

SURICATA_PID=""

generate_random_string() {
    LC_ALL=C < /dev/urandom tr -dc 'A-Za-z0-9' | head -c 5
}

cleanup() {
    echo "Cleaning up..."
    rm -f "${READINESS_FILE}"

    if [[ -n $SURICATA_PID ]]; then
        if kill $SURICATA_PID > /dev/null 2>&1; then
            echo "Suricata process terminated."
        else
            echo "Failed to terminate Suricata process with PID $SURICATA_PID. Attempting to kill by name."
            pkill -f "suricata"
        fi
    else
        pkill -f "suricata"
    fi
}

# trap for script cleanup on exit, crash, or interrupt
trap cleanup EXIT INT TERM

echo "CONFIG_FILE: ${CONFIG_FILE}"
echo "RULES_FILE: ${RULES_FILE}"
echo "READINESS_FILE: ${READINESS_FILE}"

# generate random sock filename and update config.yaml
rand=$(generate_random_string)
SOCK_FILE="${CURRDIR}/suricata/socks/suricata_eve_${rand}.sock"
echo -e "New sock file: ${SOCK_FILE}"
sed -i '' -E "s|filename: /tmp/suricata_eve_[a-zA-Z0-9]+\.sock|filename: ${SOCK_FILE}|" "${CONFIG_FILE}"

{
    # listen to the socket and forward events to localhost:5000/alerts/submit
    while true; do
        nc -lkU "${SOCK_FILE}" | while IFS= read -r line; do
            echo "$line" | curl -sS -o /dev/null -X POST -H "Content-Type: application/json" -d @- http://localhost:5000/alerts/submit
        done
    done
} &

# background start Suricata and get pid
sudo suricata -c "${CONFIG_FILE}" -i "${INTERFACE}" -S "${RULES_FILE}" -vvv &
SURICATA_PID=$!

# wait for Suricata to initialize
sleep 5

# check if Suricata process is still running
if ps -p ${SURICATA_PID} > /dev/null; then
   echo "Suricata started successfully."
   touch "${READINESS_FILE}"
else
   echo "Failed to start Suricata."
   exit 1
fi

# monitor Suricata process and cleanup if it stops
wait ${SURICATA_PID}
cleanup
