#!/usr/bin/env bash
#
# Build NS8 Business Roadwarrior VPN images (vpn-controller + vpn module)
#

set -euo pipefail

repobase="${REPOBASE:-ghcr.io/bls-isp}"
imagetag="${IMAGETAG:-latest}"

controller_image="${repobase}/vpn-controller"
module_image="${repobase}/vpnportal"

if [[ -n "${CONTAINER_ENGINE:-}" ]]; then
    if ! command -v "${CONTAINER_ENGINE}" >/dev/null 2>&1; then
        echo "Error: requested CONTAINER_ENGINE '${CONTAINER_ENGINE}' not found in PATH" >&2
        exit 1
    fi
elif command -v podman >/dev/null 2>&1; then
    CONTAINER_ENGINE="podman"
elif command -v docker >/dev/null 2>&1; then
    CONTAINER_ENGINE="docker"
else
    echo "Error: neither podman nor docker found in PATH" >&2
    exit 1
fi

echo "Building ${controller_image}:${imagetag} using ${CONTAINER_ENGINE}..."
"${CONTAINER_ENGINE}" build \
    --force-rm \
    -f container/Containerfile \
    -t "${controller_image}:${imagetag}" \
    container

echo "Building ${module_image}:${imagetag} using ${CONTAINER_ENGINE}..."
"${CONTAINER_ENGINE}" build \
    --force-rm \
    -f Containerfile \
    --label "org.nethserver.images=${controller_image}:${imagetag}" \
    -t "${module_image}:${imagetag}" \
    .

images=("${controller_image}" "${module_image}")

if [[ -n "${CI:-}" && -n "${GITHUB_OUTPUT:-}" ]]; then
    printf 'images=["%s","%s"]\n' "${controller_image}" "${module_image}" >> "${GITHUB_OUTPUT}"
else
    printf "Images built successfully:\n"
    for img in "${images[@]}"; do
        printf "  - %s:%s\n" "${img}" "${imagetag}"
    done
fi
