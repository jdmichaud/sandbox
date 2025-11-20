#!/usr/bin/env bash
set -e

# ==============================================================================
# 1. PRE-FLIGHT CHECKS
# ==============================================================================

if [[ $EUID -ne 0 ]]; then
   echo "Error: This script must be run with sudo."
   exit 1
fi

if [[ -z "$SUDO_USER" ]]; then
    echo "Error: Please run this via 'sudo', not as a direct root login."
    exit 1
fi

# Capture Real User details
REAL_USER="$SUDO_USER"
REAL_UID="$SUDO_UID"
REAL_GID="$SUDO_GID"
REAL_HOME=$(getent passwd "$REAL_USER" | cut -d: -f6)

# ==============================================================================
# 2. CONFIGURATION
# ==============================================================================

IMAGE_SIZE="10G"
VERBOSE=0
POSITIONAL=()

while [[ $# -gt 0 ]]; do
  key="$1"
  case $key in
    -s|--size)
      IMAGE_SIZE="$2"
      shift; shift
      ;;
    -v|--verbose)
      VERBOSE=1
      shift
      ;;
    -h|--help)
      echo "Usage: sudo $0 <IMAGE_FILE> <TARGET_DIR> [-s SIZE] [-v]"
      exit 0
      ;;
    *)
      POSITIONAL+=("$1")
      shift
      ;;
  esac
done
set -- "${POSITIONAL[@]}"

if [ "$#" -lt 2 ]; then
    echo "Usage: sudo $0 <IMAGE_FILE> <TARGET_DIR> [-s SIZE] [-v]"
    exit 1
fi

# Fix: Convert paths to absolute to prevent 'Read-only file system' errors in bwrap
IMAGE_FILENAME=$(realpath "$1")
TARGET_DIR=$(realpath "$2")
PROMPT_NAME=$(basename "${IMAGE_FILENAME%.*}")

# Helper for verbose logging
info() {
    if [[ $VERBOSE -eq 1 ]]; then
        echo "$@"
    fi
}

if [ ! -d "$TARGET_DIR" ]; then
    echo "Error: Target directory '$TARGET_DIR' does not exist."
    exit 1
fi

# ==============================================================================
# 3. DEPENDENCIES
# ==============================================================================

check_dep() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "Error: Required tool '$1' is missing."
        exit 1
    fi
}

check_dep "truncate"
check_dep "mkfs.ext4"
check_dep "blkid"
check_dep "mount"
check_dep "umount"
check_dep "losetup"
check_dep "fsck.ext4"
check_dep "runuser"
check_dep "realpath"

# Locate bwrap and PATH as the Real User using a Login Shell.
{ read -r BWRAP_BIN; read -r USER_PATH; } < <(sudo -u "$REAL_USER" bash -l -c 'command -v bwrap; echo $PATH')

if [[ -z "$BWRAP_BIN" ]]; then
    echo "Error: Required tool 'bwrap' is missing (not found in user's PATH)."
    exit 1
fi

if ! "$BWRAP_BIN" --help 2>&1 | grep -q -- "--overlay"; then
    echo "Error: bwrap version too old (missing --overlay)."
    exit 1
fi

# ==============================================================================
# 4. MAIN LOGIC
# ==============================================================================

TMP_MOUNT=""

cleanup() {
    if [ -n "$TMP_MOUNT" ] && [ -d "$TMP_MOUNT" ]; then
        if mountpoint -q "$TMP_MOUNT"; then
            echo ""
            info "[*] Unmounting..."
            umount "$TMP_MOUNT" || echo "Warning: Unmount failed."
        fi
        rmdir "$TMP_MOUNT" 2>/dev/null || true
    fi
}
trap cleanup EXIT INT TERM

# --- Image Creation ---
if [ ! -f "${IMAGE_FILENAME}" ]; then
    info "[*] Creating new ${IMAGE_SIZE} sparse image..."

    # Create as the user
    if ! sudo -u "$REAL_USER" truncate -s "${IMAGE_SIZE}" "${IMAGE_FILENAME}"; then
        echo "Error: Failed to create image file."
        exit 1
    fi

    # Format (root owner set to user)
    # -m 0: Disable reserved blocks (save 5% space)
    # lazy_itable_init=1,lazy_journal_init=1: Don't write empty metadata to disk immediately (keeps file sparse/small)
    if ! mkfs.ext4 -q -m 0 -E root_owner=$REAL_UID:$REAL_GID,lazy_itable_init=1,lazy_journal_init=1 "${IMAGE_FILENAME}"; then
        echo "Error: Failed to format image."
        rm -f "${IMAGE_FILENAME}"
        exit 1
    fi
else
    info "[*] Found existing image: ${IMAGE_FILENAME}"

    # Lock check
    if losetup -j "${IMAGE_FILENAME}" | grep -q "${IMAGE_FILENAME}"; then
        echo "Error: This image is already mounted/in-use!"
        exit 1
    fi

    # Filesystem type check
    FS_TYPE=$(blkid -o value -s TYPE "${IMAGE_FILENAME}" || echo "unknown")
    if [ "$FS_TYPE" != "ext4" ]; then
        echo "Error: File is not an ext4 filesystem (Type: $FS_TYPE)."
        exit 1
    fi

    # Filesystem integrity check
    info "[*] Checking filesystem integrity..."
    
    # Capture exit code explicitly because 'if ! fsck' resets $? to 0
    FSCK_RET=0
    fsck.ext4 -p "${IMAGE_FILENAME}" >/dev/null 2>&1 || FSCK_RET=$?

    # Exit code 1 means "Errors Corrected" (Safe). >1 means "Uncorrected" (Bad).
    if [ "$FSCK_RET" -gt 1 ]; then
        echo "Error: Filesystem corrupted (fsck code $FSCK_RET)."
        echo "       Run 'fsck.ext4 ${IMAGE_FILENAME}' manually."
        exit 1
    fi

    if [ "$IMAGE_SIZE" != "10G" ]; then
        info "    (Warning: Ignoring -s ${IMAGE_SIZE} because file exists)"
    fi
fi

# --- Mounting ---
TMP_MOUNT=$(mktemp -d)
info "[*] Mounting image..."

if ! mount -o loop,noatime,nosuid,nodev "${IMAGE_FILENAME}" "${TMP_MOUNT}"; then
    echo "Error: Mount failed."
    rmdir "${TMP_MOUNT}"
    exit 1
fi

# --- Preparation ---
# Create upper/work as User.
if ! sudo -u "$REAL_USER" mkdir -p "${TMP_MOUNT}/upper" "${TMP_MOUNT}/work"; then
    echo "Error: Failed to create overlay directories (Permission denied?)"
    exit 1
fi

# --- Path Safety Check ---
META_FILE="${TMP_MOUNT}/.sandbox_target"
if [ -f "$META_FILE" ]; then
    STORED_TARGET=$(cat "$META_FILE")
    if [[ "$STORED_TARGET" != "$TARGET_DIR" ]]; then
        echo "Error: Path mismatch!"
        echo "       This image is bound to: ${STORED_TARGET}"
        echo "       You are trying to use:  ${TARGET_DIR}"
        exit 1
    fi
else
    echo "$TARGET_DIR" > "$META_FILE"
fi

info "[*] Entering Sandbox: ${PROMPT_NAME}"
info "    Overlay Target: ${TARGET_DIR}"

# --- Environment Import ---
# We grab the environment variables from the User's Shell (Parent of sudo).
USER_SHELL_PID=$(ps -o ppid= -p $PPID | tr -d ' ')
ENV_ARGS=()

while IFS= read -r -d '' pair; do
    key=${pair%%=*}
    val=${pair#*=}
    
    # Exclude sudo-specific or confusing variables
    case "$key" in
        SUDO_*|PWD|OLDPWD|_) continue ;;
    esac

    ENV_ARGS+=( "--setenv" "$key" "$val" )
done < "/proc/$USER_SHELL_PID/environ"

# --- Execution ---
# Locate sudo to mask it inside the container
SUDO_BIN=$(command -v sudo)

# We run bwrap as ROOT (allowing namespace creation).
# Inside the sandbox, we use 'runuser' to drop to the Real User.
# -p ensures the environment we built in ENV_ARGS is preserved.
# We mask sudo binary with /dev/null to prevent privilege escalation inside sandbox.
# FIX: Moved --ro-bind / / to the TOP so subsequent binds (like /dev) override it.
"$BWRAP_BIN" \
    "${ENV_ARGS[@]}" \
    --ro-bind / / \
    --dev-bind /dev /dev \
    --tmpfs /tmp \
    --bind /run /run \
    --bind /var/tmp /var/tmp \
    --ro-bind /dev/null "$SUDO_BIN" \
    --proc /proc \
    --overlay-src "${TARGET_DIR}" \
    --overlay "${TMP_MOUNT}/upper" "${TMP_MOUNT}/work" "${TARGET_DIR}" \
    --setenv PS1 "(${PROMPT_NAME}) \u@\h:\w$ " \
    runuser -u "$REAL_USER" -p -- /bin/bash

# Trap triggers cleanup (unmount) automatically here
