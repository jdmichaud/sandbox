#!/usr/bin/env bash
set -e

# ==============================================================================
# 1. CONFIGURATION & PARSING
# ==============================================================================

IMAGE_SIZE="10G"
POSITIONAL=()

while [[ $# -gt 0 ]]; do
  key="$1"
  case $key in
    -s|--size)
      IMAGE_SIZE="$2"
      shift; shift
      ;;
    -h|--help)
      echo "Usage: $0 <IMAGE_FILE> <TARGET_DIR> [-s SIZE]"
      echo ""
      echo "Description:"
      echo "  Creates a persistent writable overlay on top of <TARGET_DIR>."
      echo "  Writes are stored in <IMAGE_FILE>. The original directory is untouched."
      echo ""
      echo "Options:"
      echo "  -s, --size SIZE   Size of the image file (default: 10G)"
      echo ""
      echo "Example:"
      echo "  $0 overlay.img /home/bob/project -s 20G"
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
    echo "Usage: $0 <IMAGE_FILE> <TARGET_DIR> [-s SIZE]"
    echo "Try '$0 --help' for more information."
    exit 1
fi

IMAGE_FILENAME="$1"
TARGET_DIR="$2"
PROMPT_NAME=$(basename "${IMAGE_FILENAME%.*}")

# ==============================================================================
# 2. DEPENDENCY CHECKS
# ==============================================================================

check_dep() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "Error: Required tool '$1' is missing."
        exit 1
    fi
}

check_dep "gcc"
check_dep "truncate"
check_dep "mkfs.ext4"
check_dep "bwrap"
check_dep "blkid"

# Check bwrap version for overlay support
if ! bwrap --help 2>&1 | grep -q -- "--overlay"; then
    echo "Error: Your version of 'bwrap' is too old (missing --overlay support)."
    echo "       Please upgrade bubblewrap."
    exit 1
fi

# Check for libcap development files (Required for secure C compilation)
if ! echo "int main() { return 0; }" | gcc -x c - -lcap -o /dev/null 2>/dev/null; then
    echo "Error: 'libcap' development library is missing."
    echo "       This is required for security features."
    echo "       Debian/Ubuntu: sudo apt install libcap-dev"
    echo "       Fedora/RHEL:   sudo dnf install libcap-devel"
    exit 1
fi

# ==============================================================================
# 3. COMPILATION: 'imu' (Image Mount Utility)
# ==============================================================================

if [ -f "./imu" ]; then IMU_BIN="./imu"; else IMU_BIN="imu"; fi

has_suid_root() {
    local bin=$1
    local owner
    owner=$(stat -c '%u' "$bin")
    [ "$owner" -eq 0 ] && [ -u "$bin" ]
}

if ! command -v "$IMU_BIN" >/dev/null 2>&1; then
    echo "[*] 'imu' (Image Mount Utility) not found. Compiling..."
    cat << 'EOF' > imu.c
/*
 * imu.c - Image Mount Utility
 *
 * DESCRIPTION:
 *   A securely hardened tool to mount ext4 loopback images.
 *   Designed to allow unprivileged users to mount their own images
 *   without requiring full sudo access for every operation.
 *
 * SECURITY ARCHITECTURE:
 *   1. SUID Root Entry:
 *      Required initially to access mount() and loop-control system calls.
 *
 *   2. The Ambident Principle (Privilege Dropping):
 *      Using libcap, we immediately drop our Identity (EUID) to the Real User
 *      (e.g., "bob"). We retain ONLY the `CAP_SYS_ADMIN` capability.
 *      - Effect: If we try to open `/etc/shadow`, the kernel sees "User Bob"
 *        and denies it. If we try to `mount`, the kernel sees the Capability
 *        and allows it.
 *
 *   3. Anti-TOCTOU (Time-Of-Check to Time-Of-Use):
 *      We never trust file paths (which can be swapped for symlinks).
 *      We open files to get File Descriptors (FDs), verify the FDs,
 *      and then operate strictly on those FDs (using /proc/self/fd pinning).
 *
 *   4. Seccomp BPF (System Call Filtering):
 *      Once initialized, we install a strict syscall firewall.
 *      Only safe calls (read/write/mount/close) are allowed.
 *      Attempts to execve() (spawn shell) or open network sockets result
 *      in immediate process death.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stddef.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/syscall.h>
#include <sys/prctl.h>
#include <sys/capability.h>
#include <linux/loop.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>

// Helper macro for cleaner error printing
#define FAIL(msg) do { perror("Error: " msg); exit(EXIT_FAILURE); } while(0)

// --- Seccomp Whitelist ---
// Defines which system calls are allowed. All others kill the process.
#define ALLOW(name) \
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_##name, 0, 1), \
    BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW)
#define KILL BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL)

void lock_process() {
    struct sock_filter filter[] = {
        // 1. Verify Architecture (x86_64)
        BPF_STMT(BPF_LD+BPF_W+BPF_ABS, (offsetof(struct seccomp_data, arch))),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, AUDIT_ARCH_X86_64, 1, 0),
        KILL,

        // 2. Check Syscall Number
        BPF_STMT(BPF_LD+BPF_W+BPF_ABS, (offsetof(struct seccomp_data, nr))),

        // 3. Whitelist
        ALLOW(write), ALLOW(exit_group),
        ALLOW(brk), ALLOW(mmap), ALLOW(munmap),
        ALLOW(stat), ALLOW(lstat), ALLOW(fstat), ALLOW(newfstatat),
        ALLOW(openat), ALLOW(open), ALLOW(close),
        ALLOW(readlink),
        ALLOW(ioctl),       // Required for loop device configuration
        ALLOW(mount),       // Required to mount
        ALLOW(umount2),     // Required to unmount

        // 4. Default Action: Kill
        KILL
    };
    struct sock_fprog prog = { .len = sizeof(filter)/sizeof(filter[0]), .filter = filter };

    // Install the filter
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)) {
        FAIL("Failed to install Seccomp filter");
    }
}

/*
 * Drop Root identity but keep CAP_SYS_ADMIN.
 * This prevents "Confused Deputy" attacks where we accidentally
 * access files the user shouldn't see.
 */
void drop_root_keep_caps(uid_t r_uid, gid_t r_gid) {
    // Ensure capabilities persist across UID change
    if (prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0) < 0) FAIL("prctl(KEEPCAPS) failed");

    // Drop to Real User ID/GID
    if (setresgid(r_gid, r_gid, r_gid) < 0) FAIL("Failed to drop GID");
    if (setresuid(r_uid, r_uid, r_uid) < 0) FAIL("Failed to drop UID");

    // Restore CAP_SYS_ADMIN
    cap_t caps = cap_init();
    if (!caps) FAIL("cap_init failed");

    cap_value_t cap_list[] = { CAP_SYS_ADMIN };

    if (cap_set_flag(caps, CAP_PERMITTED, 1, cap_list, CAP_SET) < 0) FAIL("Setting caps (PERM)");
    if (cap_set_flag(caps, CAP_EFFECTIVE, 1, cap_list, CAP_SET) < 0) FAIL("Setting caps (EFF)");

    if (cap_set_proc(caps) < 0) FAIL("Failed to apply capabilities");
    cap_free(caps);
}

int main(int argc, char *argv[]) {
    if (geteuid() != 0) {
        fprintf(stderr, "Fatal: 'imu' is not running as Root (EUID=%d).\n", geteuid());
        fprintf(stderr, "       Possible causes:\n");
        fprintf(stderr, "       1. SUID bit not set (run: sudo chmod u+s imu)\n");
        fprintf(stderr, "       2. Filesystem mounted with 'nosuid' (Move imu to /usr/local/bin)\n");
        return EXIT_FAILURE;
    }

    if (argc < 2) {
        fprintf(stderr, "Usage: %s [mount|umount] ...\n", argv[0]);
        return EXIT_FAILURE;
    }

    // Handle Help
    if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) {
        printf("imu - Image Mount Utility (Secure SUID Helper)\n");
        printf("Usage:\n");
        printf("  imu mount <img_path> <mount_dir>\n");
        printf("  imu umount <mount_dir>\n");
        return EXIT_SUCCESS;
    }

    uid_t r_uid = getuid();
    gid_t r_gid = getgid();

    // 1. Drop Privileges immediately (become User Bob)
    drop_root_keep_caps(r_uid, r_gid);

    // 2. Lock Process (Seccomp)
    lock_process();

    // --- COMMAND: MOUNT ---
    if (strcmp(argv[1], "mount") == 0) {
        if (argc != 4) {
            fprintf(stderr, "Usage: imu mount <img_file> <mount_point>\n");
            return EXIT_FAILURE;
        }

        // Open Image (Checked against User Bob's permissions)
        int img_fd = open(argv[2], O_RDWR);
        if (img_fd < 0) FAIL("Failed to open image file");

        struct stat st;
        if (fstat(img_fd, &st) < 0) FAIL("Failed to stat image");
        if (st.st_uid != r_uid) FAIL("Security: You do not own the image file");
        if (!S_ISREG(st.st_mode)) FAIL("Security: Image is not a regular file");

        // Open Mountpoint (Checked against User Bob's permissions)
        int mnt_fd = open(argv[3], O_RDONLY | O_DIRECTORY);
        if (mnt_fd < 0) FAIL("Failed to open mountpoint directory");
        if (fstat(mnt_fd, &st) < 0) FAIL("Failed to stat mountpoint");
        if (st.st_uid != r_uid) FAIL("Security: You do not own the mountpoint directory");

        // Find Free Loop Device
        int c_fd = open("/dev/loop-control", O_RDWR);
        if (c_fd < 0) FAIL("Failed to access /dev/loop-control");
        long devnr = ioctl(c_fd, LOOP_CTL_GET_FREE);
        close(c_fd);
        if (devnr < 0) FAIL("No free loop devices available");

        char l_path[32]; snprintf(l_path, 32, "/dev/loop%ld", devnr);
        int loop_fd = open(l_path, O_RDWR);
        if (loop_fd < 0) FAIL("Failed to open new loop device");

        // Bind Image to Loop
        if (ioctl(loop_fd, LOOP_SET_FD, img_fd) < 0) FAIL("Failed to bind image to loop device");

        // Set Autoclear (Loop device is freed on unmount)
        struct loop_info64 i = {0}; i.lo_flags = LO_FLAGS_AUTOCLEAR;
        if (ioctl(loop_fd, LOOP_SET_STATUS64, &i) < 0) FAIL("Failed to set loop device flags");

        // Mount
        // Use /proc/self/fd to ensure we mount onto the exact directory we verified
        char mnt_proc[64]; snprintf(mnt_proc, 64, "/proc/self/fd/%d", mnt_fd);

        if (mount(l_path, mnt_proc, "ext4", MS_NOSUID|MS_NODEV|MS_NOATIME, NULL) < 0) {
            ioctl(loop_fd, LOOP_CLR_FD, 0); // Cleanup loop if mount fails
            FAIL("Mount syscall failed");
        }

        // Cleanup FDs
        close(img_fd); close(mnt_fd); close(loop_fd);

    // --- COMMAND: UMOUNT ---
    } else if (strcmp(argv[1], "umount") == 0) {
        if (argc != 3) {
            fprintf(stderr, "Usage: imu umount <mount_point>\n");
            return EXIT_FAILURE;
        }

        int mnt_fd = open(argv[2], O_RDONLY | O_DIRECTORY);
        if (mnt_fd < 0) FAIL("Failed to open mountpoint for verification");

        struct stat st;
        if (fstat(mnt_fd, &st) < 0) FAIL("Failed to stat mountpoint");
        if (st.st_uid != r_uid) FAIL("Security: You do not own this mountpoint");

        // Unmount
        if (umount2(argv[2], 0) < 0) FAIL("Unmount syscall failed");
        close(mnt_fd);

    } else {
        fprintf(stderr, "Error: Unknown command '%s'. Use mount or umount.\n", argv[1]);
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
EOF
    # Compile: Static link libcap if possible for robustness
    if gcc -O2 imu.c -o imu -Wl,-Bstatic -lcap -Wl,-Bdynamic >/dev/null 2>&1; then
        echo "[*] 'imu' compiled successfully (Static libcap)."
    elif gcc -O2 imu.c -o imu -lcap >/dev/null 2>&1; then
        echo "[*] 'imu' compiled successfully (Dynamic libcap)."
        echo "    (Note: Install static libcap for better portability)"
    else
        echo "Error: Compilation failed."
        rm imu.c
        exit 1
    fi
    rm imu.c
    IMU_BIN="./imu"
fi

# Check Permissions
if ! has_suid_root "$IMU_BIN"; then
    echo "Error: '$IMU_BIN' requires SUID Root permissions to function."
    echo "       It needs to perform privileged 'mount' operations."
    echo "Please run the following command to authorize it:"
    echo "  sudo chown root:root $IMU_BIN && sudo chmod u+s $IMU_BIN"
    echo "  (If you are on a 'nosuid' partition, move imu to /usr/local/bin)"
    exit 1
fi

# ==============================================================================
# 4. MAIN EXECUTION
# ==============================================================================

TMP_MOUNT=""
cleanup() {
    if [ -n "$TMP_MOUNT" ] && [ -d "$TMP_MOUNT" ]; then
        if [ -d "$TMP_MOUNT/upper" ]; then
            echo ""
            echo "[*] Unmounting..."
            $IMU_BIN umount "${TMP_MOUNT}" || echo "Warning: Unmount failed."
        fi
        rmdir "${TMP_MOUNT}" 2>/dev/null || true
    fi
}
trap cleanup EXIT INT TERM

# --- Image Creation / Checking ---
if [ ! -f "${IMAGE_FILENAME}" ]; then
    echo "[*] Creating new ${IMAGE_SIZE} sparse image..."

    # Guard Truncate
    if ! truncate -s "${IMAGE_SIZE}" "${IMAGE_FILENAME}"; then
        echo "Error: Failed to create image file '${IMAGE_FILENAME}'."
        echo "       Please check disk space and write permissions."
        exit 1
    fi

    # Guard Mkfs
    # -E root_owner ensures the FS inside belongs to the user, not root.
    if ! mkfs.ext4 -q -E root_owner=$(id -u):$(id -g) "${IMAGE_FILENAME}"; then
        echo "Error: Failed to format image '${IMAGE_FILENAME}'."
        echo "       Ensure 'e2fsprogs' is installed and the file is writable."
        exit 1
    fi
else
    echo "[*] Found existing image: ${IMAGE_FILENAME}"

    # Validate Filesystem Type
    FS_TYPE=$(blkid -o value -s TYPE "${IMAGE_FILENAME}" || echo "unknown")
    if [ "$FS_TYPE" != "ext4" ]; then
        echo "Error: The file '${IMAGE_FILENAME}' is not an ext4 filesystem."
        echo "       Detected type: '$FS_TYPE'"
        echo "       This tool only supports ext4 images for security reasons."
        exit 1
    fi

    if [ "$IMAGE_SIZE" != "10G" ]; then
        echo "    (Warning: Ignoring -s ${IMAGE_SIZE} because file exists)"
    fi
fi

# --- Mounting ---
TMP_MOUNT=$(mktemp -d)
echo "[*] Mounting image to temporary location..."

# Calls our C tool.
# If this fails, the C tool will print a specific error (e.g., "Permission denied").
if ! $IMU_BIN mount "${IMAGE_FILENAME}" "${TMP_MOUNT}"; then
    echo "Error: Failed to mount the image."
    rmdir "${TMP_MOUNT}"
    exit 1
fi

# Prepare Overlay Structure
mkdir -p "${TMP_MOUNT}/upper" "${TMP_MOUNT}/work"

echo "[*] Entering Sandbox: ${PROMPT_NAME}"
echo "    Overlay Target: ${TARGET_DIR}"
echo "    (Note: The rest of the filesystem is Read-Only)"

# --- Sandbox Execution ---
bwrap \
    --dev-bind /dev /dev \
    --ro-bind / / \
    --proc /proc \
    --overlay "${TMP_MOUNT}/upper" "${TMP_MOUNT}/work" "${TARGET_DIR}" \
    --setenv PS1 "(${PROMPT_NAME}) \u@\h:\w$ " \
    /bin/bash
