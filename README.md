# Sandbox Overlay Script

A lightweight, secure tool to create persistent, writable overlays on top of arbitrary directories.

## 1. What is this and why do I need it?

**The Problem:**
You want to test a new library, compile a project, or run a program, but you are afraid it might clutter your home directory or accidentally delete your files. You want a "Save Game" feature for your filesystem.

**The Solution:**
This script creates a **Sandbox**.
1.  It creates a single file (e.g., `project.img`) that acts as a virtual hard drive.
2.  It takes a directory of your choice (e.g., `/home/bob/my_project`) and layers the virtual drive on top of it.
3.  It gives you a shell inside this layered environment.

**The Result:**
*   **Reads:** You can verify and read all your existing files normally.
*   **Writes:** Any file you create, modify, or delete is recorded **only** in the `project.img` file.
*   **Cleanup:** When you exit the shell, your real directory is exactly how you left it. If you want to keep the changes, just mount the image again later. If you messed up, just delete the image file.

---

## 2. How to Use

### Prerequisites
This tool works on standard Linux distributions (Debian, Ubuntu, Fedora, Arch). You need the following dependencies installed:
*   `bubblewrap` (bwrap)
*   `gcc` (for compiling the helper)
*   `libcap-dev` (or `libcap-devel` on Fedora)
*   `e2fsprogs` (for mkfs.ext4)

### Installation
Save the script as `sandbox.sh` and make it executable:
```bash
chmod +x sandbox.sh
```

### Basic Usage
Run the script providing an image name and the target directory you want to overlay:

```bash
./sandbox.sh my_work.img /home/me/projects/test
```

**First Run Note:**
The script relies on a custom C tool (`imu`) to handle mounting securely. The first time you run it, the script will compile this tool and ask for `sudo` permission once to set the **SUID** bit (make it executable as root).
*> "Error: './imu' requires SUID Root permissions... Please run sudo..."*

### Advanced Options
You can specify the size of the image (default is 10GB). Note that this is a **sparse file**, meaning it takes up 0 space initially and grows as you add data.

```bash
# Create a 50GB container over your entire home directory
./sandbox.sh steam_games.img /home/me -s 50G
```

### Exiting
Type `exit` or press `Ctrl+D` to close the sandbox. The script will automatically unmount the image and clean up temporary directories.

---

## 3. Technical Details (Under the Hood)

This script combines Bash scripting, low-level C system calls, and Linux Namespaces to achieve a secure, unprivileged-feeling workflow.

### The Architecture

1.  **The Image:** A sparse `ext4` loopback file holds the persistent data.
2.  **The Helper (`imu`):** A custom C binary that handles the privileged operations (mounting/unmounting).
3.  **The Container (`bwrap`):** Uses Linux Namespaces to create the environment where the overlay is visible.

### Security Mechanisms

The most critical part of this tool is the `imu` binary. Since `mount` requires Root privileges, `imu` is a **SUID** binary. To prevent it from being used maliciously (e.g., to mount system files or gain root shell), it employs several advanced hardening techniques:

1.  **The Ambident Principle (Capabilities):**
    Unlike traditional SUID tools that run as Root, `imu` immediately drops its identity to the **Real User ID** (your user). It keeps only one "superpower" (Capability): `CAP_SYS_ADMIN`.
    *   *Result:* If the tool tries to open a file you don't have permission to read (like `/etc/shadow`), the Kernel denies it immediately because the process is effectively running as *you*, not root.

2.  **Anti-TOCTOU (Time-Of-Check to Time-Of-Use):**
    A common attack involves swapping a valid file for a malicious symlink between the time a program checks it and the time it opens it.
    *   `imu` avoids this by opening files immediately to get a **File Descriptor (FD)**. All subsequent checks (ownership, stats) are performed on the FD.
    *   Mounting is performed by pinning the directory inode via `/proc/self/fd/N`, ensuring we mount exactly what we checked.

3.  **Seccomp BPF (System Call Filtering):**
    Once initialized, `imu` applies a strict whitelist of allowed System Calls using **Seccomp**.
    *   Allowed: `read`, `write`, `mount`, `ioctl`, `close`.
    *   Blocked: `execve` (spawning shells), `socket` (network access), and everything else.
    *   *Result:* Even if an attacker finds a buffer overflow in the code, they cannot spawn a shell or exfiltrate data because the kernel will kill the process instantly.

4.  **Static Linking:**
    The script attempts to statically link `libcap` to ensure the binary is robust and independent of system library versions.

### The Overlay Logic

1.  `imu` mounts the image to a temporary folder (e.g., `/tmp/tmp.X/upper`).
2.  The script sets up the standard OverlayFS structure (`upper` directory for data, `work` directory for atomicity).
3.  `bubblewrap` is launched. It binds the host root `/` as Read-Only.
4.  Finally, `bubblewrap` mounts the OverlayFS on top of your target directory (e.g., `/home/me`) and drops you into a shell.
