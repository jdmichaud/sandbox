# Sandbox Overlay Script

A lightweight, self-contained tool to create persistent, writable overlays on top of arbitrary directories.

## 1. What is this?

This script allows you to "sandbox" a directory.
- It creates a virtual hard drive file (an ext4 image).
- It uses `bubblewrap` to layer this virtual drive on top of a real directory.
- **Reads:** You see all your existing files.
- **Writes:** Any file you create or modify is saved into the image file, leaving the original directory untouched.

## 2. Prerequisites

This script uses standard system tools found on most Linux distributions.
You need:
- `bubblewrap` (package name: `bubblewrap`)
- `sudo` access
- Standard tools: `mkfs.ext4`, `mount`, `truncate`, `mount`, `umount`, `losetup`, `fsck.ext4`

## 3. Installation

1. Save the script as `sandbox.sh`.
2. Make it executable:
   ```bash
   chmod +x sandbox.sh
   ```

## 4. Usage

Because mounting filesystem images requires system privileges, you must run this script with `sudo`.

```bash
sudo ./sandbox.sh <IMAGE_FILE> <TARGET_DIR> [-s SIZE] [-v]
```

### Examples

**Basic Usage (Default 10GB size):**
```bash
sudo ./sandbox.sh my_project.img /home/me/projects/cpp_app
```

**Custom Size:**
```bash
sudo ./sandbox.sh steam_library.img /home/me/.steam -s 100G
```

**To Exit:**
Simply type `exit` or press `Ctrl+D`. The script will automatically unmount the image and clean up temporary mount points.

## 5. Technical Details & Security

Although the script runs with `sudo`, it is designed to minimize the use of root privileges:

1.  **Check:** Fails immediately if not run via `sudo`.
2.  **Image Creation:** It identifies your real user account and creates the image file *as you*, ensuring you own the file (not root).
3.  **Mounting:** It uses root privileges strictly to perform the `mount` command on the loopback device.
4.  **Sandboxing:** It drops root privileges immediately to launch the `bubblewrap` container as your real user.

Files created inside the sandbox are written to the ext4 image. The image is formatted with specific options so that the root of the virtual drive acts as your user, preventing permission issues.