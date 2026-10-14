# Manual test: deactivating an interrupted reencryption with `secboot-tool deactivate`

This procedure reproduces the state left behind when a LUKS2 online reencryption
is interrupted, and then deactivates the leftover device-mapper volumes with
`secboot-tool deactivate`.

It covers the bug where `DeactivateContainer` could not deactivate a container
whose backing device is shared by several device-mapper volumes (`crypt02`,
`crypt02-overlay`, `crypt02-hotzone-forward`). The fix is
`ActivateContext.DeactivateContainerByName`, which detaches a volume by its name
instead of looking the name up from the device.

All files are created inside `cmd/secboot-tool/`. Run every command from the
repository root (`/secboot`).

---

## Contents

- [Requirements](#requirements)
- [Procedure](#procedure)
  - [1. Build the tool](#1-build-the-tool)
  - [2. Create a backing image file](#2-create-a-backing-image-file)
  - [3. Attach the image to a loop device](#3-attach-the-image-to-a-loop-device)
  - [4. Format the loop device as LUKS2](#4-format-the-loop-device-as-luks2)
  - [5. Open the container](#5-open-the-container)
  - [6. Start an online reencryption](#6-start-an-online-reencryption)
  - [7. Interrupt the reencryption](#7-interrupt-the-reencryption)
  - [8. Confirm the leftover device-mapper volumes](#8-confirm-the-leftover-device-mapper-volumes)
  - [9. Deactivate the top-level volume `crypt02`](#9-deactivate-the-top-level-volume-crypt02)
  - [10. Verify that nothing is left active](#10-verify-that-nothing-is-left-active)
  - [11. Fallback if a deactivate fails](#11-fallback-if-a-deactivate-fails)
  - [12. Clean up the test environment](#12-clean-up-the-test-environment)
- [Expected results](#expected-results)

---

## Requirements

| Requirement | Version used | Notes |
| --- | --- | --- |
| Linux with device-mapper | kernel with `dm_crypt` and `dm_mod` | Needed for `/dev/mapper` and `dmsetup`. |
| `cryptsetup` | 2.8.4 | Provides `luksFormat`, `open`, `reencrypt`, `close`. |
| `libkeyutils-dev` | 1.6.3 | Needed to build the root `secboot` package (cgo). Install with `sudo apt install libkeyutils-dev`. |
| `dmsetup` | Part of `libdevmapper` | Used to inspect the device-mapper state. |
| Go | version from `go.mod` | Used to build the tool. |
| `sudo` | - | Required for `losetup`, `cryptsetup`, `dmsetup` and the tool itself. |
| Free disk space | at least 8 GiB | The reencryption writes the whole image. |

The test takes about 2 minutes. Most of that is the reencryption.

---

## Procedure

Each step lists the command, what it does, and what to check. Keep the terminal
output of each step for the PR.

### 1. Build the tool

```bash
go build -o cmd/secboot-tool/secboot-tool ./cmd/secboot-tool
```

Builds the `secboot-tool` binary into `cmd/secboot-tool/`. The binary links
against the `DeactivateContainerByName` API, so rebuild it after any change to
the code.

**Check:** the build exits without output and `cmd/secboot-tool/secboot-tool`
exists.

```bash
ls -l cmd/secboot-tool/secboot-tool
```

**Optional check:** the usage text must show only the active-name argument.

```bash
cmd/secboot-tool/secboot-tool deactivate -h
```

Expected usage line:

```
usage: secboot-tool deactivate [<options>] <active-name>
```

---

### 2. Create a backing image file

```bash
truncate -s 8G cmd/secboot-tool/cool-test.img
```

Creates a sparse 8 GiB file that acts as the disk for the LUKS2 container. The
file takes no space until it is written, but the reencryption writes the whole
device, so about 8 GiB must be free.

**Check:**

```bash
ls -lh cmd/secboot-tool/cool-test.img
```

Expected: `8.0G`.

---

### 3. Attach the image to a loop device

```bash
sudo losetup -f --show cmd/secboot-tool/cool-test.img
```

Attaches the file to the first free loop device and prints its path.

**Note the device path.** Store it in the `LOOP` variable. The following steps
use `$LOOP`.

If the image is already attached, `losetup -f --show` attaches it again and
creates another loop device. Check first with
`sudo losetup -a | grep cool-test`, and reuse an existing device if one is
listed.

```bash
LOOP=$(sudo losetup -f --show cmd/secboot-tool/cool-test.img)
echo "$LOOP"
```

Keep the shell session open, so that `$LOOP` stays set.

---

### 4. Format the loop device as LUKS2

```bash
sudo cryptsetup luksFormat --type luks2 $LOOP
```

Initialises a LUKS2 header on the loop device.

Cryptsetup prints a warning and asks for confirmation. Type `YES` in capital
letters, then enter and verify a throwaway passphrase. Use the same passphrase
for steps 5 and 6.

**Check:**

```bash
sudo cryptsetup luksDump $LOOP | head -n 3
```

Expected first line: `LUKS header information`, and a line `Version:  2`.

---

### 5. Open the container

```bash
sudo cryptsetup open $LOOP crypt02
```

Unlocks the container and creates the device-mapper volume
`/dev/mapper/crypt02`. This is the active volume that the reencryption operates
on. Enter the passphrase from step 4.

**Check:**

```bash
sudo dmsetup ls
```

Expected: a `crypt02` entry, alongside the system devices.

---

### 6. Start an online reencryption

```bash
sudo cryptsetup reencrypt --active-name crypt02
```

Starts an online reencryption of the open container. While it runs, cryptsetup
creates the additional mappings `crypt02-hotzone-forward` and `crypt02-overlay`
on top of the same backing device. This is the state that makes the old lookup
ambiguous.

Cryptsetup asks for the passphrase again (`Enter passphrase for key slot 0`) and
then prints progress, for example:

```
Enter passphrase for key slot 0:
Progress:   9.1%, ETA 01m09s,  742 MiB written, speed 106.5 MiB/s
```

Throughput on the test machine was between about 94 and 140 MiB/s. At that
speed, an 8 GiB image takes about 60 to 90 seconds, which gives enough time for
step 7.

> **Verify before running:** the online-reencryption options depend on the
> cryptsetup version. Check `man cryptsetup` (section `reencrypt`) or
> `cryptsetup reencrypt --help`. The command above is the form used for this
> test. If it is rejected, adjust the options and keep the active name the same.

**Check:** leave this command running. Step 7 interrupts it.

---

### 7. Interrupt the reencryption

Open a **second terminal**. Find the `cryptsetup` process and kill it while the
reencryption is still running:

```bash
pgrep -a -x cryptsetup
```

Expected: one line with the PID and the command, for example `12345 cryptsetup
reencrypt --active-name crypt02`.

```bash
sudo kill -9 <PID>
```

Replace `<PID>` with the number from `pgrep`.

In the first terminal the command prints `Killed`.

`kill -9` simulates what happens when snapd is restarted in the middle of a
reencryption: the process dies without cleanup, leaving the device-mapper
volumes behind.

**Timing:** if the reencryption finishes before you kill it, the test does not
reproduce the state. You will see `Finished` in the first terminal and no
leftover mappings in step 8. Repeat the test from step 2 with a larger image
(for example `16G`).

---

### 8. Confirm the leftover device-mapper volumes

```bash
sudo dmsetup ls
sudo dmsetup table | grep crypt02
```

`dmsetup ls` lists the device-mapper devices. `dmsetup table` shows how each one
is built.

Expected output (device numbers may differ):

```
crypt02	(252:2)
crypt02-hotzone-forward	(252:3)
crypt02-overlay	(252:4)
dm_crypt-0	(252:0)
ubuntu--vg-ubuntu--lv	(252:1)
```

Expected table lines for `crypt02*` (the backing device is `7:42` in this
example, your loop device will show its own number):

```
crypt02: 0 16744448 linear 252:4 0
crypt02-hotzone-forward: 0 16744448 linear 7:42 32768
crypt02-overlay: 0 2028544 crypt aes-xts-plain64 ... 0 7:42 32768
crypt02-overlay: 2028544 507136 crypt aes-xts-plain64 ... 2028544 252:3 2028544
crypt02-overlay: 2535680 14208768 crypt aes-xts-plain64 ... 2535680 7:42 2568448
```

**Check:** `crypt02`, `crypt02-overlay` and `crypt02-hotzone-forward` are all
present, and the `crypt02-hotzone-forward` and `crypt02-overlay` segments refer
to the loop device. If `crypt02-overlay` or `crypt02-hotzone-forward` is
missing, the reencryption finished before it was killed. See the timing note in
step 7.

---

### 9. Deactivate the top-level volume `crypt02`

```bash
sudo cmd/secboot-tool/secboot-tool deactivate crypt02
```

Detaches the top of the device-mapper stack. `DeactivateContainerByName` finds
the backing container from `/dev/mapper/crypt02` using
`FindActivatedStorageContainer`, then detaches the mapping by its supplied name.
The caller no longer needs to provide the backing device path.

**Expected:** no output, exit code 0.

**Check:**

```bash
echo "exit code: $?"
sudo dmsetup ls
```

Expected: `crypt02`, `crypt02-overlay` and `crypt02-hotzone-forward` are all gone.
Deactivating the top-level volume should also remove the reencryption mappings
below it. If any remain, record this as a test failure and use the fallback in
step 11 to clean up the unexpected leftovers.

---

### 10. Verify that nothing is left active

```bash
sudo dmsetup ls
sudo dmsetup table | grep crypt02 || echo "no crypt02 mappings"
```

Expected: `dmsetup ls` lists only the system devices, for example:

```
dm_crypt-0	(252:0)
ubuntu--vg-ubuntu--lv	(252:1)
```

and the second command prints `no crypt02 mappings`.

---

### 11. Fallback if a deactivate fails

Run this only if step 9 fails or step 10 shows leftover mappings:

```bash
sudo cryptsetup close crypt02
sudo cryptsetup close crypt02-overlay
sudo cryptsetup close crypt02-hotzone-forward
```

Uses the standard cryptsetup close command, in the same top-down order. Close
only the names that still exist (check with `sudo dmsetup ls`).

After the fallback, check the state again with step 8. If the fallback also
fails, record the error text and the output of:

```bash
sudo dmsetup deps crypt02
sudo dmsetup info -c
sudo dmsetup table
```

`dmsetup deps` shows what each volume depends on, and `dmsetup info -c` shows
the open count of each device. A non-zero open count means something still holds
the device.

---

### 12. Clean up the test environment

```bash
sudo losetup -d $LOOP
```

Detaches the loop device stored in `$LOOP`. Run this only
after all `crypt02*` mappings are gone; otherwise `losetup -d` fails or leaves
the mappings referring to a detached device.

```bash
rm cmd/secboot-tool/cool-test.img
```

Removes the backing image file.

```bash
rm cmd/secboot-tool/secboot-tool
```

Removes the test binary. Skip this if you want to keep the binary.

**Check:**

```bash
sudo losetup -a | grep cool-test || echo "loop device detached"
sudo dmsetup ls
```

---

## Expected results

| Step | Command | Expected outcome |
| --- | --- | --- |
| 1 | `go build` | Builds `cmd/secboot-tool/secboot-tool` with no errors |
| 2 | `truncate -s 8G` | Sparse 8 GiB image |
| 3 | `losetup -f --show` | Prints a loop device path |
| 4 | `cryptsetup luksFormat` | LUKS2 header written |
| 5 | `cryptsetup open` | `crypt02` in `dmsetup ls` |
| 6 | `cryptsetup reencrypt` | Progress output, running until killed |
| 7 | `kill -9` | First terminal prints `Killed` |
| 8 | `dmsetup ls` | `crypt02`, `crypt02-hotzone-forward`, `crypt02-overlay` present, sharing the loop device |
| 9 | `deactivate crypt02` | Exit 0. No `crypt02*` mappings left |
| 10 | `dmsetup ls` | Only `dm_crypt-0` and `ubuntu--vg-ubuntu--lv` |
| 12 | `losetup -d` | Loop device detached |

A failure with `Device or resource busy` in step 9 means something still holds
the device open. Record the error and use the fallback in step 11 if needed.
