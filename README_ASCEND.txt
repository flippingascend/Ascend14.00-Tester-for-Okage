# ASCEND PS5 14.00 Network ELF Loader
## Okage Shadow King (CUSA02199) Save Exploit Package

---

### OVERVIEW
This package contains everything needed to run homebrew ELF payloads on PS5 firmware 14.00 via the Okage Shadow King PS2 emulator save exploit.

**Exploit Chain:**
1. Save-game stack overflow in PS2 emulator (player name field in `bkmo0.dat`)
2. Stage 1 MIPS shellcode → overwrites return address → jumps to `0x01ffe9b4`
3. Stage 2 MIPS shellcode → sets up ARM64 ROP chain
4. ARM64 ROP → leaks EBOOT/libkernel/stack addresses → calls kernel syscalls
5. Network listener opens on port 9045 → receives ELF from PC → executes

**Current Status:** Full chain working EXCEPT `LIB_KERNEL_SYS_RET_ERROR` offset for 14.00 (syscall entry stub). Scan12 ELF finds this at runtime.

---

### NETWORK SETUP
```
PS5 IP (router):      192.168.0.117
PS5 IP (direct):      192.168.137.102
PC IP:                192.168.0.189
Loader Port:          9045
DNS Blocker Port:     53 (runs AFTER loader dialog appears)
```

---

### DIRECTORY STRUCTURE
```
ASCEND_FINAL/
├── okage_save/           # Complete VMC save images (8,650,752 bytes each)
│   ├── VMC0.card                                              # Original working save
│   ├── VMC0.card.lightbar-stage1                              # ✅ WORKS - proves ROP on 14.00 (orange lightbar)
│   ├── VMC0.card.test-dialog                                  # ✅ WORKS - shows dialog "deadbeefcafebabe"
│   ├── VMC0.card.scan12-stub-search-64KB-5patterns-FINAL      # 🎯 TEST THIS - scanner for LIB_KERNEL_SYS_RET_ERROR
│   ├── VMC0.card.scan01-stub-search-4KB
│   ├── VMC0.card.scan02-stub-search-8KB
│   ├── VMC0.card.scan03-stub-search-16KB-loop-freeze
│   ├── VMC0.card.scan04-stub-search-32KB
│   ├── VMC0.card.scan05-stub-search-64KB
│   ├── VMC0.card.scan06-stub-search-128KB
│   ├── VMC0.card.scan07-stub-search-256KB
│   ├── VMC0.card.scan08-stub-search-512KB
│   ├── VMC0.card.scan09-stub-search-1MB
│   ├── VMC0.card.scan10-stub-search-2MB-loop-freeze
│   └── VMC0.card.scan11-stub-search-centered-128KB
├── PAYLOADS/             # Compiled ELF payloads (PS5 0.00 hybrid build)
│   ├── ps-lightbar-PS5-0-00.elf       # 56,500 bytes - lightbar test
│   ├── ps-notification-PS5-0-00.elf   # 56,580 bytes - notification test
│   ├── ps-test-dialog-PS5-0-00.elf    # 61,776 bytes - dialog test
│   ├── ps-syscall-scan-PS5-0-00.elf   # 63,960 bytes - scanner (in scan12 save)
│   └── ps-blank-PS5-0-00.elf          # 1,284 bytes - minimal payload
├── psn-dns-blocker/      # DNS blocker for PSN domains
│   ├── psn_block_dns.py       # Main blocker (13 rules, blocks PSN)
│   ├── blocklist.txt          # Domains to block
│   └── allowlist.txt          # Domains to allow
├── SEND_ELF.bat            # Sends ELF to PS5 (port 9045)
├── send_elf.py             # Python ELF sender (correct framing, large writes)
├── RUN_DNS.bat             # DNS blocker launcher (auto-elevates, Python detect)
└── README_ASCEND.txt       # This file
```

---

### WORKING SAVES (TESTED ON 14.00)
| Save File | Purpose | Result |
|-----------|---------|--------|
| `VMC0.card.lightbar-stage1` | Stage 1 lightbar test | ✅ Orange lightbar |
| `VMC0.card.test-dialog` | Dialog system test | ✅ Shows "deadbeefcafebabe" |

**Use these as packaging references** — they load correctly and produce debug output.

---

### SCAN HISTORY (All Tested on PS5 14.00)

| Save File | Scan Range | Patterns | Result | Notes |
|-----------|------------|----------|--------|-------|
| `VMC0.card.scan01-stub-search-4KB` | ±4KB | 1 (mov rax) | ❌ NO MATCH | First attempt, range too narrow |
| `VMC0.card.scan02-stub-search-8KB` | ±8KB | 1 (mov rax) | ❌ NO MATCH | Still narrow |
| `VMC0.card.scan03-stub-search-16KB-loop-freeze` | ±16KB | 1 (mov rax) | 💥 **CRASH/FREEZE** | ROP loop too large, PS5 hung, no output |
| `VMC0.card.scan04-stub-search-32KB` | ±32KB | 1 (mov rax) | ❌ NO MATCH | |
| `VMC0.card.scan05-stub-search-64KB` | ±64KB | 1 (mov rax) | ❌ NO MATCH | |
| `VMC0.card.scan06-stub-search-128KB` | ±128KB | 1 (mov rax) | ❌ NO MATCH | |
| `VMC0.card.scan07-stub-search-256KB` | ±256KB | 1 (mov rax) | ❌ NO MATCH | |
| `VMC0.card.scan08-stub-search-512KB` | ±512KB | 1 (mov rax) | ❌ NO MATCH | |
| `VMC0.card.scan09-stub-search-1MB` | ±1MB | 1 (mov rax) | ❌ NO MATCH | Wide but single pattern |
| `VMC0.card.scan10-stub-search-2MB-loop-freeze` | ±2MB | 1 (mov rax) | 💥 **CRASH/FREEZE** | Loop way too big, ROP chain overflow |
| `VMC0.card.scan11-stub-search-centered-128KB` | ±128KB centered | 1 (mov rax), step 0x200 | ❌ NO MATCH | Dialog showed: `stub 0x8117a3b20 NO MATCH (scanned f1)` |
| `VMC0.card.scan12-stub-search-64KB-5patterns-FINAL` | ±64KB | **5 patterns** | 🎯 **PENDING TEST** | Multi-pattern, reports all matches via dialog |

**Key Findings:**
- **scan03 & scan10 froze** — ROP chain loop too large for stack space
- **scan11 ran but found nothing** — dialog confirmed "NO MATCH" at scanned address
- **All prior scans used only pattern 1** (`mov rax, imm32; syscall; ret`) — may be wrong pattern for 14.00
- **scan12 is first with 5 patterns** — covers `mov eax`, `syscall;ret`, `mov r10/rcx`, and wildcard
- **Working saves (lightbar-stage1, test-dialog) always show `Okage::printf` debug BEFORE any crash** — scan12 crash = packaging issue, not exploit issue

---

### SCAN12 — THE KEY TEST
**File:** `okage_save/VMC0.card.scan12-stub-search-64KB-5patterns-FINAL` (8,650,752 bytes)
**ELF:** `PAYLOADS/ps-syscall-scan-PS5-0-00.elf` (63,960 bytes)

**What it does:**
- Scans ±64KB around error stub (`EBOOT_ERROR_STUB_PTR = 0x083cfa0`)
- Checks 5 syscall patterns:
  1. `mov rax, imm32; syscall; ret` (15 bytes)
  2. `mov eax, imm32; syscall; ret` (10 bytes) ← **THIS ONE gives syscall number**
  3. `syscall; ret` (3 bytes)
  4. `mov r10, rcx; mov eax, imm32; syscall; ret` (13 bytes)
  5. Any `syscall; ret` within 32 bytes
- Reports all matches via `Okage::printf` (on-screen) AND dialog

**Expected Output:**
```
stub=0xXXXXXXXXXXXX range=0xXXXXXXXXXX-0xXXXXXXXXXX
P2 @0xXXXXXXXXXXXX num=0x14
```
- `P2` = pattern 2 (`mov eax, imm32; syscall; ret`)
- `num=0xXX` = **`LIB_KERNEL_SYS_RET_ERROR` syscall number for 14.00**

---

### HOW TO TEST SCAN12

1. **Upload to Discord bot** (or your save signer):
   - Send `okage_save/VMC0.card.scan12-stub-search-64KB-5patterns-FINAL` as `VMC0.card`
   - Download signed save

2. **Transfer to PS5:**
   - Copy signed `VMC0.card` to PS5 save slot (USB or network)
   - Path: `/user/savedata/<slot>/VMC0.card`

3. **Run on PS5:**
   - Start Okage Shadow King
   - Load the save slot
   - Watch screen for `Okage::printf` output
   - Dialog will appear with "SCAN12 RESULT"

4. **Report results:**
   - Paste the `stub=...` line
   - Paste any `P# @0x... num=0x...` matches

---

### AFTER SCAN12 SUCCESS

If scan finds `num=0xXXXX` (pattern 2):

1. **Patch SDK:**
   ```bash
   # Edit /home/bigal/mast1c0re/sdk/include/offsets/ps/libkernel.hpp
   # Change FIRMWARE == 0 branch:
   # #define LIB_KERNEL_SYS_RET_ERROR 0xXXXX  # <- use found value
   ```

2. **Rebuild network loader:**
   ```bash
   cd /home/bigal/mast1c0re-ps2-network-elf-loader/samples/ps-tcp-server
   make SYSTEM=PS5 FIRMWARE=0.00
   ```

3. **Run full loader:**
   - Start DNS blocker: `RUN_DNS.bat` (run as admin)
   - Start listener: `SEND_ELF.bat` (waits for connection)
   - Trigger exploit with network loader save
   - Port 9045 opens → send any ELF

---

### DNS BLOCKER USAGE
```cmd
RUN_DNS.bat
```
- Self-elevates to admin
- Auto-detects Python
- Blocks 13 PSN domains (see `blocklist.txt`)
- Run AFTER loader dialog appears on PS5

---

### ELF SENDER USAGE
```cmd
SEND_ELF.bat <ELF_FILE> [PS5_IP] [PORT]
```
Example:
```cmd
SEND_ELF.bat PAYLOADS\ps-lightbar-PS5-0-00.elf 192.168.0.117 9045
```
- Correct framing protocol
- Handles large writes
- Defaults: PS5_IP=192.168.0.117, PORT=9045

---

### BUILD ENVIRONMENT (WSL Ubuntu)
```bash
export PS2DEV=/usr/local/ps2dev
export PATH="$PATH:$PS2DEV/ee/bin:$PS2DEV/iop/bin:$PS2DEV/dvp/bin"
export MAST1C0RE=/home/bigal/mast1c0re

# Build SDK for PS5 0.00 (hybrid 6.50 offsets)
cd /home/bigal/mast1c0re/sdk
PATH="/usr/bin:/usr/local/ps2dev/ee/bin:$PATH" make SYSTEM=PS5 FIRMWARE=000 EBOOT=101

# Build payloads
cd /home/bigal/mast1c0re-ps2-network-elf-loader/samples/ps-<payload>
PATH="/usr/bin:/usr/local/ps2dev/ee/bin:$PATH" make SYSTEM=PS5 FIRMWARE=0.00
```

**Cross-compiler:** `/usr/local/ps2dev/ee/bin/mips64r5900el-ps2-elf-g++`

---

### PACKER: okrager
**Location:** `/home/bigal/.local/share/pipx/venvs/okrager/lib/python3.14/site-packages/okrager/`

**Process:**
1. Export save as PSU (via mymcplus)
2. Inject stage1/stage2 into `bkmo0.dat` at `NAME_OFFSET=0x844`
3. Update CRC (`!crc` header at offset 0, checksum at offset 8)
4. Write ELF as `program.elf` with 4-byte length prefix
5. Re-import to VMC image

**Key files:**
- `injector.py` — stage1/stage2 injection logic
- `mymc.py` — mymcplus wrapper
- `CRC.py` — CRC calculation

---

### KNOWN OFFSETS (PS5 14.00 / EBOOT 1.01)
```c
// EBOOT offsets (from sdk/include/offsets/ps/eboot/1.01.hpp)
EBOOT_ERROR_STUB_PTR           = 0x083cfa0
EBOOT_SCE_KERNEL_USLEEP_STUB_PTR = 0x083d1c0
IO_REGISTER_READ_HANDLERS      = 0x060e7880
INTERRUPT_WRITE_HANDLERS       = 0x00ae7d98

// Libkernel (6.50 values used in hybrid 0.00 build)
LIB_KERNEL_SYS_RET_ERROR       = 0x35f6  // 6.50 value — NEED 14.00 VALUE
```

---

### TROUBLESHOOTING

**Save crashes instantly (no debug output):**
- VMC image structurally invalid (bad CRC, wrong bkmo0.dat format)
- Compare with working save (`lightbar-stage1`) using hex editor
- Check `bkmo0.dat` CRC and `program.elf` embedding

**No network connection:**
- DNS blocker not running or wrong timing
- PS5/PC on different subnets (use direct IP 192.168.137.102)
- Port 9045 blocked by firewall

**ELF send fails:**
- Loader not listening (wrong `LIB_KERNEL_SYS_RET_ERROR`)
- Try `ps-lightbar-PS5-0-00.elf` first (proven payload)

---

### CREDITS
- **Ascend** — PS5 research & exploit development
- **mast1c0re** — SDK & ROP framework
- **okrager** — Save packer/injector
- **mymcplus** — PS2 save manipulation
- **PS2DEV** — MIPS cross-compiler toolchain

---

### CONTACT
For questions or contributions, reach out in the Ascend Discord.

**Last Updated:** October 5, 2026
**Firmware Target:** PS5 14.00
**Game:** Okage Shadow King (CUSA02199 / SCUS-97129)