# Kernel-Security-Feature-Checker

Example log output;

# Windows Security Features Detection Driver

A Windows Kernel-Mode Driver (WDM) that detects security features using direct hardware queries and kernel APIs. Includes all checks performed by modern anti-cheat systems (EasyAntiCheat, BattlEye, Vanguard, FACEIT).

## Features Detected

### Core Security Features
- **HVCI** (Hypervisor-Protected Code Integrity) - via `NtQuerySystemInformation`
- **Secure Boot** - via EFI runtime variable query
- **TPM 2.0** - presence detection via VBS correlation
- **VBS** (Virtualization-Based Security) - via CPUID hypervisor queries
- **IOMMU/DMA Protection** - via CPUID virtualization extensions
- **Kernel DMA Protection** - derived from IOMMU + VBS state

### Anti-Cheat Critical Checks
- **Test Signing Mode** - detects unsigned driver loading capability
- **Debug Mode** - detects bcdedit /debug enablement
- **Hypervisor Presence** - detects VM/hypervisor environments
- **Secure Kernel** - detects Isolated User Mode (IUM)
- **DSE** (Driver Signature Enforcement) - critical for anti-cheat
- **SMEP** (Supervisor Mode Execution Prevention) - CPU security feature
- **SMAP** (Supervisor Mode Access Prevention) - CPU security feature
- **UEFI Secure Boot** - detailed UEFI security state
- **Memory Integrity** - explicit HVCI check
- **Core Isolation** - combined VBS + HVCI state

## Anti-Cheat Compatibility

The driver generates a security score (0-10) and identifies red flags that would cause anti-cheat systems to block:

🚫 **Blocking Conditions:**
- Test signing enabled
- Debug mode enabled
- Kernel debugger attached
- DSE (Driver Signature Enforcement) disabled

✅ **Optimal Configuration:**
- HVCI enabled
- Secure Boot enabled
- VBS enabled
- DSE enabled
- No debuggers attached
- Test signing disabled

## Technical Implementation

- Zero registry access (no `ZwOpenKey`/`ZwQueryValueKey`)
- All queries at IRQL ≤ PASSIVE_LEVEL
- Full exception handling with `__try`/`__except`
- Proper resource cleanup in all code paths
- Results written to `C:\security_report.txt` via system worker thread
- Compiled with `/W4 /WX` (warnings as errors)

## Build Requirements

- Windows Driver Kit (WDK) 10
- Visual Studio 2019 or later
- Windows 10 SDK

## Build Instructions

1. Open `pte.sln` in Visual Studio
2. Select **Release | x64** configuration
3. Build → Build Solution (F7)
4. Output: `x64\Release\pte.sys`

## Deployment

### Enable Test Signing (Required for unsigned drivers)

```cmd
bcdedit /set testsigning on
```

Reboot required.

### Install Driver

```cmd
sc create pte type= kernel binPath= C:\path\to\pte.sys
sc start pte
```

### View Results

Check `C:\security_report.txt` for the detection report.

Example output:
```
Windows Security Features Report
=================================

=== CORE SECURITY FEATURES ===
HVCI (Hypervisor-Protected Code Integrity): ENABLED
Secure Boot: ENABLED
TPM 2.0: PRESENT
VBS (Virtualization-Based Security): ENABLED
IOMMU / DMA Protection: CAPABLE
Credential Guard: ENABLED
Kernel DMA Protection: ENABLED

=== ANTI-CHEAT CRITICAL CHECKS ===
Test Signing Mode: DISABLED
Debug Mode (bcdedit /debug): DISABLED
Kernel Debugger Present: NOT PRESENT
Hypervisor Present: PRESENT
Secure Kernel Running: RUNNING
DSE (Driver Signature Enforcement): ENABLED
SMEP (Supervisor Mode Execution Prevention): ENABLED
SMAP (Supervisor Mode Access Prevention): ENABLED
UEFI Secure Boot: ENABLED
Windows Defender: ACTIVE
Memory Integrity: ENABLED
Core Isolation: ENABLED

=== ANTI-CHEAT VERDICT ===
System Status: CLEAN - Anti-cheat compatible

Red Flags:
(none)

Security Score: 10/10
```

### Debug Output

Use DebugView or WinDbg to see `DbgPrint` output:

```
[PTE] Driver loaded
[PTE] HVCI: ENABLED (Options: 0x401)
[PTE] Secure Boot: ENABLED (Value: 1)
[PTE] VBS: ENABLED (Features: 0x1)
[PTE] Test Signing: DISABLED
[PTE] Debug Mode: DISABLED
[PTE] Kernel Debugger: NOT PRESENT
[PTE] SMEP: ENABLED
[PTE] SMAP: ENABLED
...
```

### Uninstall

```cmd
sc stop pte
sc delete pte
```

## Driver Verifier

Test with Driver Verifier enabled:

```cmd
verifier /standard /driver pte.sys
```

## Compatibility

- Windows 10 20H1+ (Build 19041+)
- Windows 11 (all versions)
- x64 architecture only

## Safety Features

- All pointer dereferences guarded
- IRQL checks before PASSIVE_LEVEL operations
- Proper object lifecycle management
- No BSOD risk under normal operation
- Handles closed in both success and failure paths

## Anti-Cheat Systems Covered

This driver detects all security features checked by:
- **EasyAntiCheat** (Epic Games)
- **BattlEye** (BattlEye Innovations)
- **Vanguard** (Riot Games)
- **FACEIT Anti-Cheat**
- **Valve Anti-Cheat (VAC)**
- **PunkBuster**

## Limitations

- TPM detection is heuristic-based (inferred from VBS state)
- IOMMU detection checks CPU capability, not ACPI table parsing
- Requires administrative privileges to load

## License

Educational/research purposes only.

