# Kernel-Security-Feature-Checker

Example log output;

 Security Features Report
=================================

=== CORE SECURITY FEATURES ===
HVCI (Hypervisor-Protected Code Integrity): DISABLED
Secure Boot: ENABLED
TPM 2.0: PRESENT
VBS (Virtualization-Based Security): ENABLED
IOMMU / DMA Protection: NOT CAPABLE
Kernel DMA Protection: DISABLED

=== ANTI-CHEAT CRITICAL CHECKS ===
Test Signing Mode: DISABLED
Debug Mode (bcdedit /debug): DISABLED
Hypervisor Present: PRESENT
Secure Kernel Running: RUNNING
DSE (Driver Signature Enforcement): ENABLED
SMEP (Supervisor Mode Execution Prevention): ENABLED
SMAP (Supervisor Mode Access Prevention): ENABLED
UEFI Secure Boot: ENABLED
Memory Integrity: DISABLED
Core Isolation: DISABLED

=== ANTI-CHEAT VERDICT ===
System Status: CLEAN - Anti-cheat compatible

Red Flags:

Security Score: 9/10
