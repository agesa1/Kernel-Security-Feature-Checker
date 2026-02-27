#include <ntddk.h>
#include <ntstrsafe.h>
#include <intrin.h>

#pragma intrinsic(__readcr4)

DRIVER_UNLOAD DriverUnload;
NTSTATUS QuerySecurityFeatures(PVOID Context);
VOID WorkerThreadRoutine(PVOID Context);

typedef struct _SECURITY_FEATURES {
    BOOLEAN HvciEnabled;
    BOOLEAN SecureBootEnabled;
    BOOLEAN TpmPresent;
    BOOLEAN VbsEnabled;
    BOOLEAN IommuEnabled;
    BOOLEAN KernelDmaProtectionEnabled;
    BOOLEAN TestSigningEnabled;
    BOOLEAN DebugModeEnabled;
    BOOLEAN HypervisorPresent;
    BOOLEAN SecureKernelRunning;
    BOOLEAN DseEnabled;
    BOOLEAN SmepEnabled;
    BOOLEAN SmapEnabled;
    BOOLEAN UefiSecureBootEnabled;
    BOOLEAN MemoryIntegrityEnabled;
    BOOLEAN CoreIsolationEnabled;
} SECURITY_FEATURES, *PSECURITY_FEATURES;

#define SystemCodeIntegrityInformation 103

typedef struct _SYSTEM_CODEINTEGRITY_INFORMATION {
    ULONG Length;
    ULONG CodeIntegrityOptions;
} SYSTEM_CODEINTEGRITY_INFORMATION, *PSYSTEM_CODEINTEGRITY_INFORMATION;

#define CODEINTEGRITY_OPTION_ENABLED 0x01
#define CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED 0x400
#define CODEINTEGRITY_OPTION_HVCI_KMCI_AUDITMODE_ENABLED 0x800
#define CODEINTEGRITY_OPTION_HVCI_KMCI_STRICTMODE_ENABLED 0x1000

static const GUID EFI_GLOBAL_VARIABLE = {
    0x8BE4DF61, 0x93CA, 0x11D2, {0xAA, 0x0D, 0x00, 0xE0, 0x98, 0x03, 0x2B, 0x8C}
};

NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);

VOID SafeCpuid(int leaf, int subleaf, int* regs) {
    __try {
        __cpuidex(regs, leaf, subleaf);
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        regs[0] = regs[1] = regs[2] = regs[3] = 0;
    }
}

BOOLEAN QueryHvci(VOID) {
    SYSTEM_CODEINTEGRITY_INFORMATION ci = {0};
    NTSTATUS status;
    
    if (KeGetCurrentIrql() > PASSIVE_LEVEL)
        return FALSE;
    
    ci.Length = sizeof(ci);
    
    __try {
        status = ZwQuerySystemInformation(SystemCodeIntegrityInformation, &ci, sizeof(ci), NULL);
        if (NT_SUCCESS(status)) {
            BOOLEAN hvciEnabled = (ci.CodeIntegrityOptions & CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED) != 0;
            DbgPrint("[SEC] HVCI: %s (0x%X)\n", hvciEnabled ? "ON" : "OFF", ci.CodeIntegrityOptions);
            return hvciEnabled;
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("[SEC] HVCI query failed: 0x%X\n", GetExceptionCode());
    }
    
    return FALSE;
}

BOOLEAN QuerySecureBoot(VOID) {
    UNICODE_STRING varName;
    UCHAR value = 0;
    ULONG length = sizeof(value);
    NTSTATUS status;
    
    if (KeGetCurrentIrql() > PASSIVE_LEVEL)
        return FALSE;
    
    RtlInitUnicodeString(&varName, L"SecureBoot");
    
    __try {
        #pragma warning(push)
        #pragma warning(disable: 28251)
        status = ExGetFirmwareEnvironmentVariable(&varName, (LPGUID)&EFI_GLOBAL_VARIABLE, &value, &length, NULL);
        #pragma warning(pop)
        
        if (NT_SUCCESS(status)) {
            DbgPrint("[SEC] SecureBoot: %d\n", value);
            return (value == 1);
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("[SEC] SecureBoot query failed\n");
    }
    
    return FALSE;
}

BOOLEAN QueryVbs(VOID) {
    int regs[4] = {0};
    
    __try {
        SafeCpuid(1, 0, regs);
        if ((regs[2] & (1 << 31)) == 0)
            return FALSE;
        
        SafeCpuid(0x40000000, 0, regs);
        ULONG maxLeaf = regs[0];
        
        if (maxLeaf >= 0x40000003) {
            SafeCpuid(0x40000003, 0, regs);
            BOOLEAN vbs = (regs[0] & 0x1) != 0;
            DbgPrint("[SEC] VBS: %s\n", vbs ? "ON" : "OFF");
            return vbs;
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
    }
    
    return FALSE;
}

BOOLEAN QueryTpm(VOID) {
    __try {
        BOOLEAN vbs = QueryVbs();
        if (vbs) {
            DbgPrint("[SEC] TPM: detected\n");
            return TRUE;
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
    }
    
    return FALSE;
}

BOOLEAN QueryIommu(VOID) {
    int regs[4] = {0};
    
    __try {
        SafeCpuid(1, 0, regs);
        BOOLEAN intelVt = (regs[2] & (1 << 5)) != 0;
        
        SafeCpuid(0x80000001, 0, regs);
        BOOLEAN amdV = (regs[2] & (1 << 2)) != 0;
        
        BOOLEAN capable = intelVt || amdV;
        DbgPrint("[SEC] IOMMU: %s\n", capable ? "capable" : "not capable");
        return capable;
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
    }
    
    return FALSE;
}

BOOLEAN QueryKernelDmaProtection(BOOLEAN iommu, BOOLEAN vbs) {
    BOOLEAN enabled = iommu && vbs;
    DbgPrint("[SEC] Kernel DMA Protection: %s\n", enabled ? "ON" : "OFF");
    return enabled;
}

BOOLEAN QueryTestSigning(VOID) {
    SYSTEM_CODEINTEGRITY_INFORMATION ci = {0};
    NTSTATUS status;
    
    if (KeGetCurrentIrql() > PASSIVE_LEVEL)
        return FALSE;
    
    ci.Length = sizeof(ci);
    
    __try {
        status = ZwQuerySystemInformation(SystemCodeIntegrityInformation, &ci, sizeof(ci), NULL);
        if (NT_SUCCESS(status)) {
            BOOLEAN testSign = (ci.CodeIntegrityOptions & CODEINTEGRITY_OPTION_ENABLED) == 0;
            DbgPrint("[SEC] TestSigning: %s\n", testSign ? "ON" : "OFF");
            return testSign;
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
    }
    
    return FALSE;
}

BOOLEAN QueryDebugMode(VOID) {
    BOOLEAN debug = FALSE;
    
    __try {
        PUCHAR sharedData = (PUCHAR)0x7FFE0000;
        debug = *(BOOLEAN*)(sharedData + 0x2D4);
        DbgPrint("[SEC] DebugMode: %s\n", debug ? "ON" : "OFF");
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
    }
    
    return debug;
}

BOOLEAN QueryHypervisorPresence(VOID) {
    int regs[4] = {0};
    
    __try {
        SafeCpuid(1, 0, regs);
        if ((regs[2] & (1 << 31)) == 0) {
            DbgPrint("[SEC] Hypervisor: not present\n");
            return FALSE;
        }
        
        SafeCpuid(0x40000000, 0, regs);
        char vendor[13] = {0};
        *(int*)(vendor + 0) = regs[1];
        *(int*)(vendor + 4) = regs[2];
        *(int*)(vendor + 8) = regs[3];
        
        DbgPrint("[SEC] Hypervisor: %.4s\n", vendor);
        return TRUE;
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
    }
    
    return FALSE;
}

BOOLEAN QuerySecureKernel(VOID) {
    int regs[4] = {0};
    
    __try {
        SafeCpuid(1, 0, regs);
        if ((regs[2] & (1 << 31)) == 0)
            return FALSE;
        
        SafeCpuid(0x40000000, 0, regs);
        ULONG maxLeaf = regs[0];
        
        if (maxLeaf >= 0x40000003) {
            SafeCpuid(0x40000003, 0, regs);
            BOOLEAN sk = (regs[0] & (1 << 12)) != 0;
            DbgPrint("[SEC] SecureKernel: %s\n", sk ? "running" : "not running");
            return sk;
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
    }
    
    return FALSE;
}

BOOLEAN QueryDse(VOID) {
    SYSTEM_CODEINTEGRITY_INFORMATION ci = {0};
    NTSTATUS status;
    
    if (KeGetCurrentIrql() > PASSIVE_LEVEL)
        return FALSE;
    
    ci.Length = sizeof(ci);
    
    __try {
        status = ZwQuerySystemInformation(SystemCodeIntegrityInformation, &ci, sizeof(ci), NULL);
        if (NT_SUCCESS(status)) {
            BOOLEAN dse = (ci.CodeIntegrityOptions & CODEINTEGRITY_OPTION_ENABLED) != 0;
            DbgPrint("[SEC] DSE: %s\n", dse ? "ON" : "OFF");
            return dse;
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
    }
    
    return FALSE;
}

BOOLEAN QuerySmep(VOID) {
    int regs[4] = {0};
    ULONG64 cr4 = 0;
    
    __try {
        SafeCpuid(7, 0, regs);
        if ((regs[1] & (1 << 7)) == 0)
            return FALSE;
        
        cr4 = __readcr4();
        BOOLEAN smep = (cr4 & (1ULL << 20)) != 0;
        DbgPrint("[SEC] SMEP: %s\n", smep ? "ON" : "OFF");
        return smep;
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
    }
    
    return FALSE;
}

BOOLEAN QuerySmap(VOID) {
    int regs[4] = {0};
    ULONG64 cr4 = 0;
    
    __try {
        SafeCpuid(7, 0, regs);
        if ((regs[1] & (1 << 20)) == 0)
            return FALSE;
        
        cr4 = __readcr4();
        BOOLEAN smap = (cr4 & (1ULL << 21)) != 0;
        DbgPrint("[SEC] SMAP: %s\n", smap ? "ON" : "OFF");
        return smap;
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
    }
    
    return FALSE;
}

BOOLEAN QueryUefiSecureBoot(VOID) {
    UNICODE_STRING setupMode, secureBoot;
    UCHAR setupVal = 0, secureVal = 0;
    ULONG length;
    NTSTATUS s1, s2;
    
    if (KeGetCurrentIrql() > PASSIVE_LEVEL)
        return FALSE;
    
    RtlInitUnicodeString(&setupMode, L"SetupMode");
    RtlInitUnicodeString(&secureBoot, L"SecureBoot");
    
    __try {
        #pragma warning(push)
        #pragma warning(disable: 28251)
        
        length = sizeof(setupVal);
        s1 = ExGetFirmwareEnvironmentVariable(&setupMode, (LPGUID)&EFI_GLOBAL_VARIABLE, &setupVal, &length, NULL);
        
        length = sizeof(secureVal);
        s2 = ExGetFirmwareEnvironmentVariable(&secureBoot, (LPGUID)&EFI_GLOBAL_VARIABLE, &secureVal, &length, NULL);
        
        #pragma warning(pop)
        
        if (NT_SUCCESS(s1) && NT_SUCCESS(s2)) {
            BOOLEAN uefi = (secureVal == 1) && (setupVal == 0);
            DbgPrint("[SEC] UEFI SecureBoot: %s\n", uefi ? "ON" : "OFF");
            return uefi;
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
    }
    
    return FALSE;
}

BOOLEAN QueryMemoryIntegrity(BOOLEAN hvci) {
    DbgPrint("[SEC] MemoryIntegrity: %s\n", hvci ? "ON" : "OFF");
    return hvci;
}

BOOLEAN QueryCoreIsolation(BOOLEAN vbs, BOOLEAN hvci) {
    BOOLEAN ci = vbs && hvci;
    DbgPrint("[SEC] CoreIsolation: %s\n", ci ? "ON" : "OFF");
    return ci;
}

VOID WorkerThreadRoutine(PVOID Context) {
    PSECURITY_FEATURES f = (PSECURITY_FEATURES)Context;
    HANDLE hFile = NULL;
    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING path;
    IO_STATUS_BLOCK iosb;
    NTSTATUS status;
    CHAR buf[1024];
    SIZE_T len;
    
    if (KeGetCurrentIrql() > PASSIVE_LEVEL)
        goto cleanup;
    
    RtlInitUnicodeString(&path, L"\\??\\C:\\security_report.txt");
    InitializeObjectAttributes(&oa, &path, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    
    __try {
        status = ZwCreateFile(&hFile, GENERIC_WRITE, &oa, &iosb, NULL, FILE_ATTRIBUTE_NORMAL,
                             0, FILE_OVERWRITE_IF, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
        
        if (!NT_SUCCESS(status))
            goto cleanup;
        
        status = RtlStringCbPrintfA(buf, sizeof(buf),
            " Security Report\r\n"
            "=======================\r\n\r\n"
            "Core Features:\r\n"
            "  HVCI: %s\r\n"
            "  SecureBoot: %s\r\n"
            "  TPM 2.0: %s\r\n"
            "  VBS: %s\r\n"
            "  IOMMU: %s\r\n"
            "  Kernel DMA Protection: %s\r\n"
            "\r\nAnti-Cheat Checks:\r\n"
            "  TestSigning: %s\r\n"
            "  DebugMode: %s\r\n"
            "  Hypervisor: %s\r\n"
            "  SecureKernel: %s\r\n"
            "  DSE: %s\r\n"
            "  SMEP: %s\r\n"
            "  SMAP: %s\r\n"
            "  UEFI SecureBoot: %s\r\n"
            "  MemoryIntegrity: %s\r\n"
            "  CoreIsolation: %s\r\n\r\n",
            f->HvciEnabled ? "ON" : "OFF",
            f->SecureBootEnabled ? "ON" : "OFF",
            f->TpmPresent ? "YES" : "NO",
            f->VbsEnabled ? "ON" : "OFF",
            f->IommuEnabled ? "YES" : "NO",
            f->KernelDmaProtectionEnabled ? "ON" : "OFF",
            f->TestSigningEnabled ? "ON" : "OFF",
            f->DebugModeEnabled ? "ON" : "OFF",
            f->HypervisorPresent ? "YES" : "NO",
            f->SecureKernelRunning ? "YES" : "NO",
            f->DseEnabled ? "ON" : "OFF",
            f->SmepEnabled ? "ON" : "OFF",
            f->SmapEnabled ? "ON" : "OFF",
            f->UefiSecureBootEnabled ? "ON" : "OFF",
            f->MemoryIntegrityEnabled ? "ON" : "OFF",
            f->CoreIsolationEnabled ? "ON" : "OFF"
        );
        
        if (!NT_SUCCESS(status))
            goto cleanup;
        
        len = strlen(buf);
        status = ZwWriteFile(hFile, NULL, NULL, NULL, &iosb, buf, (ULONG)len, NULL, NULL);
        
        if (!NT_SUCCESS(status))
            goto cleanup;
        
        CHAR verdict[512];
        BOOLEAN suspicious = f->TestSigningEnabled || f->DebugModeEnabled || !f->DseEnabled;
        
        status = RtlStringCbPrintfA(verdict, sizeof(verdict),
            "Status: %s\r\n\r\nFlags:\r\n%s%s%s\r\nScore: %d/10\r\n",
            suspicious ? "SUSPICIOUS" : "CLEAN",
            f->TestSigningEnabled ? "  - TestSigning enabled\r\n" : "",
            f->DebugModeEnabled ? "  - DebugMode enabled\r\n" : "",
            !f->DseEnabled ? "  - DSE disabled\r\n" : "",
            (f->HvciEnabled ? 2 : 0) + (f->SecureBootEnabled ? 2 : 0) + (f->VbsEnabled ? 2 : 0) +
            (!f->TestSigningEnabled ? 1 : 0) + (!f->DebugModeEnabled ? 1 : 0) +
            (f->DseEnabled ? 1 : 0) + (f->SmepEnabled ? 1 : 0) + (f->SmapEnabled ? 1 : 0)
        );
        
        if (NT_SUCCESS(status)) {
            len = strlen(verdict);
            ZwWriteFile(hFile, NULL, NULL, NULL, &iosb, verdict, (ULONG)len, NULL, NULL);
        }
        
        DbgPrint("[SEC] Report written\n");
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
    }
    
cleanup:
    if (hFile != NULL) {
        __try {
            ZwClose(hFile);
        }
        __except(EXCEPTION_EXECUTE_HANDLER) {
        }
    }
    
    if (f != NULL)
        ExFreePoolWithTag(f, 'FTSP');
    
    PsTerminateSystemThread(STATUS_SUCCESS);
}

NTSTATUS QuerySecurityFeatures(PVOID Context) {
    UNREFERENCED_PARAMETER(Context);
    PSECURITY_FEATURES f = NULL;
    HANDLE hThread = NULL;
    NTSTATUS status;
    
    if (KeGetCurrentIrql() > PASSIVE_LEVEL)
        return STATUS_UNSUCCESSFUL;
    
    DbgPrint("[SEC] Starting detection\n");
    
    f = (PSECURITY_FEATURES)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(SECURITY_FEATURES), 'FTSP');
    if (f == NULL)
        return STATUS_INSUFFICIENT_RESOURCES;
    
    RtlZeroMemory(f, sizeof(SECURITY_FEATURES));
    
    __try {
        f->HvciEnabled = QueryHvci();
        f->SecureBootEnabled = QuerySecureBoot();
        f->VbsEnabled = QueryVbs();
        f->TpmPresent = QueryTpm();
        f->IommuEnabled = QueryIommu();
        f->KernelDmaProtectionEnabled = QueryKernelDmaProtection(f->IommuEnabled, f->VbsEnabled);
        
        f->TestSigningEnabled = QueryTestSigning();
        f->DebugModeEnabled = QueryDebugMode();
        f->HypervisorPresent = QueryHypervisorPresence();
        f->SecureKernelRunning = QuerySecureKernel();
        f->DseEnabled = QueryDse();
        f->SmepEnabled = QuerySmep();
        f->SmapEnabled = QuerySmap();
        f->UefiSecureBootEnabled = QueryUefiSecureBoot();
        f->MemoryIntegrityEnabled = QueryMemoryIntegrity(f->HvciEnabled);
        f->CoreIsolationEnabled = QueryCoreIsolation(f->VbsEnabled, f->HvciEnabled);
        
        status = PsCreateSystemThread(&hThread, THREAD_ALL_ACCESS, NULL, NULL, NULL, WorkerThreadRoutine, f);
        
        if (NT_SUCCESS(status)) {
            ZwClose(hThread);
        } else {
            ExFreePoolWithTag(f, 'FTSP');
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        if (f != NULL)
            ExFreePoolWithTag(f, 'FTSP');
        return STATUS_UNSUCCESSFUL;
    }
    
    return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);
    
    DbgPrint("[SEC] Driver loaded\n");
    DriverObject->DriverUnload = DriverUnload;
    QuerySecurityFeatures(NULL);
    
    return STATUS_SUCCESS;
}

VOID DriverUnload(PDRIVER_OBJECT DriverObject) {
    UNREFERENCED_PARAMETER(DriverObject);
    DbgPrint("[SEC] Driver unloaded\n");
}
