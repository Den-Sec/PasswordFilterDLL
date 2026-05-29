;// PasswordFilterDLL - Windows Event Log message catalog.
;// Compiled by mc.exe into messages.h + messages.rc + MSG00001.bin; the resulting
;// message table is linked into the DLL, which the installer registers as the
;// EventMessageFile for the "Den-Sec PasswordFilter" source.

MessageIdTypedef=DWORD

SeverityNames=(
    Success=0x0:STATUS_SEVERITY_SUCCESS
    Informational=0x1:STATUS_SEVERITY_INFORMATIONAL
    Warning=0x2:STATUS_SEVERITY_WARNING
    Error=0x3:STATUS_SEVERITY_ERROR
)

FacilityNames=(
    Filter=0x0:FACILITY_FILTER
)

LanguageNames=(English=0x409:MSG00001)

MessageId=0x1
Severity=Informational
Facility=Filter
SymbolicName=MSG_PASSWORD_REJECTED
Language=English
PasswordFilterDLL rejected a password for account "%1" (operation: %2). Reason: %3.
.

MessageId=0x2
Severity=Informational
Facility=Filter
SymbolicName=MSG_FILTER_INITIALIZED
Language=English
PasswordFilterDLL initialized. Breach checking: %1. Blacklist entries: %2.
.

MessageId=0x3
Severity=Warning
Facility=Filter
SymbolicName=MSG_INTERNAL_ERROR
Language=English
PasswordFilterDLL hit an internal error (%1) and is failing open (allowing the change). Account: "%2".
.

MessageId=0x4
Severity=Warning
Facility=Filter
SymbolicName=MSG_BLOOM_UNAVAILABLE
Language=English
PasswordFilterDLL could not load the breach Bloom filter (%1). Breach checking is disabled until it is available.
.
