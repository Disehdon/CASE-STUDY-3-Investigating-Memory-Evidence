# SBT-DF204 — Case Study 3: Investigating Suspected Illegal File Transfer From Memory Evidence

Forensic examination of a Windows 7 memory image — Volatility 2 analysis of USB device connection, command history, and user profile evidence to reconstruct a suspected file exfiltration.

---

## Author

| Field | Detail |
| :--- | :--- |
| **Student** | Ibrahim Diseh Garba |
| **Registration No.** | `2025/FWSD/11521` |
| **Programme** | Fellowship in Web Application Security & Digital Forensics |
| **Institution** | International Cybersecurity and Digital Forensics Academy (ICDFA) |
| **Course** | SBT-DF204 — Computer Forensics Case Studies |
| **Instructor** | Aminu Idris, AMCPN |
| **Batch** | BATCH-B2025 · L1/S2 |
| **Case Reference** | `SBT-DF204-CS3-2025-FWSD-11521` |
| **Submission Date** | 18 October 2026 |

---

## Overview

This repository contains the complete forensic analysis of a Windows 7 x86 (PAE) raw physical memory image (`memdumpWin7.mem`) supplied as part of the **SBT-DF204 Case Study 3** investigation.

The case hypothesis is that a confidential document (`secret_file.docx`) was transferred from a workstation's Downloads folder to an unauthorized removable USB device. Using **Volatility 2.6.1**, the investigation reconstructs a time-ordered sequence of artefacts across process execution, command history, USB registry records, drive mappings, and File Explorer ShellBags.

**Critical scope note:** Memory forensics proves that an action occurred within a specific user profile; it does **not** prove the physical presence of a specific human operator. The report grades confidence accordingly, distinguishing between high-confidence artefact sequences and lower-confidence personal attribution.

---

## Objectives

1. Acquire and preserve the supplied memory image with a documented SHA-256 and verified read-only working copy.
2. Identify the correct Volatility profile from the actual image output rather than assuming from screenshots.
3. Examine processes, network artefacts, command history, USB registry records, drive mappings, and ShellBag traces.
4. Reconstruct a chronological UTC timeline linking the browser download, folder access, USB attachment, drive mounting, and command execution.
5. Distinguish direct observations from inferences about the transfer.
6. State a cautious conclusion with confidence level and at least three limitations.

---

## Environment

| Component | Value |
| :--- | :--- |
| Operating System | Kali Linux (rolling) |
| Memory Framework | Volatility 2.6.1 |
| Python Runtime | Python 2.7.18 |
| Crypto Library | pycryptodome 3.23.0 |
| Disassembler | distorm3 3.5.2 |
| Evidence Item | `memdumpWin7.mem` (1,073,676,288 bytes) |
| Analysis Mode | Offline only — no live endpoints contacted |

---

## Methodology

| Step | Action | Plugin / Command |
| :---: | :--- | :--- |
| 1 | Verify image profile | `imageinfo` |
| 2 | List processes | `pslist`, `psscan` |
| 3 | Review network activity | `netscan` |
| 4 | Extract command history | `cmdscan`, `consoles` |
| 5 | Enumerate USB devices | `printkey` on `Enum\USBSTOR` |
| 6 | Identify drive letter assignments | `printkey` on `MountedDevices` |
| 7 | Examine ShellBag artefacts | `shellbags --output=html` |
| 8 | Walk user profile registry hives | `hivelist`, `printkey` |
| 9 | Correlate timestamps | Manual comparison across outputs |

---

## Key Findings

| Indicator | Value |
| :--- | :--- |
| Evidence file | `memdumpWin7.mem` (1,073,676,288 bytes) |
| SHA-256 | `500bc1ba8b5ffa8053b6213d7e7aae0c84c18cce541dc53a55887e6e5099495e` |
| Image Profile | `Win7SP1x86_23418` (Windows 7 SP1 x86 PAE) |
| Capture Time (UTC) | 2019-01-06 15:09:06 |
| Active User | `IEUser` (SID `...-1000`) |
| Removable Device | `Disk&Ven_General&Prod_UDisk&Rev_5.00` |
| USB Instance ID | `661bec0f48605_60` |
| USB Attached | 2019-01-06 15:02:54 UTC |
| Drive Assignment | `F:` mapped to USB at 15:03:06 UTC |
| Command Execution | `cmd.exe` (PID 3996) started 15:06:11 UTC |
| Command History | `ipconfig` → `cd Downloads` → `copy secret_file.docx F:` |
| Console Result | `1 file(s) copied.` |
| Network Activity | 2 CLOSED connections to `192.168.56.5:80` |

### Verdict

The memory image preserves a coherent, artefact-based sequence on 6 January 2019. A USB device was mounted as `F:`, the Downloads folder was reviewed, and a command prompt executed a copy operation that the console confirmed as successful (`1 file(s) copied.`). 

**Confidence:** High (90%) for the artefact sequence and copy completion. Moderate (60-70%) for personal attribution, as the image proves profile activity, not physical human presence.

---

## Challenges Encountered
**Environment and Setup**
Volatility 2 on Python 2: The training image requires Volatility 2, which runs on Python 2.7 (legacy). Volatility 3 does not support this image's profile set out of the box, so python2 had to be used explicitly for all invocations.

**Large image size:** The ~1 GB memory image required patience during plugin execution, especially shellbags, which took noticeably longer.

Profile validation: Volatility reports four candidate profiles for this image. Win7SP1x86_23418 was selected after validating that the KDBG (0x82972c68L) and DTB (0x185000L) matched the image, and that subsequent plugins produced clean output.

---

## Technical Challenges
**Challenge	Resolution**
netscan showed PID -1 for closed connections	Documented as unidentifiable (process exited before capture). Did not invent attribution.
MountedDevices records only the most recent mapping	Cross-checked against USBSTOR LastWrite timestamp to confirm the mapping was fresh.
cmdscan does not capture command output	Used consoles to recover the shell screen buffer showing 1 file(s) copied.
ShellBag timestamps can be misread	Distinguished Created, Accessed, and LastWrite fields; relied on LastWrite for folder-view activity.

---

## Evidence Integrity
**Original image preserved read-only.**

Working copy created with cp --preserve=timestamps and re-hashed.

No recovered files were executed.

No password cracking was attempted.

No remote endpoint was contacted.

--- 

## Recommendations
**Further Investigative Steps
Action	Purpose**
Examine the physical USB device	Confirm secret_file.docx exists on the drive; hash the file and preserve MAC times.
Correlate Windows Security event logs	Establish which user session was active at 15:06 UTC on 6 Jan 2019.
Recover Chrome download history	Identify where secret_file.docx was downloaded from.
Identify 192.168.56.5	Determine what service was accessed over HTTP.
Examine the SAM hive	Correlate user logon timestamps with the command execution window.

---

## Defensive Recommendations
**Control	Description**
Removable-media policy	Enforce read-only or block-list USB mass storage unless approved.
Disk encryption	BitLocker To Go or equivalent reduces the value of exfiltrated data.
Least-privilege access	Restrict local administrator rights; use separate admin accounts.
Session auditing	Record and monitor interactive console sessions and remote logins.
Endpoint DLP	Alert on sensitive filenames (e.g., *secret*, *confidential*) leaving managed folders.
USB audit logging	Enable Windows Event ID 6416 (PnP device install) or Sysmon Event ID 6.
For the Forensic Practitioner
Always use imageinfo output to select the profile; never assume from screenshots.

Run multiple plugins for command history (cmdscan and consoles) and confirm they agree.

Convert timestamps to UTC and document any local-time assumption.

Distinguish folder view (ShellBags) from file operation (MFT, USB artefacts).

State command-execution evidence as intent; use consoles for completion proof.

Never confuse the user profile with the physical person.

Safety and Ethics
This case study was conducted exclusively offline against the supplied training memory image.

No live website, host, account, or service was contacted.

No recovered file was executed.

No password or hash-cracking step was performed.

Unrelated personal data was redacted from screenshots.

Original image preserved read-only; all analysis performed on a timestamp-preserved working copy.

**Warning:** Memory forensics is a powerful investigative technique intended for authorised examination only. Do not use these techniques against systems you are not explicitly authorised to examine.

---

## References
ICDFA. (2026). SBT-DF204 — Computer Forensics Case Studies — Case Study 3 Brief.

ICDFA. (2026). Illegal File Transferring: Memory Forensics — Teaching Deck.

Volatility Foundation. (2020). The Volatility Framework 2.6 documentation.

Microsoft. (2024). Windows Registry Reference — MountedDevices key.

Microsoft. (2024). Plug and Play — Device Identification Strings.

MITRE ATT&CK. (2026). T1052.001, T1059.003, T1083, T1021.004.

RFC 3339. (2002). Date and Time on the Internet: Timestamps.

---

## License
Submitted as academic coursework for SBT-DF204 Case Study 3 at ICDFA. Contents may not be redistributed, reused, or reproduced without written permission from the author and ICDFA.

© 2026 Ibrahim Diseh Garba. All rights reserved.
