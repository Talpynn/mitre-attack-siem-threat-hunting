# Configuration

## 1. Lab Environment

This directory documents the environment configuration used in the Week 8 adversary emulation exercise.

| Component | Configuration |
|---|---|
| Host Operating System | Windows 11 |
| Linux Environment | Kali Linux |
| Virtualization Platform | Oracle VirtualBox |
| SIEM Platform | Splunk Enterprise |
| Network Configuration | NAT and Host-only Network |
| Test Data | Harmless fictional training files |

## 2. Network Configuration

The Kali Linux virtual machine uses two network adapters.

| Adapter | Network Mode | IPv4 Address | Purpose |
|---|---|---|---|
| Adapter 1 (eth0) | NAT | 10.0.2.15 | Internet connectivity |
| Adapter 2 (eth1) | Host-only | 192.168.56.101 | Communication with Windows host |

The Windows Host-only network adapter uses the following address:

- **Windows Host-only IP:** `192.168.56.1`
- **Subnet Mask:** `255.255.255.0`

The Host-only network provides isolated communication between Windows and Kali Linux.

Connectivity was verified successfully using ICMP ping tests.

## 3. Tool Configuration

### Windows 11
- Used as the monitored host.
- Generated Windows Security Event Logs.
- Recorded process creation and scheduled task activities.

### Kali Linux
- Used as the Linux laboratory environment.
- Hosted a local HTTP receiving service for the controlled data transfer test.

### Splunk Enterprise
- Installed directly on Windows 11.
- Used to search and investigate Windows Security Event Logs.
- Used to analyze Event IDs 4688, 4698, and 4699.

## 4. Test Data and Safety

All experiments used harmless fictional training files.

The data transfer was performed through the Host-only network between Windows and Kali Linux.

No external target systems or malicious payloads were used.

## 5. Configuration Summary

The laboratory environment was configured to support controlled adversary emulation, Windows event monitoring, and SIEM-based investigation.

The network configuration allowed Kali Linux and Windows 11 to communicate while keeping the test data transfer within the local laboratory environment.
