# APT29 Threat Actor Profile

## 1. Overview

APT29 (MITRE ATT&CK Group ID: G0016) is a threat group attributed to Russia's Foreign Intelligence Service (SVR). The group has been active since at least 2008.

APT29 is also known by several names in public security reporting, including Cozy Bear, The Dukes, NOBELIUM, UNC2452, and Midnight Blizzard.

## 2. Common Targets

According to MITRE ATT&CK, APT29 has frequently targeted:

- Government networks in Europe
- NATO member countries
- Research institutes
- Think tanks

## 3. Notable Campaign: SolarWinds Compromise

The SolarWinds Compromise (MITRE ATT&CK Campaign ID: C0024) was a major supply-chain operation discovered in December 2020.

The attackers inserted malicious code into the SolarWinds Orion software build process. The compromised software was then distributed through legitimate software updates.

Reported activities included password spraying, token theft, API abuse, spearphishing, and supply-chain compromise.

In April 2021, the United States and United Kingdom publicly attributed the campaign to Russia's Foreign Intelligence Service (SVR).

## 4. Relevance to Cybersecurity Monitoring

The SolarWinds case demonstrates why SOC analysts should monitor:

- Unusual process creation
- Suspicious account authentication activity
- Unexpected scheduled tasks
- Abnormal use of trusted software
- Suspicious network communication
- Identity and access token activity

These monitoring areas are investigation priorities, not proof that APT29 activity is present in our laboratory.

## 5. Research Sources

1. MITRE ATT&CK – APT29 (G0016): https://attack.mitre.org/groups/G0016/
2. MITRE ATT&CK – SolarWinds Compromise (C0024): https://attack.mitre.org/campaigns/C0024/
