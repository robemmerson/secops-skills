# Detection library: EMAIL/MIMECAST

Mimecast email security detections. Source: Devo "Query and alert library" (docs.devo.com). Queries are verbatim from the docs; `lu(...)` enrichments need the lookups listed in INDEX.md.

Detections (2):

- SecOpsMimecastMessageWithHighSpamScore
- SecOpsMimecastMessageWithVirusDetections

## SecOpsMimecastMessageWithHighSpamScore

**Summary:** Adversaries may send spearphishing emails with malicious attachments in an attempt to gain access to victim systems.

**MITRE:** Tactics: Initial Access (TA0001) | Techniques: Phishing (T1566)

**Tables:** mail.mimecast.siem.receipt

**Lookups:** SecOpsAssetRole, SecOpsLocation, SecOpsAlertDescription

```linq
from mail.mimecast.siem.receipt
select ip as entity_sourceIP
select sender as entity_sourceAccount
select rcpt as entity_destinationAccount
where spamScore > 7
group every 5m by entity_sourceIP, entity_sourceAccount, entity_destinationAccount, subject, spamScore, client
every 5m
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_destinationAccount) as entity_destinationAccount_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsMimecastMessageWithHighSpamScore") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsMimecastMessageWithHighSpamScore") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsMimecastMessageWithHighSpamScore") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsMimecastMessageWithHighSpamScore") as alertPriority
```

## SecOpsMimecastMessageWithVirusDetections

**Summary:** Adversaries may send spearphishing emails with malicious attachments in an attempt to gain access to victim systems.

**MITRE:** Tactics: Initial Access (TA0001) | Techniques: Phishing (T1566)

**Tables:** mail.mimecast.siem.av

**Lookups:** SecOpsAssetRole, SecOpsLocation, SecOpsAlertDescription

```linq
from mail.mimecast.siem.av
select ip as entity_sourceIP
select sender as entity_sourceAccount
select recipient as entity_destinationAccount
where isnotnull(virus)
group every 5m by entity_sourceIP, entity_sourceAccount, entity_destinationAccount, fileName, sha256, subject, virus, client
every 5m
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_destinationAccount) as entity_destinationAccount_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsMimecastMessageWithVirusDetections") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsMimecastMessageWithVirusDetections") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsMimecastMessageWithVirusDetections") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsMimecastMessageWithVirusDetections") as alertPriority
```
