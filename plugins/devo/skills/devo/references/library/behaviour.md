# Detection library: BEHAVIOUR

Entity-behaviour analytics: entropy anomalies, new servers, DGA suspicion. Source: Devo "Query and alert library" (docs.devo.com). Queries are verbatim from the docs; `lu(...)` enrichments need the lookups listed in INDEX.md.

Detections (4):

- SecOpsEntityBehaviorEntropyServer
- SecOpsEntityBehaviorEntropyUser
- SecOpsEntityNewServer
- SecOpsSuspicionOfPossibleDomainGenerationAlgorithm

## SecOpsEntityBehaviorEntropyServer

**Summary:** Significant Velocity Behavioral change for an Entity from previous cluster.

**MITRE:** Tactics: Exfiltration (TA0010) | Techniques: Exfiltration Over Other Network Medium (T1011)

**Tables:** secops.entities.system

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription, mispIndicator

```linq
from secops.entities.system
where isnotnull(ip)
select str(ip4(ip)) as entity_sourceIP
where lastSeverity > 1
group every 5m by entity_sourceIP, bytesIn, bytesOut, lastCluster, previousCluster, lastSeverity ,previousSeverity, incomingConnectsTo, outgoingConnectsTo, impact, ip, client
every 1h
select `lu/SecOpsAssetRole/class`(entity_sourceIP) as AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select mm2asn(ip4(ip)) as enrichStream_entity_sourceIP_ASN
select mm2isp(ip4(ip)) as enrichStream_entity_sourceIP_ISP
select mm2country(ip4(ip)) as enrichStream_entity_sourceIP_country
select `lu/SecOpsAlertDescription/alertType`("SecOpsEntityBehaviorEntropyServer") as alertType,
`lu/SecOpsAlertDescription/alertMitreTactics`("SecOpsEntityBehaviorEntropyServer") as alertMitreTactics,
`lu/SecOpsAlertDescription/alertMitreTechniques`("SecOpsEntityBehaviorEntropyServer") as alertMitreTechniques,
`lu/SecOpsAlertDescription/alertPriority`("SecOpsEntityBehaviorEntropyServer") as alertPriority
select `lu/mispIndicator/category`(entity_sourceIP) as indicator,
`lu/mispIndicator/type`(entity_sourceIP) as misp_indicator_type,
`lu/mispIndicator/event_id`(entity_sourceIP) as misp_indicator_event_id
```

## SecOpsEntityBehaviorEntropyUser

**Summary:** Significant Velocity Behavioral change for an Entity from the previous cluster.

**MITRE:** Tactics: Privilege Escalation (TA0004) | Techniques: Account Manipulation (T1098)

**Tables:** secops.entities.user

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from secops.entities.user
where isnotnull(account)
group every 5m by account, bytesIn, bytesOut, lastCluster, previousCluster, lastSeverity ,previousSeverity, outgoingAccessIn, impact, client
every 1h
where lastSeverity > 1
select account as entity_sourceAccount
select `lu/SecOpsAssetRole/class`(entity_sourceAccount) as AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select `lu/SecOpsAlertDescription/alertType`("SecOpsEntityBehaviorEntropyUser") as alertType
select `lu/SecOpsAlertDescription/alertMitreTactics`("SecOpsEntityBehaviorEntropyUser") as alertMitreTactics
select `lu/SecOpsAlertDescription/alertMitreTechniques`("SecOpsEntityBehaviorEntropyUser") as alertMitreTechniques
select `lu/SecOpsAlertDescription/alertPriority`("SecOpsEntityBehaviorEntropyUser") as alertPriority
```

## SecOpsEntityNewServer

**Summary:** We have identified a newly observed entity that has not been active in the last 72 hours, which has joined a server cluster.

**MITRE:** Tactics: Discovery (TA0007) | Techniques: System Information Discovery (T1082)

**Tables:** secops.entities.behavior

**Lookups:** SecOpsAssetRole, SecOpsLocation, mispIndicator, SecOpsAlertDescription

```linq
from secops.entities.behavior
where isnotnull(entityIp)
where isnull(cluster2d)
where isnull(cluster1d)
group every 30m by entityIp,cluster0d,modelId, client
every 60m
where cluster0d >= 3
select entityIp as entity_sourceIP
select `lu/SecOpsAssetRole/class`(entity_sourceIP) as AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select `lu/SecOpsLocation/city`(entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select `lu/SecOpsLocation/country`(entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select `lu/mispIndicator/category`(entity_sourceIP) as indicator
select `lu/mispIndicator/type`(entity_sourceIP) as misp_indicator_type
select`lu/mispIndicator/event_id`(entity_sourceIP) as misp_indicator_event_id
select `lu/SecOpsAlertDescription/alertType`("SecOpsEntityNewServer") as alertType  
select `lu/SecOpsAlertDescription/alertMitreTactics`("SecOpsEntityNewServer") as alertMitreTactics  
select `lu/SecOpsAlertDescription/alertMitreTechniques`("SecOpsEntityNewServer") as alertMitreTechniques
select `lu/SecOpsAlertDescription/alertPriority`("SecOpsEntityNewServer") as alertPriority
```

## SecOpsSuspicionOfPossibleDomainGenerationAlgorithm

**Summary:** Detected possible DGA or domain-generation algorithm which can be associated with Command & control (C&C) communication.

**MITRE:** Tactics: Command and Control (TA0011) | Techniques: Dynamic Resolution (T1568)

**Tables:** secops.entities.system

**Lookups:** SecOpsAssetRole, MozillaTLDList, AlexaTop1M, UmbrellaTop1M, SecOpsAlertDescription, mispIndicator

```linq
from secops.entities.system
group every 5m by hostname, subdomain, domainLength, domainEntropy, subdomainLength, subdomainEntropy, topLevelDomain, rootDomain, client
select hostname as entity_sourceHostname
select `lu/SecOpsAssetRole/class`(entity_sourceHostname) as entity_sourceHostname_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
where isnotnull(hostname) and subdomain /= ""
select length(subdomain) - length(subsall(subdomain, re("[bcdfghjklmnpqrstvxzw]"), template(""))) as consonantsInDomain  
select length(subdomain) - length(subsall(subdomain, re("[aeiou]"), template(""))) as vocalsInDomain  
select length(subdomain) - length(subsall(subdomain, re("[1234567890]"), template(""))) as numbersInDomain  
where not vocalsInDomain = 0
select consonantsInDomain/vocalsInDomain as ratioConsonantsToVowels
select numbersInDomain/subdomainLength as rationumbersTolength
where ratioConsonantsToVowels >= 8 // ration over 8 it's double of language media ratio
where subdomainEntropy >= 3.0 // three times the entropy of Top ranked domains
where rationumbersTolength >= 0.3 // three times over the average ration from Top ranked domains
select `lu/MozillaTLDList/status`(topLevelDomain) as enrichStream_entity_sourceHostname_isInMozillaTLD
select `lu/AlexaTop1M/position`(rootDomain+"."+topLevelDomain) as enrichStream_entity_sourceHostname_positionInAlexaTop1M
select `lu/UmbrellaTop1M/position`(rootDomain+"."+topLevelDomain) as enrichStream_entity_sourceHostname_positionInUmbrellaTop1M
select domainLength as enrichStream_entity_sourceHostname_domainLength
select domainEntropy as enrichStream_entity_sourceHostname_domainShannonEntropy
select `lu/SecOpsAlertDescription/alertType`("SecOpsSuspicionOfPossibleDomainGenerationAlgorithm") as alertType
select `lu/SecOpsAlertDescription/alertMitreTactics`("SecOpsSuspicionOfPossibleDomainGenerationAlgorithm") as alertMitreTactics
select `lu/SecOpsAlertDescription/alertMitreTechniques`("SecOpsSuspicionOfPossibleDomainGenerationAlgorithm") as alertMitreTechniques
select `lu/SecOpsAlertDescription/alertPriority`("SecOpsSuspicionOfPossibleDomainGenerationAlgorithm") as alertPriority
select `lu/mispIndicator/category`(entity_sourceHostname) as indicator
select `lu/mispIndicator/type`(entity_sourceHostname) as misp_indicator_type
select `lu/mispIndicator/event_id`(entity_sourceHostname) as misp_indicator_event_id
```
