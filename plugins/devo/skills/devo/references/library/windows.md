# Detection library: WINDOWS

Windows event-log detections (box.all.win): accounts, services, registry, PowerShell, lateral movement. Source: Devo "Query and alert library" (docs.devo.com). Queries are verbatim from the docs; `lu(...)` enrichments need the lookups listed in INDEX.md.

Detections (187):

- SecOpsAccessToBrowserLoginData
- SecOpsAccountsCreatedRemovedWithinFourHours
- SecOpsADAccountNoExpires
- SecOpsADPasswdNoExpires
- SecOpsAppInitDLLsLoaded
- SecOpsAPT29byGoogleUpdateServiceInstall
- SecOpsBcdModificationRecoveryAndBootFailureSuppression
- SecOpsBlackByteRansomwareRegChangesPowershell
- SecOpsBlackByteRansomwareRegistryChanges
- SecOpsBlackKingdomWebshellInstalation
- SecOpsBlankPasswordAsk
- SecOpsBypassUserAccountControl
- SecOpsChangesAccessibilityBinaries
- SecOpsComsvcsDllDowngradeForPotentialCredentialDumping
- SecOpsDeletingMassAmountOfFiles
- SecOpsDLLWithNonUsualPath
- SecOpsEnumerationFor3rdPartyCredsFromCli
- SecOpsFailLogOn
- SecOpsFsutilSuspiciousInvocation
- SecOpsGenericRansomwareBehaviorIpScanner
- SecOpsHAFNIUMUmServiceSuspiciousFileTargetingExchangeServers
- SecOpsHighVolumeFileDeletion
- SecOpsIntegrityProblem
- SecOpsLocalUserCreation
- SecOpsLolbinBitsadminTransfer
- SecOpsLolbinCertocexecution
- SecOpsLolbinCertreq
- SecOpsLolbinCertutil
- SecOpsLolbinConfigsecuritypolicy
- SecOpsLolbinDatasvcutil
- SecOpsLolbinMshta
- SecOpsLsassDumpKeywordInCommandLine
- SecOpsMaliciousPowerShellCommandletNames
- SecOpsMaliciousPowerShellPrebuiltCommandlet
- SecOpsMaliciousServiceInstallations
- SecOpsMoveitCmdlineFileCreation
- SecOpsMoveitDynamicCompilationViaCscExe
- SecOpsMoveitFilePotentialActivityTransferExploitation
- SecOpsMultipleMachineAccessedbyUser
- SecOpsNewAccountCreated
- SecOpsNtdsDitDomainHashExtractionActivity
- SecOpsOsCredentialDumpingGsecdump
- SecOpsPassTheHashActivityLoginBehaviour
- SecOpsPersistenceAndExecutionViaGPOScheduledTask
- SecOpsPotentiallySuspiciousEventLogReconActivity
- SecOpsPsExecToolExecution
- SecOpsPuaFastReverseProxyExecution
- SecOpsRansomwareBehaviorMaze
- SecOpsRansomwareBehaviorNotPetya
- SecOpsRansomwareBehaviorRyuk
- SecOpsRareServiceInstalls
- SecOpsResetPasswordAttempt
- SecOpsRevilKaseyaRegistryKey
- SecOpsSecurityEnabledLocalGroupChanged
- SecOpsSensitiveFileAccessViaVolumeShadowCopyBackup
- SecOpsSeveralPasswordChanges
- SecOpsShadowCopiesDeletion
- SecOpsSIGRedExploitMicrosoftWindowsDNS
- SecOpsStoneDrillServiceInstall
- SecOpsStopSqlServicesRunning
- SecOpsSuspiciousBehaviorAppInitDLL
- SecOpsSuspiciousEventlogClearingOrConfigurationChangeActivity
- SecOpsSuspiciousEventlogClearUsingWevtutil
- SecOpsSuspiciousPowerShellInvocation
- SecOpsSuspiciousWMIExecution
- SecOpsTurlaPNGDropperService
- SecOpsTurlaServiceInstall
- SecOpsUserAccountChanged
- SecOpsVolumeShadowCopyDeletion
- SecOpsWannaCryBehavior
- SecOpsWermgrConnectingToIPCheckWebServices
- SecOpsWinActivateNoCloseGroupPolicyFeature
- SecOpsWinActivateNoControlPanelGroupPolicyFeature
- SecOpsWinActivateNoFileMenuGroupPolicyFeature
- SecOpsWinActivateNoPropertiesMyDocumentsGroupPolicyFeature
- SecOpsWinActivateNoSetTaskbarGroupPolicyFeature
- SecOpsWinActivateNoTrayContextMenuGroupPolicyFeature
- SecOpsWinADDomainEnumeration
- SecOpsWinAddRegistryValueToLoadSrvcInSafeModeWithNetwork
- SecOpsWinAddRegistryValueToLoadSrvcInSafeModeWONetwork
- SecOpsWinAdminRemoteLogon
- SecOpsWinAdminShareSuspiciousUse
- SecOpsWinAnonymousAccountCreated
- SecOpsWinAppInstallerExecution
- SecOpsWinAttackerToolsOnEndpoint
- SecOpsWinAttemptToAddCertificateToStore
- SecOpsWinAuditLogCleared
- SecOpsWinAutomatedCollectionCmd
- SecOpsWinAutomatedCollectionPowershell
- SecOpsWinBackupCatalogDeleted
- SecOpsWinCompressEncryptData
- SecOpsWinCredentialDumpingNppspy
- SecOpsWinCritServiceStopped
- SecOpsWinCurl
- SecOpsWinDcShadowDetected
- SecOpsWinDefenderDownloadActivity
- SecOpsWinDisableAntispywareRegistry
- SecOpsWinDisableUac
- SecOpsWinDnsExeParentProcess
- SecOpsWinDomainTrustActivity
- SecOpsWinExcessiveUserInteractiveLogin
- SecOpsWinExternalDeviceInstallationDenied
- SecOpsWinFakeProcesses
- SecOpsWinFsutilDeleteChangeJournal
- SecOpsWinFTPScriptExecution
- SecOpsWinGatherVictimIdentitySAMInfo
- SecOpsWinGoldenSamlCertificateExport
- SecOpsWinIcmpExfiltration
- SecOpsWinIISWebRootProcessExecution
- SecOpsWinInvokewebrequestUse
- SecOpsWinKerberosUserEnumeration
- SecOpsWinLocalSystemExecuteWhoami
- SecOpsWinLockoutsEndpoint
- SecOpsWinLsassKeyModification
- SecOpsWinLsassMemDump
- SecOpsWinMapSmbShare
- SecOpsWinMemoryCorruptionVulnerability
- SecOpsWinMimikatzLsadump
- SecOpsWinModifyShowCompressColorAndInfoTipRegistry
- SecOpsWinMsiExecInstallWeb
- SecOpsWinNetworkShareCreated
- SecOpsWinNewPsDrive
- SecOpsWinOfficeBrowserLaunchingShell
- SecOpsWinPermissionGroupDiscovery
- SecOpsWinPotentialPassTheHash
- SecOpsWinPowerSettings
- SecOpsWinPowershellKeyloggin
- SecOpsWinPowershellProcessDiscovery
- SecOpsWinPowershellSetExecutionPolicyBypass
- SecOpsWinRcloneExecution
- SecOpsWinRegistryModificationActivateNoRunGroupPolicy
- SecOpsWinRegistryModificationDisableChangePasswdFeature
- SecOpsWinRegistryModificationDisableCMDApp
- SecOpsWinRegistryModificationDisableLockWSFeature
- SecOpsWinRegistryModificationDisableLogOffButton
- SecOpsWinRegistryModificationDisableNotificationCenter
- SecOpsWinRegistryModificationDisableRegistryTool
- SecOpsWinRegistryModificationDisableShutdownButton
- SecOpsWinRegistryModificationDisableTaskmgr
- SecOpsWinRegistryModificationGlobalFolderOptions
- SecOpsWinRegistryModificationHideClockGroupPolicyFeature
- SecOpsWinRegistryModificationHideSCAHealth
- SecOpsWinRegistryModificationHideSCANetwork
- SecOpsWinRegistryModificationHideSCAPower
- SecOpsWinRegistryModificationHideSCAVolume
- SecOpsWinRegistryModificationIExplorerSecZone
- SecOpsWinRegistryModificationNewTrustedSite
- SecOpsWinRegistryModificationNoDesktopGroupPolicy
- SecOpsWinRegistryModificationNoFindGroupPolicyFeature
- SecOpsWinRegistryModificationPowershellLoggingDisabled
- SecOpsWinRegistryModificationRunKeyAdded
- SecOpsWinRegistryModificationStoreLogonCred
- SecOpsWinRegistryQuery
- SecOpsWinRegUtilityHiveExport
- SecOpsWinRemoteSystemDiscovery
- SecOpsWinRunasCommandExecution
- SecOpsWinSamStopped
- SecOpsWinScheduledTaskCreation
- SecOpsWinSchtasksForcedReboot
- SecOpsWinSchtasksRemoteSystem
- SecOpsWinSensitiveFiles
- SecOpsWinServiceCreatedNonStandardPath
- SecOpsWinShadowCopyDetected
- SecOpsWinSmtpExfiltration
- SecOpsWinSpoolsvExeAbnormalProcessSpawn
- SecOpsWinSuspiciousExternalDeviceInstallation
- SecOpsWinSuspiciousWritesToRecycleBin
- SecOpsWinSysInfoGatheringUsingDxdiag
- SecOpsWinSysInternalsActivityDetected
- SecOpsWinSysTimeDiscovery
- SecOpsWinTFTPExecution
- SecOpsWinUserAddedPrivlegedSecGroup
- SecOpsWinUserAddedSelfToSecGroup
- SecOpsWinUserAddedToLocalSecurityEnabledGroup
- SecOpsWinUserCreationAbnormalNamingConvention
- SecOpsWinUserCredentialDumpRegistry
- SecOpsWinWebclientClassUse
- SecOpsWinWifiCredHarvestNetsh
- SecOpsWinWmiExecVbsScript
- SecOpsWinWmiLaunchingShell
- SecOpsWINWmiMOFProcessExecution
- SecOpsWinWMIPermanentEventSubscription
- SecOpsWinWmiProcessCallCreate
- SecOpsWinWmiprvseSpawningProcess
- SecOpsWinWMIReconRunningProcessOrSrvcs
- SecOpsWinWmiScriptExecution
- SecOpsWinWmiTemporaryEventSubscription

## SecOpsAccessToBrowserLoginData

**Summary:** Detects PowerShell script activity attempting to copy browser credential files using Copy-Item with specified destination paths.

**MITRE:** Tactics: Credential Access (TA0006) | Techniques: Credentials from Password Stores (T1555)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, mispIndicator, SecOpsAlertDescription

```linq
from box.all.win
where event_id = 4104 or event_id = 4688
select ifthenelse(process_command_line = null, new_process_name, process_command_line) as selected_command_line
where weakhas(parent_process_name,"powershell")
where (weakhas(selected_command_line,"Opera Software\\Opera Stable\\Login Data")
    or weakhas(selected_command_line,"Mozilla\\Firefox\\Profiles")
    or weakhas(selected_command_line,"Microsoft\\Edge\\User Data\\Default")
    or weakhas(selected_command_line,"Google\\Chrome\\User Data\\Default\\Login Data")
    or weakhas(selected_command_line,"Google\\Chrome\\User Data\\Default\\Login Data For Account")
    or weakhas(selected_command_line,"Google\\Chrome\\User Data"))
group every 5m by source_ip, account, subject_username, subject_domain, source_hostname, process_name, device, client
every 5m
select process_name as ServiceName
select source_ip as entity_sourceIP
select account as entity_sourceAccount
select subject_username as entity_sourceName
select subject_domain as entity_sourceDomain
select source_hostname as entity_sourceHostname
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceDomain) as entity_sourceDomain_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceName) as entity_sourceName_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("mispIndicator", "category", entity_sourceIP) as indicator
select lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type
select lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
select lu("SecOpsAlertDescription", "alertType", "SecOpsAccessToBrowserLoginData") as alertType  
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsAccessToBrowserLoginData") as alertMitreTactics  
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsAccessToBrowserLoginData") as alertMitreTechniques  
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsAccessToBrowserLoginData") as alertPriority
```

## SecOpsAccountsCreatedRemovedWithinFourHours

**Summary:** Detects user accounts that are created and delete within a four time period.

**Description:** Detects user accounts that are created and delete within a four time period. Attackers will create accounts with administrative privileges to conduct their activities and delete the account once they are finished.

**MITRE:** Tactics: Privilege Escalation (TA0004) | Techniques: Account Manipulation (T1098)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.all.win
where event_id = 4726 and isnotnull(account) and account != "-"
group every 5m by account, source_hostname, client
where account in (
    from box.all.win
    select account
    where event_id = 4720, isnotnull(account) and account != "-"
    group every - by account)
select account as entity_sourceAccount
select source_hostname as entity_sourceHostname
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsAccountsCreatedRemovedWithinFourHours") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsAccountsCreatedRemovedWithinFourHours") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsAccountsCreatedRemovedWithinFourHours") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsAccountsCreatedRemovedWithinFourHours") as alertPriority
```

## SecOpsADAccountNoExpires

**Summary:** The monitoring of policies related to passwords is a fundamental part of keeping systems and users safe. This alert helps to ensure policies are applying properly.

**MITRE:** Tactics: Defense Evasion (TA0005) | Techniques: Domain Policy Modification (T1484)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, SecOpsLocation, SecOpsAlertDescription

```linq
from box.all.win
where isnotnull(account),
not account -> "$",
not account = "SYSTEM",
event_id = 4722 or event_id = 4738,
weakhas(message, "Account Expires:  <never>") or weakhas(message, "Account Expires: -")
group every 30m by account, subject_username, source_hostname, subject_domain, source_ip, device, client
every 1h
select subject_username as entity_sourceName
select account as entity_destinationAccount
select source_hostname as entity_sourceHostname
select subject_domain as entity_sourceDomain
select source_ip as entity_sourceIP
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceDomain) as entity_sourceDomain_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_destinationAccount) as entity_destinationAccount_AssetRole  // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceName) as entity_sourceName_AssetRole  // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsADAccountNoExpires") as alertType  
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsADAccountNoExpires") as alertMitreTactics  
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsADAccountNoExpires") as alertMitreTechniques  
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsADAccountNoExpires") as alertPriority
```

## SecOpsADPasswdNoExpires

**Summary:** The monitoring of policies related to passwords is a fundamental part of keeping systems and users safe. This alert helps to ensure policies are applying properly.

**MITRE:** Tactics: Defense Evasion (TA0005) | Techniques: Domain Policy Modification (T1484)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, SecOpsLocation, SecOpsAlertDescription

```linq
from box.all.win
where isnotnull(account),
not account -> "$",
not account = "SYSTEM",
event_id = 4722 or event_id = 4738,
weakhas(message, "'Don't Expire Password' - Enabled")
group every 30m by account, subject_username, source_hostname, subject_domain, source_ip, device, client
every 1h
select count() as count
select subject_username as entity_sourceName
select account as entity_destinationAccount
select source_hostname as entity_sourceHostname
select subject_domain as entity_sourceDomain
select source_ip as entity_sourceIP
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceDomain) as entity_sourceDomain_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_destinationAccount) as entity_destinationAccount_AssetRole  // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsADPasswdNoExpires") as alertType  
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsADPasswdNoExpires") as alertMitreTactics  
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsADPasswdNoExpires") as alertMitreTechniques  
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsADPasswdNoExpires") as alertPriority
```

## SecOpsAppInitDLLsLoaded

**Summary:** Monitor DLL loads by processes that load user32.dll and look for DLLs that are not recognized or not normally loaded into a process.

**MITRE:** Tactics: Persistence (TA0003) | Techniques: Event Triggered Execution (T1546)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.all.win
where eq(str(event_id), "4622") and weakhas(message,"user32.dll")
select source_hostname as entity_sourceHostname
select str(machine_ip) as entity_sourceIP
group every 5m by event_id, procName, entity_sourceIP, entity_sourceHostname, message, device, client
every 5m
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsAppInitDLLsLoaded") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsAppInitDLLsLoaded") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsAppInitDLLsLoaded") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsAppInitDLLsLoaded") as alertPriority
```

## SecOpsAPT29byGoogleUpdateServiceInstall

**Summary:** Monitor service creation through changes in the Registry and common utilities using command-line invocation ir order to detect Russian nation-state attackers APT29.

**MITRE:** Tactics: Persistence (TA0003) | Techniques: Create or Modify System Process (T1543)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, SecOpsLocation, SecOpsAlertDescription

```linq
from box.all.win
where (eq(event_id, 7045) or eq(event_id, 4697))
where isnotnull(split(split(service_file_name, "C:\\Program Files(x86)\\Google\\", 1), ".exe", 0))
select str(machine_ip) as entity_sourceIP
select source_hostname as entity_sourceHostname
select service_account as entity_sourceAccount
group every 5m by event_id, service_file_name, entity_sourceIP, entity_sourceHostname, entity_sourceAccount, procName, device, client
every 5m
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsAPT29byGoogleUpdateServiceInstall") as alertType  
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsAPT29byGoogleUpdateServiceInstall") as alertMitreTactics  
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsAPT29byGoogleUpdateServiceInstall") as alertMitreTechniques  
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsAPT29byGoogleUpdateServiceInstall") as alertPriority
```

## SecOpsBcdModificationRecoveryAndBootFailureSuppression

**Summary:** This alert detects the execution of commands that modify the Boot Configuration Data (BCD) settings on Windows systems. The command bcdedit.exe /set default recoveryenabled No disables the Windows recovery environment, while bcdedit.exe /set default bootstatuspolicy ignoreallfailures configures the system to ignore boot failure notifications. These changes are often associated with malicious activities, such as ransomware or other attack scenarios, where attackers seek to prevent system recovery and mask potential failures to maintain control over the compromised system.

**Description:** Detects the execution of commands that modify the Boot Configuration Data (BCD) settings on Windows systems.

**MITRE:** Tactics: Impact (TA0040) | Techniques: Inhibit System Recovery (T1490)

**Tables:** box.all.win

**Lookups:** none

```linq
from box.all.win
where (endswith(image, "bcdedit.exe")
or original_file_name = "bcdedit.exe")
and (toktains(process_command_line, "bootstatuspolicy", true, true)
or toktains(process_command_line, "deletevalue", true, true)
or toktains(process_command_line, "recoveryenabled", true, true)
or toktains(process_command_line, "safeboot", true, true)
or toktains(process_command_line, "network", true, true))
group every 5m by username,account,source_ip,destination_ip,source_hostname,destination_hostname,process_name,source, device, client
select collectdistinct(process_command_line) as commands
where round(hllppcount(process_command_line)) > 1
select source_ip as entity_sourceIP
select destination_ip as entity_destionationIP
select source_hostname as entity_sourceHostname
select destination_hostname as entity_destinationHostname
select account as entity_sourceAccount
//<filtering_section>
select "Detection" as alertType
select "Impact" as alertMitreTactics
select "Inhibit System Recovery" as alertMitreTechniques
select 4 as alertPriority
```

## SecOpsBlackByteRansomwareRegChangesPowershell

**Summary:** Adversaries may interact with the Windows Registry to hide configuration information within Registry keys, remove information as part of cleaning up, or as part of other techniques to aid in persistence and execution.

**MITRE:** Tactics: Defense Evasion (TA0005) | Techniques: Modify Registry (T1112)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.all.win
where ((event_id = 1 and channel ="Microsoft-Windows-Sysmon") or event_id = 4688) and weakhas(process_command_line, "New-ItemProperty") and ( weakhas(process_command_line, "EnableLinkedConnections") or weakhas(process_command_line, "LocalAccountTokenFilterPolicy") or weakhas(process_command_line, "LongPathsEnabled"))
select source_hostname as entity_sourceHostname
group every 5m by entity_sourceHostname, machine_ip, subject_username, device, client
every 5m
select int(hllppcount(process_command_line)) as num_added_regKeys
where num_added_regKeys = 3
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsBlackByteRansomwareRegChangesPowershell") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsBlackByteRansomwareRegChangesPowershell") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsBlackByteRansomwareRegChangesPowershell") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsBlackByteRansomwareRegChangesPowershell") as alertPriority
```

## SecOpsBlackByteRansomwareRegistryChanges

**Summary:** Adversaries may interact with the Windows Registry to hide configuration information within Registry keys, remove information as part of cleaning up, or as part of other techniques to aid in persistence and execution. Microsoft-Windows-Sysmon required.

**Description:** Adversaries may interact with the Windows Reg. to hide information within Registry keys, remove information as part of cleaning up, or as part of other techniques to aid in persistence and execution. Microsoft-Windows-Sysmon required.

**MITRE:** Tactics: Defense Evasion (TA0005) | Techniques: Modify Registry (T1112)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.all.win
where ((event_id = 1 and weakhas(process_command_line, "Microsoft-Windows-Sysmon")) or event_id = 4688) and (weakhas(process_command_line, "reg") and weakhas(process_command_line, "add")) and ( weakhas(process_command_line, "EnableLinkedConnections") or weakhas(process_command_line, "LocalAccountTokenFilterPolicy") or weakhas(process_command_line, "LongPathsEnabled"))
select source_hostname as entity_sourceHostname
group every 5m by entity_sourceHostname, machine_ip, subject_username, device, client
every 5m
select int(hllppcount(process_command_line)) as num_added_regKeys
where num_added_regKeys = 3
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsBlackByteRansomwareRegistryChanges") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsBlackByteRansomwareRegistryChanges") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsBlackByteRansomwareRegistryChanges") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsBlackByteRansomwareRegistryChanges") as alertPriority
```

## SecOpsBlackKingdomWebshellInstalation

**Summary:** Detects suspicious file creation activity on that could be related with Black Kingdom Ransomware

**MITRE:** Tactics: Persistence (TA0003) | Techniques: Server Software Component (T1505)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, mispIndicator, SecOpsLocation, SecOpsAlertDescription

```linq
from box.all.win
where event_id = 4688
where toktains(process_name, "w3wp.exe")
where weaktoktains(message, "MSExchangeECPAppPool")
group every 5m by source_ip, machine, account, subject_username, subject_domain, source_hostname, process_name, device, client
every 15m
select process_name as ServiceName
select source_ip as entity_sourceIP
select account as entity_sourceAccount
select subject_username as entity_sourceName
select subject_domain as entity_sourceDomain
select source_hostname as entity_sourceHostname
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceDomain) as entity_sourceDomain_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceName) as entity_sourceName_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("mispIndicator", "category", entity_sourceIP) as indicator
select lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type
select lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsBlackKingdomWebshellInstalation") as alertType  
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsBlackKingdomWebshellInstalation") as alertMitreTactics  
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsBlackKingdomWebshellInstalation") as alertMitreTechniques  
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsBlackKingdomWebshellInstalation") as alertPriority
```

## SecOpsBlankPasswordAsk

**Summary:** An attempt was made to query the existence of a blank password for an account. If you see this event for many different target account names it must be investigated.

**MITRE:** Tactics: Persistence (TA0003) | Techniques: Account Manipulation (T1098)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, mispIndicator, SecOpsAlertDescription

```linq
from box.all.win
where event_id = 4797
select machine_ip as entity_sourceIP
select account as entity_sourceName
select subject_username as entity_sourceAccount
group every 30m by entity_sourceName, entity_sourceIP,entity_sourceAccount, device, client
every 1h
select lu("SecOpsAssetRole", "class", entity_sourceIP) as AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select nnlast(subject_domain) as entity_sourceDomain
select nnlast(machine) as entity_sourceHostname
select countrycode(ip4(entity_sourceIP)) as country
select ifthenelse(toktains(lu("mispIndicator", "eventtags_name_str", str(entity_sourceIP)),"TOR"), true, false) as enrichStream_entity_sourceIP_isAnonymousProxy
select lu("mispIndicator", "category", entity_sourceIP) as indicator,
       lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type,
       lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
select lu("SecOpsAlertDescription", "alertType", "SecOpsBlankPasswordAsk") as alertType  
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsBlankPasswordAsk") as alertMitreTactics  
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsBlankPasswordAsk") as alertMitreTechniques  
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsBlankPasswordAsk") as alertPriority
```

## SecOpsBypassUserAccountControl

**Summary:** Some UAC bypass methods rely on modifying specific, user-accessible Registry settings.

**MITRE:** Tactics: Privilege Escalation (TA0004) | Techniques: Abuse Elevation Control Mechanism (T1548)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, mispIndicator, SecOpsLocation, SecOpsAlertDescription

```linq
from box.all.win
where toktains(object_name, "CurrentVersion\\App Paths\\control.exe") or
toktains(object_name, "Classes\\exefile\\shell\\runas\\command\\isolatedCommand") or
toktains(object_name, "Software\\Classes\\mscfile\\shell\\open\\command")
group every 5m by machine_ip, process_name, object_name, source_hostname, device, client
every 15m
select process_name as ProcessName
select object_name as DLL
select str(machine_ip) as entity_sourceIP
select source_hostname as entity_sourceHostname
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("mispIndicator", "category", entity_sourceIP) as indicator
select lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type
select lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsBypassUserAccountControl") as alertType  
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsBypassUserAccountControl") as alertMitreTactics  
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsBypassUserAccountControl") as alertMitreTechniques  
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsBypassUserAccountControl") as alertPriority
```

## SecOpsChangesAccessibilityBinaries

**Summary:** Changes to accessibility utility binaries or binary paths that do not correlate with known software, patch cycles, etc., are suspicious.

**MITRE:** Tactics: Privilege Escalation (TA0004) | Techniques: Event Triggered Execution (T1546)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, mispIndicator, SecOpsLocation, SecOpsAlertDescription

```linq
from box.all.win
where object_name -> "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options"
group every 5m by machine_ip, source_hostname, device, client
every 15m
select str(machine_ip) as entity_sourceIP
select source_hostname as entity_sourceHostname
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("mispIndicator", "category", entity_sourceIP) as indicator
select lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type
select lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsChangesAccessibilityBinaries") as alertType  
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsChangesAccessibilityBinaries") as alertMitreTactics  
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsChangesAccessibilityBinaries") as alertMitreTechniques  
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsChangesAccessibilityBinaries") as alertPriority
```

## SecOpsComsvcsDllDowngradeForPotentialCredentialDumping

**Summary:** Detection of potential credential dumping via downgraded comsvcs.dll.

**MITRE:** Tactics: Credential Access (TA0006) | Techniques: OS Credential Dumping (T1003)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, mispIndicator, SecOpsAlertDescription

```linq
from box.all.win
where event_id = 11
select "comsvcs.dll" as targetDLL
where target_file_name -> targetDLL
where targetDLL in (
    from box.all.win
    where event_id = 4688
    select "comsvcs.dll" as targetDLL
    select ifthenelse(process_command_line = null, new_process_name, process_command_line) as selected_command_line
    where weakhas(selected_command_line,"certutil") and weakhas(selected_command_line,"urlcache") and weakhas(selected_command_line, targetDLL)
    group every - by targetDLL
)
group every 5m by source_ip, username, account, subject_domain, source_hostname,new_process_name, image, target_file_name, device, client
every 5m
select new_process_name as ServiceName
select source_ip as entity_sourceIP
select account as entity_sourceAccount
select username as entity_sourceName
select subject_domain as entity_sourceDomain
select source_hostname as entity_sourceHostname
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceDomain) as entity_sourceDomain_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceName) as entity_sourceName_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("mispIndicator", "category", entity_sourceIP) as indicator
select lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type
select lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
select lu("SecOpsAlertDescription", "alertType", "SecOpsComsvcsDllDowngradeForPotentialCredentialDumping") as alertType  
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsComsvcsDllDowngradeForPotentialCredentialDumping") as alertMitreTactics  
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsComsvcsDllDowngradeForPotentialCredentialDumping") as alertMitreTechniques  
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsComsvcsDllDowngradeForPotentialCredentialDumping") as alertPriority
```

## SecOpsDeletingMassAmountOfFiles

**Summary:** User is deleting mass amounts of files in a very short period of time.

**MITRE:** Tactics: Impact (TA0040) | Techniques: Data Destruction (T1485)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, SecOpsLocation, SecOpsAlertDescription

```linq
from box.all.win
where event_id = 4660
where not endswith(subject_username, "$")
select str(machine_ip) as entity_sourceIP
select subject_username as entity_sourceName
select source_hostname as entity_sourceHostname
group every 10m by entity_sourceName,entity_sourceHostname,entity_sourceIP, device, client
every 10m
select count() as count
where count > 1000
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceName) as entity_sourceName_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsDeletingMassAmountOfFiles") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsDeletingMassAmountOfFiles") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsDeletingMassAmountOfFiles") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsDeletingMassAmountOfFiles") as alertPriority
```

## SecOpsDLLWithNonUsualPath

**Summary:** Monitor DLLs loaded into a process and detect DLLs that have the same file name but abnormal paths.

**MITRE:** Tactics: Persistence (TA0003) | Techniques: Hijack Execution Flow (T1574)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.all.win
where eq(str(event_id), "4622") and (not weakhas(message, "C:\\Windows\\System\\") and not weakhas(message, "C:\\WINNT\\System32\\") and not weakhas(message, "C:\\Windows\\SysWOW64\\") and not weakhas(message, "C:\\Windows\\System32\\") )
select source_hostname as entity_sourceHostname
select str(machine_ip) as entity_sourceIP
group every 5m by event_id, entity_sourceIP, entity_sourceHostname, message, device, client
every 5m
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsDLLWithNonUsualPath") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsDLLWithNonUsualPath") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsDLLWithNonUsualPath") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsDLLWithNonUsualPath") as alertPriority
```

## SecOpsEnumerationFor3rdPartyCredsFromCli

**Summary:** Detects command-line processes querying third-party registry keys that commonly store credentials.

**MITRE:** Tactics: Discovery (TA0007) | Techniques: Query Registry (T1012)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, mispIndicator, SecOpsAlertDescription

```linq
from box.all.win
where event_id = 4688
select ifthenelse(process_command_line = null, new_process_name, process_command_line) as selected_command_line
where (weakhas(selected_command_line,"PuTTY\\Sessions")
    or weakhas(selected_command_line,"Mobatek\\MobaXterm")
    or weakhas(selected_command_line,"WOW6432Node\\Radmin\\v3.0\\Server\\Parameters\\Radmin")
    or weakhas(selected_command_line,"Aerofox\\FoxmailPreview")
    or weakhas(selected_command_line,"IncrediMail\\Identities")
    or weakhas(selected_command_line,"Qualcomm\\Eudora\\CommandLine")
    or weakhas(selected_command_line,"RimArts\\B2\\Settings")
    or weakhas(selected_command_line,"OpenVPN-GUI\\configs")
    or weakhas(selected_command_line,"FTPWare\\COREFTP\\Sites")
    or weakhas(selected_command_line,"DownloadManager\\Passwords")
    or weakhas(selected_command_line,"OpenSSH\\Agent\\Keys")
    or weakhas(selected_command_line,"DownloadManager\\Passwords")
    or weakhas(selected_command_line,"TightVNC\\Server")
    or weakhas(selected_command_line,"ORL\\WinVNC3\\Password")
    or weakhas(selected_command_line,"RealVNC\\WinVNC4"))
group every 5m by source_ip, account, subject_username, subject_domain, source_hostname, process_name, device, client
every 5m
select process_name as ServiceName
select source_ip as entity_sourceIP
select account as entity_sourceAccount
select subject_username as entity_sourceName
select subject_domain as entity_sourceDomain
select source_hostname as entity_sourceHostname
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceDomain) as entity_sourceDomain_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceName) as entity_sourceName_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("mispIndicator", "category", entity_sourceIP) as indicator
select lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type
select lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
select lu("SecOpsAlertDescription", "alertType", "SecOpsEnumerationFor3rdPartyCredsFromCli") as alertType  
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsEnumerationFor3rdPartyCredsFromCli") as alertMitreTactics  
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsEnumerationFor3rdPartyCredsFromCli") as alertMitreTechniques  
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsEnumerationFor3rdPartyCredsFromCli") as alertPriority
```

## SecOpsFailLogOn

**Summary:** Several login attempts must be investigated because could be part of a brute force attack.

**MITRE:** Tactics: Credential Access (TA0006) | Techniques: Brute Force (T1110)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, mispIndicator, SecOpsLocation, SecOpsAlertDescription

```linq
from box.all.win
where event_id = 4625
group every 15m by source_ip, account, subject_username, subject_domain, source_hostname, device, client
every 15m
select count() as count
where count > 3
select source_ip as entity_sourceIP
select account as entity_sourceAccount
select subject_username as entity_sourceName
select subject_domain as entity_sourceDomain
select source_hostname as entity_sourceHostname
select lu("SecOpsAssetRole", "class", entity_sourceIP) as AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("mispIndicator", "category", entity_sourceIP) as indicator
select lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type
select lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsFailLogOn") as alertType  
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsFailLogOn") as alertMitreTactics  
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsFailLogOn") as alertMitreTechniques  
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsFailLogOn") as alertPriority
```

## SecOpsFsutilSuspiciousInvocation

**Summary:** Detects suspicious parameters of fsutil

**MITRE:** Tactics: Impact (TA0040) | Techniques: Data Encrypted for Impact (T1486)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, mispIndicator, SecOpsLocation, SecOpsAlertDescription

```linq
from box.all.win
where event_id = 4688
where weakhas(message, "fsutil.exe") and
(weaktoktains(message, "deletejournal") or
weaktoktains(message, "createjournal"))
group every 15m by source_ip, account, subject_username, subject_domain, source_hostname, process_name, device, client
every 15m
select process_name as ServiceName
select source_ip as entity_sourceIP
select account as entity_sourceAccount
select subject_username as entity_sourceName
select subject_domain as entity_sourceDomain
select source_hostname as entity_sourceHostname
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceDomain) as entity_sourceDomain_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceName) as entity_sourceName_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("mispIndicator", "category", entity_sourceIP) as indicator
select lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type
select lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsFsutilSuspiciousInvocation") as alertType  
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsFsutilSuspiciousInvocation") as alertMitreTactics  
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsFsutilSuspiciousInvocation") as alertMitreTechniques  
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsFsutilSuspiciousInvocation") as alertPriority
```

## SecOpsGenericRansomwareBehaviorIpScanner

**Summary:** Detects the use of Advanced IP Scanner. Seems to be a popular tool for ransomware groups.

**MITRE:** Tactics: Impact (TA0040) | Techniques: Data Encrypted for Impact (T1486)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, mispIndicator, SecOpsLocation, SecOpsAlertDescription

```linq
from box.all.win
where event_id = 4688
where weakhas(message, "advanced_ip_scanner")
group every 15m by source_ip, account, subject_username, subject_domain, source_hostname, service, device, client
every 15m
select source_ip as entity_sourceIP
select account as entity_sourceAccount
select subject_username as entity_sourceName
select subject_domain as entity_sourceDomain
select source_hostname as entity_sourceHostname
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceDomain) as entity_sourceDomain_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceName) as entity_sourceName_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("mispIndicator", "category", entity_sourceIP) as indicator
select lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type
select lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsGenericRansomwareBehaviorIpScanner") as alertType  
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsGenericRansomwareBehaviorIpScanner") as alertMitreTactics  
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsGenericRansomwareBehaviorIpScanner") as alertMitreTechniques  
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsGenericRansomwareBehaviorIpScanner") as alertPriority
```

## SecOpsHAFNIUMUmServiceSuspiciousFileTargetingExchangeServers

**Summary:** Microsoft has detected multiple 0-day exploits being used to attack on-premises versions of Microsoft Exchange Server in limited and targeted attacks.

**MITRE:** Tactics: Discovery (TA0007) | Techniques: File and Directory Discovery (T1083)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, SecOpsLocation, SecOpsAlertDescription

```linq
from box.all.win
where event_id = 4663
where weaktoktains(process_name, "umworkerprocess.exe") or
weaktoktains(process_name, "UMService.exe")
where weaktoktains(object_name, ".php") or
weaktoktains(object_name, ".jsp") or
weaktoktains(object_name, ".js") or
weaktoktains(object_name, ".aspx") or
weaktoktains(object_name, ".asmx") or
weaktoktains(object_name, ".asax") or
weaktoktains(object_name, ".cfm") or
weaktoktains(object_name, ".shtml")
group every 5m by event_id,machine_ip,account,object_name,process_name, device, client
every 5m
select str(machine_ip) as entity_sourceIP
select lu("SecOpsAssetRole", "class", entity_sourceIP) as AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsHAFNIUMUmServiceSuspiciousFileTargetingExchangeServers") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsHAFNIUMUmServiceSuspiciousFileTargetingExchangeServers") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsHAFNIUMUmServiceSuspiciousFileTargetingExchangeServers") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsHAFNIUMUmServiceSuspiciousFileTargetingExchangeServers") as alertPriority
```

## SecOpsHighVolumeFileDeletion

**Summary:** This alert detects a high volume of file deletions in a short period, as recorded in Windows logs. Such behavior is a common indicator of ransomware activity, where attackers delete large numbers of files—often after encryption—to remove traces, disable backups, or disrupt system functionality.

**Description:** Detects a high volume of file deletions in a short period, as recorded in Windows logs. Such behavior is a common indicator of ransomware activity.

**MITRE:** Tactics: Impact (TA0040) | Techniques: Data Destruction (T1485)

**Tables:** box.all.win

**Lookups:** none

```linq
from box.all.win
where (type = "sysmon" and event_id = "23")
or (type = "security" and event_id = "4660")
//select trim(split(split(message, "TargetFilename:",1), "Hashes",0)) as TargetFilename
group every 5m by username,account,source_ip,destination_ip,source_hostname,destination_hostname,process_name,source, device, client
select round(hllppcount(target_file_name)) as deleted_files_count
where deleted_files_count >= 100
select source_ip as entity_sourceIP
select destination_ip as entity_destionationIP
select source_hostname as entity_sourceHostname
select destination_hostname as entity_destinationHostname
select account as entity_sourceAccount
//<filtering_section>
select "Detection" as alertType
select "Impact" as alertMitreTactics
select "Data Destruction" as alertMitreTechniques
select 4 as alertPriority
```

## SecOpsIntegrityProblem

**Summary:** Code integrity determined that the image hash of a file is not valid. The file could be corrupt due to unauthorized modification or the invalid hash could indicate a potential disk device error. This behavior can be an indicator that the machine may be compromised.

**MITRE:** Tactics: Defense Evasion (TA0005) | Techniques: Process Injection (T1055)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, mispIndicator, SecOpsLocation, SecOpsAlertDescription

```linq
from box.all.win
where event_id = 5038
group every 30m by source_hostname, machine_ip, account, subject_domain, subject_username, file_path, device, client
every 30m
select source_hostname as entity_sourceHostname
select str(machine_ip) as entity_sourceIP
select account as entity_sourceName
select subject_domain as entity_sourceDomain
select subject_username as entity_sourceAccount
select file_path as entity_filePath
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceDomain) as entity_sourceDomain_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceName) as entity_sourceName_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select asn(ip4(entity_sourceIP)) as enrichStream_entity_sourceIP_ASN
select isp(ip4(entity_sourceIP)) as enrichStream_entity_sourceIP_ISP
select ifthenelse(toktains(lu("mispIndicator", "eventtags_name_str", str(entity_sourceIP)),"TOR"), true, false) as enrichStream_entity_sourceIP_isAnonymousProxy
select lu("mispIndicator", "category", entity_sourceIP) as indicator
select lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type
select lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsIntegrityProblem") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsIntegrityProblem") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsIntegrityProblem") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsIntegrityProblem") as alertPriority
```

## SecOpsLocalUserCreation

**Summary:** The creation of a new Windows user has been detected. Although this could be a legitimate action, It should be reviewed.

**MITRE:** Tactics: Persistence (TA0003) | Techniques: Create Account (T1136)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, mispIndicator, SecOpsLocation, SecOpsAlertDescription

```linq
from box.all.win
where event_id = 4720
group every 5m by machine_ip, account, subject_domain, source_hostname, subject_username, device, client
every 15m
select str(machine_ip) as entity_sourceIP
select subject_username as entity_sourceAccount
select account as entity_destinationAccount
select subject_domain as entity_sourceDomain
select source_hostname as entity_sourceHostname
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceDomain) as entity_sourceDomain_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_destinationAccount) as entity_destinationAccount_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("mispIndicator", "category", entity_sourceIP) as indicator
select lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type
select lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsLocalUserCreation") as alertType  
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsLocalUserCreation") as alertMitreTactics  
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsLocalUserCreation") as alertM2itreTechniques  
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsLocalUserCreation") as alertPriority
```

## SecOpsLolbinBitsadminTransfer

**Summary:** Detects a potentially malicious execution of Bitsadmin binary.

**Description:** Detected a potentially malicious Bitsadmin execution on $srcHost with ip $machineIp by user $subjectUsername. This activity should be reviewed to determine that this execution is not malicious. execution: $procCmdLine

**MITRE:** Tactics: Command and Control (TA0011) | Techniques: Ingress Tool Transfer (T1105)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.all.win
where eq(event_id,4688)
where weaktoktains(new_process_name,"bitsadmin",true,true)
where weaktoktains(process_command_line," /transfer",true,true) or (weaktoktains(process_command_line," /addfile",true,true) and weaktoktains(process_command_line," http",true,true))
group every 5m by machine_ip,subject_username,source_hostname,process_command_line, device, client
//Entity Mapping Section
select source_hostname as entity_sourceHostname
select subject_username as entity_sourceAccount
select machine_ip as entity_sourceIP
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole
//<filtering_section>
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsLolbinBitsadminTransfer") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsLolbinBitsadminTransfer") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsLolbinBitsadminTransfer") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsLolbinBitsadminTransfer") as alertPriority
```

## SecOpsLolbinCertocexecution

**Summary:** Detects a malicious execution of certoc.exe that could be trying to download a file to the target machine or load an arbitrary DLL file.

**Description:** Detected execution of certoc.exe that could be trying to download a file or load a DLL library on $srcHost with ip $machineIp. Execution: $message

**MITRE:** Tactics: Command and Control (TA0011), Defense Evasion (TA0005) | Techniques: Ingress Tool Transfer (T1105), System Binary Proxy Execution (T1105)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.all.win
where eq(event_id,4688)
where `or`(toktains(new_process_name,"certoc.exe",true,true),toktains(process_name,"certoc.exe",true,true))
where `or`(weaktoktains(message,"-LoadDLL",true,true), weaktoktains(payload,"/LoadDLL",true,true), weaktoktains(payload,"-GetCACAPS",true,true), weaktoktains(payload,"/GetCACAPS",true,true))
group every 5m by machine_ip, source_hostname, message, device, client
//Entity Mapping Section
select source_hostname as entity_sourceHostname
select machine_ip as entity_sourceIP
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole
//<filtering_section>
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsLolbinCertocexecution") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsLolbinCertocexecution") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsLolbinCertocexecution") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsLolbinCertocexecution") as alertPriority
```

## SecOpsLolbinCertreq

**Summary:** Detects a potentially malicious execution of CertReq.

**Description:** Detected a potentially malicious CertReq execution on $srcHost with ip $machineIp by user $subjectUsername. This activity should be reviewed to determine that the execution is not malicious. execution: $procCmdLine

**MITRE:** Tactics: Command and Control (TA0011), Exfiltration (TA0010) | Techniques: Ingress Tool Transfer (T1105), Exfiltration Over Alternative Protocol (T1048)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.all.win
where eq(event_id,4688)
where weaktoktains(new_process_name,"certreq.exe",true,true)
where `and`( (weaktoktains(process_command_line,"-post",true,true) or weaktoktains(process_command_line,"/post",true,true)),(weaktoktains(process_command_line,"-config",true,true) or weaktoktains(process_command_line,"/config",true,true)),weaktoktains(process_command_line,"http",true,true))
group every 5m by machine_ip,subject_username,source_hostname,process_command_line, device, client
//Entity Mapping Section
select source_hostname as entity_sourceHostname
select subject_username as entity_sourceAccount
select machine_ip as entity_sourceIP
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole
//<filtering_section>
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsLolbinCertreq") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsLolbinCertreq") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsLolbinCertreq") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsLolbinCertreq") as alertPriority
```

## SecOpsLolbinCertutil

**Summary:** Detects a potentially malicious execution of certutil.

**Description:** Detected a potential malicious certutil execution on $srcHost by user $subjectUsername. This activity should be reviewed to determine that the execution is not malicious. execution: $procCmdLine

**MITRE:** Tactics: Command and Control (TA0011), Defense Evasion (TA0005) | Techniques: Ingress Tool Transfer (T1105), Deobfuscate/Decode Files or Information (T1140), Obfuscated Files or Information (T1027)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.all.win
where event_id=4688
where weaktoktains(new_process_name,"certutil.exe",true,true)
where `or`(weaktoktains(process_command_line,"-urlcache",true,true),weaktoktains(process_command_line,"/urlcache",true,true),weaktoktains(process_command_line,"-verifyctl",true,true), weaktoktains(process_command_line,"/verifyctl",true,true),weaktoktains(process_command_line,"-encode",true,true),weaktoktains(process_command_line,"/encode",true,true),weaktoktains(process_command_line,"-decode",true,true),weaktoktains(process_command_line,"/decode",true,true),weaktoktains(process_command_line,"-decodehex",true,true),weaktoktains(process_command_line,"/decodehex",true,true))
group every 5m by subject_username,source_hostname,process_command_line, device, client
//Entity Mapping Section
select source_hostname as entity_sourceHostname
select subject_username as entity_sourceAccount
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole
//<filtering_section>
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsLolbinCertutil") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsLolbinCertutil") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsLolbinCertutil") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsLolbinCertutil") as alertPriority
```

## SecOpsLolbinConfigsecuritypolicy

**Summary:** Detects a potentially malicious execution of ConfigSecurityPolicy.

**Description:** Detected a potentially malicious CertReq execution on $srcHost with ip $machineIp by user $subjectUsername. This activity should be reviewed to determine that the execution is not malicious. execution: $procCmdLine

**MITRE:** Tactics: Command and Control (TA0011), Exfiltration (TA0010) | Techniques: Ingress Tool Transfer (T1105), Exfiltration Over Web Service (T1567)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.all.win
where eq(event_id,4688)
where weaktoktains(new_process_name,"ConfigSecurityPolicy",true,true)
where `or`(weaktoktains(process_command_line,"http://",true,true), weaktoktains(process_command_line,"https://",true,true),weaktoktains(process_command_line,"ftp://",true,true))
group every 5m by machine_ip,subject_username,source_hostname,process_command_line, device, client
//Entity Mapping Section
select source_hostname as entity_sourceHostname
select subject_username as entity_sourceAccount
select machine_ip as entity_sourceIP
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole
//<filtering_section>
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsLolbinConfigsecuritypolicy") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsLolbinConfigsecuritypolicy") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsLolbinConfigsecuritypolicy") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsLolbinConfigsecuritypolicy") as alertPriority
```

## SecOpsLolbinDatasvcutil

**Summary:** Detects a potentially malicious execution of DataSvcUtil binary.

**Description:** Detected a potentially malicious DataSvcUtil execution on $srcHost with ip $machineIp by user $subjectUsername. This activity should be reviewed to determine that this execution is not malicious. execution: $procCmdLine

**MITRE:** Tactics: Exfiltration (TA0010) | Techniques: Exfiltration Over Web Service (T1567)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.all.win
where eq(event_id,4688)
where weaktoktains(new_process_name,"DataSvcUtil",true,true)
where (weaktoktains(process_command_line," /uri:",true,true) or weaktoktains(process_command_line," -uri:",true,true)) and (weaktoktains(process_command_line," /out:",true,true) or weaktoktains(process_command_line," -out:",true,true))
group every 5m by machine_ip,subject_username,source_hostname,process_command_line, device, client
//Entity Mapping Section
select source_hostname as entity_sourceHostname
select subject_username as entity_sourceAccount
select machine_ip as entity_sourceIP
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole
//<filtering_section>
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsLolbinDatasvcutil") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsLolbinDatasvcutil") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsLolbinDatasvcutil") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsLolbinDatasvcutil") as alertPriority
```

## SecOpsLolbinMshta

**Summary:** Detects a potentially malicious execution of Mshta.

**Description:** Detected a potentially malicious Mshta execution on $srcHost with ip $machineIp by user $subjectUsername. This activity should be reviewed to determine that the execution is not malicious. execution: $procCmdLine

**MITRE:** Tactics: Command and Control (TA0011), Defense Evasion (TA0005) | Techniques: Ingress Tool Transfer (T1105), System Binary Proxy Execution (T1218)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.all.win
where eq(event_id,4688)
where weaktoktains(new_process_name,"Mshta",true,true)
where `or`(weaktoktains(process_command_line,"http://",true,true),weaktoktains(process_command_line,"https://",true,true),weaktoktains(process_command_line,"https://",true,true),weaktoktains(process_command_line,"ftp://",true,true),weaktoktains(process_command_line,"javascript",true,true),weaktoktains(process_command_line,"vbscript",true,true),weaktoktains(process_command_line,".htm",true,true))
group every 5m by machine_ip,subject_username,source_hostname,process_command_line, device, client
//Entity Mapping Section
select source_hostname as entity_sourceHostname
select subject_username as entity_sourceAccount
select machine_ip as entity_sourceIP
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole
//<filtering_section>
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsLolbinMshta") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsLolbinMshta") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsLolbinMshta") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsLolbinMshta") as alertPriority
```

## SecOpsLsassDumpKeywordInCommandLine

**Summary:** Detects suspicious usage of keywords in the command line that may indicate a memory dump of the LSASS process — a common technique used for credential theft.

**MITRE:** Tactics: Credential Access (TA0006) | Techniques: OS Credential Dumping (T1003)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, mispIndicator, SecOpsAlertDescription

```linq
from box.all.win
where event_id = 4688
select ifthenelse(process_command_line = null, new_process_name, process_command_line) as selected_command_line
where (weakhas(selected_command_line,"lsass.dmp")
        or weakhas(selected_command_line,"lsass.zip")
        or weakhas(selected_command_line,"lsass.rar")
        or weakhas(selected_command_line,"Andrew.dmp")
        or weakhas(selected_command_line,"Coredump.dmp")
        or weakhas(selected_command_line,"NotLSASS.zip")
        or weakhas(selected_command_line,"lsass_2")
        or weakhas(selected_command_line,"lsassdump")
        or weakhas(selected_command_line,"lsassdmp")
        or (weakhas(selected_command_line,"lsass") and weakhas(selected_command_line,".dmp"))
        or (weakhas(selected_command_line,"SQLDmpr") and weakhas(selected_command_line,".mdmp"))
        or (weakhas(selected_command_line,"nanodump") and weakhas(selected_command_line,".dmp")))
group every 5m by source_ip, account, subject_username, subject_domain, source_hostname, process_name, device, client
every 5m
select process_name as ServiceName
select source_ip as entity_sourceIP
select account as entity_sourceAccount
select subject_username as entity_sourceName
select subject_domain as entity_sourceDomain
select source_hostname as entity_sourceHostname
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceDomain) as entity_sourceDomain_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceName) as entity_sourceName_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("mispIndicator", "category", entity_sourceIP) as indicator
select lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type
select lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
select lu("SecOpsAlertDescription", "alertType", "SecOpsLsassDumpKeywordInCommandLine") as alertType  
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsLsassDumpKeywordInCommandLine") as alertMitreTactics  
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsLsassDumpKeywordInCommandLine") as alertMitreTechniques  
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsLsassDumpKeywordInCommandLine") as alertPriority
```

## SecOpsMaliciousPowerShellCommandletNames

**Summary:** Detects the creation of known PowerShell scripts for exploitation.

**MITRE:** Tactics: Execution (TA0002) | Techniques: Command and Scripting Interpreter (T1059)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, mispIndicator, SecOpsLocation, SecOpsAlertDescription

```linq
from box.all.win
where event_id = 4663
group every 5m by message, source_ip, account, subject_username, subject_domain, source_hostname, device, client
every 15m
where message -> {"Invoke-DllInjection.ps1","Invoke-WmiCommand.ps1","Get-GPPPassword.ps1","Get-Keystrokes.ps1","Get-VaultCredential.ps1","Invoke-CredentialInjection.ps1","Invoke-Mimikatz.ps1","Invoke-NinjaCopy.ps1","Invoke-TokenManipulation.ps1","Out-Minidump.ps1","VolumeShadowCopyTools.ps1","Invoke-ReflectivePEInjection.ps1","Get-TimedScreenshot.ps1","Invoke-UserHunter.ps1","Find-GPOLocation.ps1","Invoke-ACLScanner.ps1","Invoke-DowngradeAccount.ps1","Get-ServiceUnquoted.ps1","Get-ServiceFilePermission.ps1","Get-ServicePermission.ps1","Invoke-ServiceAbuse.ps1","Install-ServiceBinary.ps1","Get-RegAutoLogon.ps1","Get-VulnAutoRun.ps1","Get-VulnSchTask.ps1","Get-UnattendedInstallFile.ps1","Get-WebConfig.ps1","Get-ApplicationHost.ps1","Get-RegAlwaysInstallElevated.ps1","Get-Unconstrained.ps1","Add-RegBackdoor.ps1","Add-ScrnSaveBackdoor.ps1","Gupt-Backdoor.ps1","Invoke-ADSBackdoor.ps1","Enabled-DuplicateToken.ps1","Invoke-PsUaCme.ps1","Remove-Update.ps1","Check-VM.ps1","Get-LSASecret.ps1","Get-PassHashes.ps1","Show-TargetScreen.ps1","Port-Scan.ps1","Invoke-PoshRatHttp.ps1","Invoke-PowerShellTCP.ps1","Invoke-PowerShellWMI.ps1","Add-Exfiltration.ps1","Add-Persistence.ps1","Do-Exfiltration.ps1","Start-CaptureServer.ps1","Invoke-ShellCode.ps1","Get-ChromeDump.ps1","Get-ClipboardContents.ps1","Get-FoxDump.ps1","Get-IndexedItem.ps1","Get-Screenshot.ps1","Invoke-Inveigh.ps1","Invoke-NetRipper.ps1","Invoke-EgressCheck.ps1","Invoke-PostExfil.ps1","Invoke-PSInject.ps1","Invoke-RunAs.ps1","MailRaider.ps1","New-HoneyHash.ps1","Set-MacAttribute.ps1","Invoke-DCSync.ps1","Invoke-PowerDump.ps1","Exploit-Jboss.ps1","Invoke-ThunderStruck.ps1","Invoke-VoiceTroll.ps1","Set-Wallpaper.ps1","Invoke-InveighRelay.ps1","Invoke-PsExec.ps1","Invoke-SSHCommand.ps1","Get-SecurityPackages.ps1","Install-SSP.ps1","Invoke-BackdoorLNK.ps1","PowerBreach.ps1","Get-SiteListPassword.ps1","Get-System.ps1","Invoke-BypassUAC.ps1","Invoke-Tater.ps1","Invoke-WScriptBypassUAC.ps1","PowerUp.ps1","PowerView.ps1","Get-RickAstley.ps1","Find-Fruit.ps1","HTTP-Login.ps1","Find-TrustedDocuments.ps1","Invoke-Paranoia.ps1","Invoke-WinEnum.ps1","Invoke-ARPScan.ps1","Invoke-PortScan.ps1","Invoke-ReverseDNSLookup.ps1","Invoke-SMBScanner.ps1","Invoke-Mimikittenz.ps1"}
select source_ip as entity_sourceIP
select account as entity_sourceAccount
select subject_username as entity_sourceName
select subject_domain as entity_sourceDomain
select source_hostname as entity_sourceHostname
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceDomain) as entity_sourceDomain_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceName) as entity_sourceName_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("mispIndicator", "category", entity_sourceIP) as indicator
select lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type
select lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsMaliciousPowerShellCommandletNames") as alertType  
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsMaliciousPowerShellCommandletNames") as alertMitreTactics  
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsMaliciousPowerShellCommandletNames") as alertMitreTechniques  
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsMaliciousPowerShellCommandletNames") as alertPriority
```

## SecOpsMaliciousPowerShellPrebuiltCommandlet

**Summary:** Detects PowerShell script execution of known PowerShell scripts for exploitation.

**MITRE:** Tactics: Execution (TA0002) | Techniques: Command and Scripting Interpreter (T1059)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, mispIndicator, SecOpsLocation, SecOpsAlertDescription

```linq
from box.all.win
where event_id = 4104
group every 5m by message, source_ip, account, subject_username, subject_domain, source_hostname, process_command_line, device, client
every 15m
where process_command_line -> {"Get-Job" ,"Receive-Job" ,"Get-ScheduledJob" ,"Export-ScheduledTask" ,"Get-ScheduledTask" ,"Get-GPO" ,"Get-NetTCPConnection" ,"Get-Process" ,"Get-ADDefaultDomainPasswordPolicy" ,"Get-Service" ,"Get-ItemProperty HKLM" ,"Get-ADComputer" ,"Get-ADUser" ,"Get-LocalGroup" ,"Get-LocalGroupMember" ,"Get-LocalUser" ,"Get-ExecutionPolicy"}
or (process_command_line -> "Set-ExecutionPolicy" and not process_command_line -> "Restricted")
or (process_command_line -> "Get-ADGroupMember" and process_command_line -> "Administrators")
or (process_command_line -> "Get-CimInstance" and process_command_line -> "UserName")
select source_ip as entity_sourceIP
select account as entity_sourceAccount
select subject_username as entity_sourceName
select subject_domain as entity_sourceDomain
select source_hostname as entity_sourceHostname
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceDomain) as entity_sourceDomain_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceName) as entity_sourceName_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("mispIndicator", "category", entity_sourceIP) as indicator
select lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type
select lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsMaliciousPowerShellPrebuiltCommandlet") as alertType  
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsMaliciousPowerShellPrebuiltCommandlet") as alertMitreTactics  
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsMaliciousPowerShellPrebuiltCommandlet") as alertMitreTechniques  
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsMaliciousPowerShellPrebuiltCommandlet") as alertPriority
```

## SecOpsMaliciousServiceInstallations

**Summary:** Monitor service creation through changes in the Registry and common utilities using command-line invocation.

**MITRE:** Tactics: Persistence (TA0003) | Techniques: Create or Modify System Process (T1543)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, mispIndicator, SecOpsLocation, SecOpsAlertDescription

```linq
from box.all.win
where event_id = 7045 or event_id = 4697
group every 5m by process_name, machine_ip, account, subject_username, subject_domain, source_hostname, message, device, client
every 15m
select process_name as ServiceName
where toktains(ServiceName, "WCESERVICE") or
toktains(ServiceName, "WCE SERVICE") or
toktains(ServiceName, "mssecsvc2.0") or
toktains(ServiceName, "pwdump") or
toktains(ServiceName, "gsecdump") or
toktains(ServiceName, "cachedump") or
toktains(message, "PAExec") or
toktains(message, "winexesvc.exe") or
toktains(message, "DumpSvc.exe") or
toktains(message, "net user") or
toktains(message, "ipvpn")
select str(machine_ip) as entity_sourceIP
select account as entity_sourceAccount
select subject_username as entity_sourceName
select subject_domain as entity_sourceDomain
select source_hostname as entity_sourceHostname
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceDomain) as entity_sourceDomain_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceName) as entity_sourceName_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("mispIndicator", "category", entity_sourceIP) as indicator
select lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type
select lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsMaliciousServiceInstallations") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsMaliciousServiceInstallations") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsMaliciousServiceInstallations") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsMaliciousServiceInstallations") as alertPriority
```

## SecOpsMoveitCmdlineFileCreation

**Summary:** This alert detects the creation of files with 'cmdline in the filename, which is a common technique used by attackers exploiting vulnerabilities like those in MOVEit to gain command execution. By creating cmdline files, attackers can script commands or automate tasks on the compromised system.

**Description:** Detects the creation of files with 'cmdline in the filename, which is a common technique used by attackers exploiting vulnerabilities like those in MOVEit to gain command execution.

**MITRE:** Tactics: Execution (TA0002) | Techniques: Command and Scripting Interpreter (T1059)

**Tables:** box.all.win

**Lookups:** none

```linq
from box.all.win
where eventID = 4656
where toktains(objName, ".cmdline", true, true)
group every 5m by subject_username,account,subject_domain,source_ip,destination_ip,source_hostname,destination_hostname,process_name,process_command_line,source
select source_ip as entity_sourceIP
select destination_ip as entity_destinationIP
select account as entity_sourceAccount
select subject_username as entity_sourceName
select subject_domain as entity_sourceDomain
select source_hostname as entity_sourceHostname
select destination_hostname as entity_destinationHostname
//<filtering_section>
select "Detection" as alertType
select "Execution" as alertMitreTactics
select "Command and Scripting Interpreter" as alertMitreTechniques
select 2 as alertPriority
```

## SecOpsMoveitDynamicCompilationViaCscExe

**Summary:** This alert detects the compilation of .aspx files, a behavior often associated with persistence mechanisms in the context of web server exploitation, such as the MOVEit vulnerability. Attackers exploiting the MOVEit Transfer vulnerability (CVE-2023-34362) may upload and compile .aspx files to establish backdoors or maintain persistent access to the compromised server.

**MITRE:** Tactics: Persistence (TA0003) | Techniques: Server Software Component (T1505)

**Tables:** box.all.win

**Lookups:** none

```linq
from box.all.win
where toktains(parent_command_line, "w3wp.exe")
where toktains(process_command_line, "csc.exe")
group every 5m by subject_username,account,subject_domain,source_ip,destination_ip,source_hostname,destination_hostname,process_name,process_command_line,parent_command_line, device, client,source
select source_ip as entity_sourceIP
select destination_ip as entity_destinationIP
select account as entity_sourceAccount
select subject_username as entity_sourceName
select subject_domain as entity_sourceDomain
select source_hostname as entity_sourceHostname
select destination_hostname as entity_destinationHostname
//<filtering_section>
select "Detection" as alertType
select "Persistence" as alertMitreTactics
select "Server Software Component" as alertMitreTechniques
select 3 as alertPriority
```

## SecOpsMoveitFilePotentialActivityTransferExploitation

**Summary:** Detects file indicators of potential exploitation of MOVEit CVE-2023-34362.

**MITRE:** Tactics: Initial Access (TA0001) | Techniques: Exploit Public-Facing Application (T1190)

**Tables:** box.all.win

**Lookups:** none

```linq
from box.all.win
where ((toktains(process_command_line, "\\MOVEit Transfer\\wwwroot\\", true, true)
    or toktains(process_command_line, "\\MOVEitTransfer\\wwwroot\\", true, true))
and (endswith(process_command_line, ".7z") or endswith(process_command_line, ".bat")
    or endswith(process_command_line, ".dll") or endswith(process_command_line, ".exe")
    or endswith(process_command_line, ".ps1") or endswith(process_command_line, ".rar")
    or endswith(process_command_line, ".vbe") or endswith(process_command_line, ".vbs")
    or endswith(process_command_line, ".zip")))
or (endswith(process_command_line, "\\MOVEit Transfer\\wwwroot\\_human2.aspx.lnk")
    or endswith(process_command_line, "\\MOVEit Transfer\\wwwroot\\_human2.aspx")
    or endswith(process_command_line, "\\MOVEit Transfer\\wwwroot\\human2.aspx.lnk")
    or endswith(process_command_line, "\\MOVEit Transfer\\wwwroot\\human2.aspx")
    or endswith(process_command_line, "\\MOVEitTransfer\\wwwroot\\_human2.aspx.lnk")
    or endswith(process_command_line, "\\MOVEitTransfer\\wwwroot\\_human2.aspx")
    or endswith(process_command_line, "\\MOVEitTransfer\\wwwroot\\human2.aspx.lnk")
    or endswith(process_command_line, "\\MOVEitTransfer\\wwwroot\\human2.aspx"))
or ((toktains(process_command_line, "\\Windows\\Microsoft.net\\Framework64\\v", true, true)
    and toktains(process_command_line, "\\Temporary ASP.NET Files\\", true, true)
    and toktains(process_command_line, "App_Web_", true, true))
    and endswith(process_command_line, ".dll"))
group every 5m by subject_username,account,subject_domain,source_ip,destination_ip,source_hostname,destination_hostname,process_name,process_command_line,source
select source_ip as entity_sourceIP
select destination_ip as entity_destinationIP
select account as entity_sourceAccount
select subject_username as entity_sourceName
select subject_domain as entity_sourceDomain
select source_hostname as entity_sourceHostname
select destination_hostname as entity_destinationHostname
//<filtering_section>
select "Detection" as alertType
select "Initial Access" as alertMitreTactics
select "Exploit Public-Facing Application" as alertMitreTechniques
select 3 as alertPriority
```

## SecOpsMultipleMachineAccessedbyUser

**Summary:** The access of a single user to multiple systems simultaneously in a short period of time can be a behavior associated with a threat.

**MITRE:** Tactics: Exfiltration (TA0010) | Techniques: Exfiltration Over C2 Channel (T1041)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, mispIndicator, SecOpsAlertDescription

```linq
from box.all.win
where event_id = 4624
where not subject_username -> "$"
where LogonType = "3" or LogonType = "2" or LogonType = "9" or LogonType = "10"
where not subject_username -> "-"
group every 5m by subject_username, account, machine_ip, subject_domain, source_ip, device, client
every 30m
select count() as count
select hllppcount(source_hostname) as diferent_entity_sourceHostname
where diferent_entity_sourceHostname >= 2
select subject_username as entity_sourceName
select machine_ip as entity_sourceIP
select nnlast(source_hostname) as entity_sourceHostname
select subject_domain as entity_sourceDomain
select account as entity_sourceAccount
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceDomain) as entity_sourceDomain_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", str(entity_sourceIP)) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceName) as entity_sourceName_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select asn(ip4(source_ip)) as enrichStream_entity_sourceIP_ASN
select isp(ip4(source_ip)) as enrichStream_entity_sourceIP_ISP
select ifthenelse(toktains(lu("mispIndicator", "eventtags_name_str", str(source_ip)),"TOR"), true, false) as enrichStream_entity_sourceIP_isAnonymousProxy
select lu("SecOpsAlertDescription", "alertType", "SecOpsMultipleMachineAccessedbyUser") as alertType  
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsMultipleMachineAccessedbyUser") as alertMitreTactics  
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsMultipleMachineAccessedbyUser") as alertMitreTechniques  
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsMultipleMachineAccessedbyUser") as alertPriority
```

## SecOpsNewAccountCreated

**Summary:** Creating new users on Active Directory should be monitored.

**MITRE:** Tactics: Persistence (TA0003) | Techniques: Account Manipulation (T1098)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, mispIndicator, SecOpsLocation, SecOpsAlertDescription

```linq
from box.all.win
where event_id = 4720
group every 5m by source_ip, account, subject_username, source_hostname, subject_domain, extended_message, device, client
every 5m
select source_ip as entity_sourceIP
select source_hostname as entity_sourceHostname
select lu("SecOpsAssetRole", "class", entity_sourceIP) as AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select asn(ip4(source_ip)) as enrichStream_entity_sourceIP_ASN
select isp(ip4(source_ip)) as enrichStream_entity_sourceIP_ISP
select ifthenelse(toktains(lu("mispIndicator", "eventtags_name_str", str(source_ip)),"TOR"), true, false) as enrichStream_entity_sourceIP_isAnonymousProxy
select lu("mispIndicator", "category", entity_sourceIP) as indicator,
       lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type,
       lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
select account as entity_sourceAccount
select subject_username as entity_sourceName
select subject_domain as entity_sourceDomain
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsNewAccountCreated") as alertType  
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsNewAccountCreated") as alertMitreTactics  
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsNewAccountCreated") as alertMitreTechniques  
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsNewAccountCreated") as alertPriority
```

## SecOpsNtdsDitDomainHashExtractionActivity

**Summary:** Detects suspicious activity on NTDS.dit

**MITRE:** Tactics: Credential Access (TA0006) | Techniques: OS Credential Dumping (T1003)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, mispIndicator, SecOpsLocation, SecOpsAlertDescription

```linq
from box.all.win
where event_id = 4688
where
weakhas(message, "vssadmin.exe Delete Shadows") or
weaktoktains(message, "vssadmin create shadow /for=C:") or
weaktoktains(message, "copy \\\\?\\GLOBALROOT\\Device\\\\*\\windows\\ntds\\ntds.dit") or
weaktoktains(message, "copy \\\\?\\GLOBALROOT\\Device\\\\*\\config\\\\SAM") or
weaktoktains(message, "vssadmin delete shadows /for=C:") or
weaktoktains(message, "reg SAVE HKLM\\\\SYSTEM") or
weaktoktains(message, "esentutl.exe /y /vss *\\ntds.dit*") or
weaktoktains(message, "esentutl.exe /y /vss *\\SAM") or
weaktoktains(message, "esentutl.exe /y /vss *\\SYSTEM")
group every 5m by source_ip, machine, account, subject_username, subject_domain, source_hostname, process_name, device, client
every 15m
select process_name as ServiceName
select source_ip as entity_sourceIP
select account as entity_sourceAccount
select subject_username as entity_sourceName
select subject_domain as entity_sourceDomain
select source_hostname as entity_sourceHostname
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceDomain) as entity_sourceDomain_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceName) as entity_sourceName_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("mispIndicator", "category", entity_sourceIP) as indicator
select lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type
select lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsNtds.ditDomainHashExtractionActivity") as alertType  
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsNtds.ditDomainHashExtractionActivity") as alertMitreTactics  
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsNtds.ditDomainHashExtractionActivity") as alertMitreTechniques  
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsNtds.ditDomainHashExtractionActivity") as alertPriority
```

## SecOpsOsCredentialDumpingGsecdump

**Summary:** Detects well-known credential dumping tools execution via service execution events.

**MITRE:** Tactics: Credential Access (TA0006) | Techniques: OS Credential Dumping (T1003)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, mispIndicator, SecOpsLocation, SecOpsAlertDescription

```linq
from box.all.win
where event_id = 4688
where weaktoktains(process_command_line, "gsecdump.exe")
group every 5m by source_hostname, subject_username, machine_ip, subject_domain, procName, objName, device, client
every 5m
//Entity Mapping Section
select source_hostname as entity_sourceHostname
select subject_username as entity_sourceAccount
select str(machine_ip) as entity_sourceIP
select subject_domain as entity_sourceDomain// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_sourceIP) as AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select asn(ip4(machine_ip)) as enrichStream_entity_sourceIP_ASN
select isp(ip4(machine_ip)) as enrichStream_entity_sourceIP_ISP
select lu("mispIndicator", "category", entity_sourceIP) as indicator
select lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type
select lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsOsCredentialDumpingGsecdump") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsOsCredentialDumpingGsecdump") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsOsCredentialDumpingGsecdump") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsOsCredentialDumpingGsecdump") as alertPriority
```

## SecOpsPassTheHashActivityLoginBehaviour

**Summary:** 

**Description:** Unusual remote logins that correlate with other suspicious activity (such as writing and executing binaries) may indicate malicious activity related to Pass The Hash technique.

**MITRE:** Tactics: Defense Evasion (TA0005) | Techniques: Use Alternate Authentication Material (T1550)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, mispIndicator, SecOpsLocation, SecOpsAlertDescription

```linq
from box.all.win
where event_id = 4624 or event_id = 4625
where toktains(message, "NtLmSsp")
group every 5m by source_ip, account, subject_username, subject_domain, source_hostname, process_name, device, client
every 1h
select process_name as ServiceName
select source_ip as entity_sourceIP
select round(hllppcount(event_id)) as eventIDDiff
select nnfirst(event_id) as eventIDFirst
select nnlast(event_id) as eventIDLast
where eventIDDiff = 2
select account as entity_sourceAccount
select subject_username as entity_sourceName
select subject_domain as entity_sourceDomain
select source_hostname as entity_sourceHostname
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceDomain) as entity_sourceDomain_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceName) as entity_sourceName_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("mispIndicator", "category", entity_sourceIP) as indicator
select lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type
select lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsPassTheHashActivityLoginBehaviour") as alertType  
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsPassTheHashActivityLoginBehaviour") as alertMitreTactics  
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsPassTheHashActivityLoginBehaviour") as alertMitreTechniques  
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsPassTheHashActivityLoginBehaviour") as alertPriority
```

## SecOpsPersistenceAndExecutionViaGPOScheduledTask

**Summary:** Persistence and Execution at Scale via GPO Scheduled Task

**MITRE:** Tactics: Command and Control (TA0011) | Techniques: Ingress Tool Transfer (T1105)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, mispIndicator, SecOpsLocation, SecOpsAlertDescription

```linq
from box.all.win
where event_id = 5145,
weakhas(message, "ScheduledTasks") and
weakhas(message, "SYSVOL") and
weakhas(message, "WriteData")
group every 10m by machine_ip,source_ip,account,subject_username,subject_domain,source_hostname,process_name, device, client
every 30m
where str(machine_ip) != source_ip
select process_name as ServiceName
select source_ip as entity_sourceIP
select str(machine_ip) as entity_destinationIP
select account as entity_destinationAccount
select subject_username as entity_destinationName
select subject_domain as entity_destinationDomain
select source_hostname as entity_destinationHostname
select lu("SecOpsAssetRole", "class", entity_destinationHostname) as entity_destinationHostname_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_destinationDomain) as entity_destinationDomain_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_destinationName) as entity_destinationName_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_destinationAccount) as entity_destinationAccount_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_destinationIP) as entity_destinationIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("mispIndicator", "category", entity_sourceIP) as indicator
select lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type
select lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
select lu("SecOpsLocation", "country", entity_destinationIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_destinationIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_destinationIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_destinationIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_destinationIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsPersistenceAndExecutionViaGPOScheduledTask") as alertType  
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsPersistenceAndExecutionViaGPOScheduledTask") as alertMitreTactics  
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsPersistenceAndExecutionViaGPOScheduledTask") as alertMitreTechniques  
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsPersistenceAndExecutionViaGPOScheduledTask") as alertPriority
```

## SecOpsPotentiallySuspiciousEventLogReconActivity

**Summary:** This alert detects the execution of utilities and commands that query or dump specific event logs, which may indicate attempts to extract sensitive information from event logs.

**MITRE:** Tactics: Credential Access (TA0006) | Techniques: OS Credential Dumping (T1003)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, mispIndicator, SecOpsAlertDescription

```linq
from box.all.win
where event_id = 4688 or event_id = 4624
where rawMessage -> "InstanceId"
where weakhas(parent_process_name,"powershell")
select ifthenelse(process_command_line = null, new_process_name, process_command_line) as selected_command_line
where ((toktains(selected_command_line, "Microsoft-Windows-PowerShell", true, true)
        or toktains(selected_command_line, "Microsoft-Windows-Security-Auditing", true, true)
        or toktains(selected_command_line, "Microsoft-Windows-TerminalServices-LocalSessionManager", true, true)
        or toktains(selected_command_line, "Microsoft-Windows-TerminalServices-RemoteConnectionManager", true, true)
        or toktains(selected_command_line, "Microsoft-Windows-Windows Defender", true, true)
        or toktains(selected_command_line, "PowerShellCore", true, true)
        or toktains(selected_command_line, "Security", true, true)
        or toktains(selected_command_line, "Windows PowerShell", true, true))
        or (toktains(selected_command_line,"-InstanceId 462" )
            or toktains(selected_command_line,"eventid -eq 462" )
            or toktains(selected_command_line,"EventCode= 462" )
            or toktains(selected_command_line,"EventIdentifier=462" )
            or toktains(selected_command_line,"System[EventID=462" )
            or toktains(selected_command_line, "-InstanceId 4778", true, true)
            or toktains(selected_command_line, "eventid -eq 4778", true, true)
            or toktains(selected_command_line, "System[EventID=4778]", true, true)
            or toktains(selected_command_line,"EventCode= 4778" )
            or toktains(selected_command_line,"EventIdentifier= 4778" )
            or toktains(selected_command_line, "-InstanceId 25", true, true)
            or toktains(selected_command_line, ".eventid -eq 25", true, true)
            or toktains(selected_command_line, "System[EventID=25]", true, true)
            or toktains(selected_command_line,"EventCode= 25")
            or toktains(selected_command_line,"EventIdentifier= 25"))
        and ((toktains(selected_command_line, "Select", true, true) and toktains(selected_command_line, "Win32_NTLogEvent", true, true))
            or ((endswith(image, "wevtutil.exe") or original_file_name = "wevtutil.exe") and (toktains(selected_command_line, " qe ", true, true) or toktains(selected_command_line, " query-events ", true, true)))
            or ((endswith(image, "wmic.exe") or original_file_name = "wmic.exe")
            and toktains(selected_command_line, " ntevent", true, true))
            or (toktains(selected_command_line, "Get-WinEvent ", true, true)
            or toktains(selected_command_line, "get-eventlog ", true, true))))
group every 5m by source_ip, account, subject_username, subject_domain, source_hostname, process_name, device, client
every 5m
select process_name as ServiceName
select source_ip as entity_sourceIP
select account as entity_sourceAccount
select subject_username as entity_sourceName
select subject_domain as entity_sourceDomain
select source_hostname as entity_sourceHostname
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceDomain) as entity_sourceDomain_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceName) as entity_sourceName_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("mispIndicator", "category", entity_sourceIP) as indicator
select lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type
select lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
select lu("SecOpsAlertDescription", "alertType", "SecOpsPotentiallySuspiciousEventLogReconActivity") as alertType  
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsPotentiallySuspiciousEventLogReconActivity") as alertMitreTactics  
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsPotentiallySuspiciousEventLogReconActivity") as alertMitreTechniques  
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsPotentiallySuspiciousEventLogReconActivity") as alertPriority
```

## SecOpsPsExecToolExecution

**Summary:** Detects PsExec service installation and execution events.

**MITRE:** Tactics: Credential Access (TA0006) | Techniques: OS Credential Dumping (T1003)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, mispIndicator, SecOpsLocation, SecOpsAlertDescription

```linq
from box.all.win
where event_id = 7045,
eqic(object_name, "PSEXESVC")
group every 5m by source_ip, account, subject_username, subject_domain, source_hostname, process_name, device, client
every 15m
select process_name as ServiceName
select source_ip as entity_sourceIP
select account as entity_sourceAccount
select subject_username as entity_sourceName
select subject_domain as entity_sourceDomain
select source_hostname as entity_sourceHostname
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceDomain) as entity_sourceDomain_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceName) as entity_sourceName_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("mispIndicator", "category", entity_sourceIP) as indicator
select lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type
select lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsPsExecToolExecution") as alertType  
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsPsExecToolExecution") as alertMitreTactics  
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsPsExecToolExecution") as alertMitreTechniques  
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsPsExecToolExecution") as alertPriority
```

## SecOpsPuaFastReverseProxyExecution

**Summary:** This alert detects the execution of Fast Reverse Proxy (FRP) tools, such as frpc.exe and frps.exe, which are used to expose local servers behind NATs or firewalls to the Internet.

**MITRE:** Tactics: Command and Control (TA0011) | Techniques: Proxy (T1059)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, mispIndicator, SecOpsAlertDescription

```linq
from box.all.win
where event_id = 4688
select ifthenelse(process_command_line = null, new_process_name, process_command_line) as selected_command_line
where ((weakhas(selected_command_line, "frpc.") or weakhas(selected_command_line, "frps."))
and (weakhas(selected_command_line, "BrightmetricAgent.") or weakhas(selected_command_line, "SMSvcService.")))
group every 5m by source_ip, account, subject_username, subject_domain, source_hostname, process_name, device, client
every 5m
select process_name as ServiceName
select source_ip as entity_sourceIP
select account as entity_sourceAccount
select subject_username as entity_sourceName
select subject_domain as entity_sourceDomain
select source_hostname as entity_sourceHostname
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceDomain) as entity_sourceDomain_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceName) as entity_sourceName_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("mispIndicator", "category", entity_sourceIP) as indicator
select lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type
select lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
select lu("SecOpsAlertDescription", "alertType", "SecOpsPuaFastReverseProxyExecution") as alertType  
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsPuaFastReverseProxyExecution") as alertMitreTactics  
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsPuaFastReverseProxyExecution") as alertMitreTechniques  
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsPuaFastReverseProxyExecution") as alertPriority
```

## SecOpsRansomwareBehaviorMaze

**Summary:** Detects Maze ransomware activity

**MITRE:** Tactics: Impact (TA0040) | Techniques: Data Encrypted for Impact (T1486)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, mispIndicator, SecOpsLocation, SecOpsAlertDescription

```linq
from box.all.win
where event_id = 4688
group every 5m by message, source_ip, account, subject_username, subject_domain, source_hostname, process_name, device, client
every 5m
where
(weakhas(message, "WINWORD.exe") and
weakhas(message, ".tmp")
) or
(weaktoktains(message, "wmic.exe") and
weaktoktains(message, "\\Temp\\") and
weaktoktains(message, "shadowcopy delete")
) or
(weaktoktains(message, "shadowcopy delete") and
weaktoktains(message, "\\..\\..\\system32")
)
select process_name as ServiceName
select source_ip as entity_sourceIP
select account as entity_sourceAccount
select subject_username as entity_sourceName
select subject_domain as entity_sourceDomain
select source_hostname as entity_sourceHostname
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceDomain) as entity_sourceDomain_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceName) as entity_sourceName_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("mispIndicator", "category", entity_sourceIP) as indicator
select lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type
select lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsRansomwareBehaviorMaze") as alertType  
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsRansomwareBehaviorMaze") as alertMitreTactics  
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsRansomwareBehaviorMaze") as alertMitreTechniques  
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsRansomwareBehaviorMaze") as alertPriority
```

## SecOpsRansomwareBehaviorNotPetya

**Summary:** Detects NotPetya ransomware activity

**MITRE:** Tactics: Impact (TA0040) | Techniques: Data Encrypted for Impact (T1486)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, mispIndicator, SecOpsLocation, SecOpsAlertDescription

```linq
from box.all.win
where event_id = 4688
group every 5m by message, source_ip, account, subject_username, subject_domain, source_hostname, process_name, device, client
every 5m
where
weakhas(message, "rundll32.exe") and
weakhas(message, ".dat,#1") and
weakhas(message, "perfc.dat") and
(weaktoktains(message, "\\AppData\\Local\\Temp\\") or
weaktoktains(message, "\\.\\pipe\\"))
select process_name as ServiceName
select source_ip as entity_sourceIP
select account as entity_sourceAccount
select subject_username as entity_sourceName
select subject_domain as entity_sourceDomain
select source_hostname as entity_sourceHostname
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceDomain) as entity_sourceDomain_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceName) as entity_sourceName_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("mispIndicator", "category", entity_sourceIP) as indicator
select lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type
select lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsRansomwareBehaviorNotPetya") as alertType  
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsRansomwareBehaviorNotPetya") as alertMitreTactics  
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsRansomwareBehaviorNotPetya") as alertMitreTechniques  
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsRansomwareBehaviorNotPetya") as alertPriority
```

## SecOpsRansomwareBehaviorRyuk

**Summary:** Detects Ryuk ransomware activity

**MITRE:** Tactics: Impact (TA0040) | Techniques: Data Encrypted for Impact (T1486)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, mispIndicator, SecOpsLocation, SecOpsAlertDescription

```linq
from box.all.win
where event_id = 4688
group every 5m by message, source_ip, account, subject_username, subject_domain, source_hostname, process_name, device, client
every 5m
where weakhas(message, "Microsoft\\Windows\\CurrentVersion\\Run") and weakhas(message, "C:\\users\\Public\\")
select process_name as ServiceName
select source_ip as entity_sourceIP
select account as entity_sourceAccount
select subject_username as entity_sourceName
select subject_domain as entity_sourceDomain
select source_hostname as entity_sourceHostname
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceDomain) as entity_sourceDomain_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceName) as entity_sourceName_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("mispIndicator", "category", entity_sourceIP) as indicator
select lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type
select lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsRansomwareBehaviorRyuk") as alertType  
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsRansomwareBehaviorRyuk") as alertMitreTactics  
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsRansomwareBehaviorRyuk") as alertMitreTechniques  
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsRansomwareBehaviorRyuk") as alertPriority
```

## SecOpsRareServiceInstalls

**Summary:** Monitor service creation through changes in the Registry and common utilities using command-line invocation.

**MITRE:** Tactics: Persistence (TA0003) | Techniques: Create or Modify System Process (T1543)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, mispIndicator, SecOpsLocation, SecOpsAlertDescription

```linq
from box.all.win
where event_id = 7045
group every 15m by machine_ip, account, subject_username, subject_domain, source_hostname, process_name, device, client
every 3h
select count() as count
where count > 5
select process_name as ServiceName
select str(machine_ip) as entity_sourceIP
select account as entity_sourceAccount
select subject_username as entity_sourceName
select subject_domain as entity_sourceDomain
select source_hostname as entity_sourceHostname
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceDomain) as entity_sourceDomain_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceName) as entity_sourceName_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("mispIndicator", "category", entity_sourceIP) as indicator
select lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type
select lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsRareServiceInstalls") as alertType  
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsRareServiceInstalls") as alertMitreTactics  
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsRareServiceInstalls") as alertMitreTechniques  
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsRareServiceInstalls") as alertPriority
```

## SecOpsResetPasswordAttempt

**Summary:** The process of resetting a password can be related to an attack in combination with other indicators.

**MITRE:** Tactics: Credential Access (TA0006) | Techniques: Brute Force (T1110)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, mispIndicator, SecOpsLocation, SecOpsAlertDescription

```linq
from box.all.win
where event_id = 4724
where not endswith(subject_username, "$")
group every 30m by source_ip, account, subject_username, source_hostname, subject_domain, device, client
every 30m
select source_ip as entity_sourceIP
select account as entity_sourceAccount
select subject_username as entity_sourceName
select source_hostname as entity_sourceHostname
select subject_domain as entity_sourceDomain
select lu("SecOpsAssetRole", "class", entity_sourceDomain) as entity_sourceDomain_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceName) as entity_sourceName_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select asn(ip4(source_ip)) as enrichStream_entity_sourceIP_ASN
select isp(ip4(source_ip)) as enrichStream_entity_sourceIP_ISP
select ifthenelse(toktains(lu("mispIndicator", "eventtags_name_str", str(source_ip)),"TOR"), true, false) as enrichStream_entity_sourceIP_isAnonymousProxy
select lu("mispIndicator", "category", entity_sourceIP) as indicator
select lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type
select lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsResetPasswordAttempt") as alertType  
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsResetPasswordAttempt") as alertMitreTactics  
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsResetPasswordAttempt") as alertMitreTechniques  
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsResetPasswordAttempt") as alertPriority
```

## SecOpsRevilKaseyaRegistryKey

**Summary:** The REvil Ransomware has hit 40 service providers globally due to multiple Kaseya VSA Zero-days. The attack was pushed out via an infected IT Management update from Kaseya.

**MITRE:** Tactics: Privilege Escalation (TA0004) | Techniques: Event Triggered Execution (T1546)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.all.win
where eq(str(event_id), "4657") and (weakhas(object_name, "SOFTWARE\\WOW6432Node\\BlackLivesMatter") or weakhas(object_name, "SOFTWARE\\WOW6432Node\\Kaseya\\Agent"))
select source_hostname as entity_sourceHostname
select str(machine_ip) as entity_sourceIP
group every 5m by entity_sourceHostname, entity_sourceIP, event_id, object_name, device, client
every 5m
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsRevilKaseyaRegistryKey") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsRevilKaseyaRegistryKey") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsRevilKaseyaRegistryKey") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsRevilKaseyaRegistryKey") as alertPriority
```

## SecOpsSecurityEnabledLocalGroupChanged

**Summary:** All security policies must be monitored. This event generates every time a security-enabled (security) local group is changed.

**MITRE:** Tactics: Persistence (TA0003) | Techniques: Account Manipulation (T1098)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, mispIndicator, SecOpsLocation, SecOpsAlertDescription

```linq
from box.all.win
where event_id = 4735
select split(machine,".",0) as entityMachineName
where lower(target_domain) = lower(entityMachineName)
group every 5m by machine_ip, account, source_hostname, entityMachineName, subject_domain, target_domain, subject_username, device, client
every 15m
select str(machine_ip) as entity_sourceIP
select account as entity_destinationAccount
select source_hostname as entity_sourceHostname
select subject_domain as entity_sourceDomain
select target_domain as entity_destinationDomain
select subject_username as entity_sourceName
select lu("SecOpsAssetRole", "class", entity_sourceName) as entity_sourceName_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceDomain) as entity_sourceDomain_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_destinationAccount) as entity_destinationAccount_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select asn(ip4(machine_ip)) as enrichStream_entity_sourceIP_ASN
select isp(ip4(machine_ip)) as enrichStream_entity_sourceIP_ISP
select countrycode(ip4(machine_ip)) as enrichStream_entity_sourceIP_country
select ifthenelse(toktains(lu("mispIndicator", "eventtags_name_str", str(entity_sourceIP)),"TOR"), true, false) as enrichStream_entity_sourceIP_isAnonymousProxy
select lu("mispIndicator", "category", entity_sourceIP) as indicator
select lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type
select lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsSecurityEnabledLocalGroupChanged") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsSecurityEnabledLocalGroupChanged") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsSecurityEnabledLocalGroupChanged") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsSecurityEnabledLocalGroupChanged") as alertPriority
```

## SecOpsSensitiveFileAccessViaVolumeShadowCopyBackup

**Summary:** Detects attempts to access sensitive files via Volume Shadow Copy, indicating possible credential or AD database extraction.

**MITRE:** Tactics: Discovery (TA0007) | Techniques: Query Registry (T1012)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, mispIndicator, SecOpsAlertDescription

```linq
from box.all.win
where event_id = 1 or event_id = 4688
where weakhas(rawMessage,"HarddiskVolumeShadowCopy1")
where (weakhas(parent_command_line,"powershell")
        or weakhas(process_command_line,"HarddiskVolumeShadowCopy1"))
    or (weakhas(parent_process_name,"powershell")
        or weakhas(new_process_name,"HarddiskVolumeShadowCopy1"))
where (weakhas(process_command_line,"NTDS.dit")
        or weakhas(process_command_line,"SYSTEM")
        or weakhas(process_command_line,"SECURITY"))
    or (weakhas(new_process_name,"NTDS.dit")
        or weakhas(new_process_name,"SYSTEM")
        or weakhas(new_process_name,"SECURITY"))
group every 5m by source_ip, account, subject_username, subject_domain, source_hostname, process_name, device, client
every 5m
select process_name as ServiceName
select source_ip as entity_sourceIP
select account as entity_sourceAccount
select subject_username as entity_sourceName
select subject_domain as entity_sourceDomain
select source_hostname as entity_sourceHostname
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceDomain) as entity_sourceDomain_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceName) as entity_sourceName_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("mispIndicator", "category", entity_sourceIP) as indicator
select lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type
select lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
select lu("SecOpsAlertDescription", "alertType", "SecOpsSensitiveFileAccessViaVolumeShadowCopyBackup") as alertType  
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsSensitiveFileAccessViaVolumeShadowCopyBackup") as alertMitreTactics  
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsSensitiveFileAccessViaVolumeShadowCopyBackup") as alertMitreTechniques  
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsSensitiveFileAccessViaVolumeShadowCopyBackup") as alertPriority
```

## SecOpsSeveralPasswordChanges

**Summary:** Several password changes from an users could be a suspicious behavior. For example could be part of an strategy to bypass password changes policies.

**MITRE:** Tactics: Persistence (TA0003) | Techniques: Account Manipulation (T1098)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, SecOpsLocation, SecOpsAlertDescription

```linq
from box.all.win
where event_id = 4723
where event_type = "Success Audit" or event_type = "AUDIT_SUCCESS"
group every 5m by source_ip, account, subject_username, source_hostname, subject_domain, device, client
every 30m
select account as user
select count() as count
where count > 3
select subject_username as entity_sourceName
select account as entity_destinationAccount
select source_hostname as entity_sourceHostname
select subject_domain as entity_sourceDomain
select source_ip as entity_sourceIP
select lu("SecOpsAssetRole", "class", entity_sourceIP) as AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsSeveralPasswordChanges") as alertType  
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsSeveralPasswordChanges") as alertMitreTactics  
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsSeveralPasswordChanges") as alertMitreTechniques  
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsSeveralPasswordChanges") as alertPriority
```

## SecOpsShadowCopiesDeletion

**Summary:** Shadow Copies Deletion Using Operating Systems Utilities

**MITRE:** Tactics: Credential Access (TA0006) | Techniques: OS Credential Dumping (T1003)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, mispIndicator, SecOpsLocation, SecOpsAlertDescription

```linq
from box.all.win
where event_id = 4688
 where
( weakhas(message, "powershell.exe") or
weakhas(message, "wmic.exe") or
weakhas(message, "vssadmin.exe")) and
(weakhas(message, "shadow") or
weakhas(message, "delete"))
group every 5m by source_ip, account, subject_username, subject_domain, source_hostname, process_name, device, client
every 30m
select process_name as ServiceName
select source_ip as entity_sourceIP
select account as entity_sourceAccount
select subject_username as entity_sourceName
select subject_domain as entity_sourceDomain
select source_hostname as entity_sourceHostname
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceDomain) as entity_sourceDomain_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceName) as entity_sourceName_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("mispIndicator", "category", entity_sourceIP) as indicator
select lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type
select lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsShadowCopiesDeletion") as alertType  
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsShadowCopiesDeletion") as alertMitreTactics  
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsShadowCopiesDeletion") as alertMitreTechniques  
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsShadowCopiesDeletion") as alertPriority
```

## SecOpsSIGRedExploitMicrosoftWindowsDNS

**Summary:** SIGRed, CVE-2020-1350, is a vulnerability in the Microsoft Windows DNS service with CVSS score of 10.0, the highest level of severity. SIGRed vulnerability consists in an integer overflow vulnerability that leads to a heap-based buffer overflow when processing malformed DNS SIG resource records.

**MITRE:** Tactics: Persistence (TA0003) | Techniques: Create or Modify System Process (T1543)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, mispIndicator, SecOpsLocation, SecOpsAlertDescription

```linq
from box.all.win
where event_id = 4688
group every 5m by parent_process_name, process_name, machine_ip, source_hostname, device, client
every 5m
where toktains(parent_process_name, "dns.exe")
where toktains(process_name, "cmd.exe") or
toktains(process_name, "cmd.exe") or
toktains(process_name, "mshta.exe") or
toktains(process_name, "rundll32.exe") or
toktains(process_name, "conhost.exe") or
toktains(process_name, "dnscmd.exe") or
toktains(process_name, "werfault.exe")
select process_name as ProcessName
select str(machine_ip) as entity_sourceIP
select source_hostname as entity_sourceHostname
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("mispIndicator", "category", entity_sourceIP) as indicator
select lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type
select lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsSIGRedExploitMicrosoftWindowsDNS") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsSIGRedExploitMicrosoftWindowsDNS") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsSIGRedExploitMicrosoftWindowsDNS") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsSIGRedExploitMicrosoftWindowsDNS") as alertPriority
```

## SecOpsStoneDrillServiceInstall

**Summary:** Monitor service creation through changes in the Registry and common utilities using command-line invocation.

**MITRE:** Tactics: Persistence (TA0003) | Techniques: Create or Modify System Process (T1543)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, mispIndicator, SecOpsLocation, SecOpsAlertDescription

```linq
from box.all.win
where event_id = 7045
where toktains(source_name, "Service Control Manager")
where service = "NtsSrv"
where toktains(service_file_name, "LocalService") or toktains(image, "LocalService")
group every 5m by source_ip, account, subject_username, subject_domain, source_hostname, process_name, device, client
every 15m
select process_name as ServiceName
select source_ip as entity_sourceIP
select account as entity_sourceAccount
select subject_username as entity_sourceName
select subject_domain as entity_sourceDomain
select source_hostname as entity_sourceHostname
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceDomain) as entity_sourceDomain_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceName) as entity_sourceName_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("mispIndicator", "category", entity_sourceIP) as indicator
select lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type
select lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsStoneDrillServiceInstall") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsStoneDrillServiceInstall") as alertMitreTactics  
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsStoneDrillServiceInstall") as alertMitreTechniques  
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsStoneDrillServiceInstall") as alertPriority
```

## SecOpsStopSqlServicesRunning

**Summary:** Detects suspicious activity on that could be related with Black Kingdom Ransomware

**MITRE:** Tactics: Impact (TA0040) | Techniques: Service Stop (T1489)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, mispIndicator, SecOpsLocation, SecOpsAlertDescription

```linq
from box.all.win
where event_id = 4688
where toktains(process_name, "powershell")
where weaktoktains(message, "Get-Service")
where weaktoktains(message, "sql")
where weaktoktains(message, "Stop-Service")
where weaktoktains(message, "Force")
group every 5m by source_ip, machine, account, subject_username, subject_domain, source_hostname, process_name, device, client
every 15m
select process_name as ServiceName
select source_ip as entity_sourceIP
select account as entity_sourceAccount
select subject_username as entity_sourceName
select subject_domain as entity_sourceDomain
select source_hostname as entity_sourceHostname
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceDomain) as entity_sourceDomain_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceName) as entity_sourceName_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("mispIndicator", "category", entity_sourceIP) as indicator
select lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type
select lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsStopSqlServicesRunning") as alertType  
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsStopSqlServicesRunning") as alertMitreTactics  
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsStopSqlServicesRunning") as alertMitreTechniques  
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsStopSqlServicesRunning") as alertPriority
```

## SecOpsSuspiciousBehaviorAppInitDLL

**Summary:** Malware can insert the location of their malicious library under the Appinit_Dlls registry key to have another process load their library.

**MITRE:** Tactics: Persistence (TA0003) | Techniques: Event Triggered Execution (T1546)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.all.win
where eq(str(event_id), "4657") and (weakhas(object_name, "Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\Appinit_Dlls") or weakhas(object_name, "Software\\Wow6432Node\\Microsoft\\WindowsNT\\CurrentVersion\\Windows\\Appinit_Dlls") or weakhas(object_name, "System\\CurrentControlSet\\Control\\Session Manager\\AppCertDlls"))
select source_hostname as entity_sourceHostname
select str(machine_ip) as entity_sourceIP
group every 5m by entity_sourceHostname, entity_sourceIP, event_id, object_name, device, client
every 5m
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsSuspiciousBehaviorAppInitDLL") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsSuspiciousBehaviorAppInitDLL") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsSuspiciousBehaviorAppInitDLL") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsSuspiciousBehaviorAppInitDLL") as alertPriority
```

## SecOpsSuspiciousEventlogClearingOrConfigurationChangeActivity

**Summary:** Detects the use of utilities such as wevtutil, powershell, and wmic to clear or modify Windows Event Logs, which may indicate attempts to evade detection.

**MITRE:** Tactics: Defense Evasion (TA0005) | Techniques: Indicator Removal (T1070), Disable or Modify Tools (T1562)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, mispIndicator, SecOpsAlertDescription

```linq
from box.all.win
where event_id = 4688
select ifthenelse(process_command_line = null, new_process_name, process_command_line) as selected_command_line
where not (weakhas(parent_process_name, "msiexec")
            and (weakhas(process_command_line," sl ")
                or weakhas(selected_command_line," sl ")))
where (((weakhas(selected_command_line, "wevtutil")) and
        ((weakhas(selected_command_line,"clear-log ")
            or weakhas(selected_command_line," cl ")
            or weakhas(selected_command_line,"set-log ")
            or weakhas(selected_command_line," sl ")
            or weakhas(selected_command_line,"lfn:")))))
    or (((weakhas(selected_command_line, "powershell") or weakhas(selected_command_line, "pwsh")) and
        ((weakhas(selected_command_line,"Clear-EventLog ")
            or weakhas(selected_command_line,"Remove-EventLog ")
            or weakhas(selected_command_line,"Limit-EventLog ")
            or weakhas(selected_command_line,"Clear-WinEvent ")))))
group every 5m by source_ip, account, subject_username, subject_domain, source_hostname, process_name, device, client
every 5m
select process_name as ServiceName
select source_ip as entity_sourceIP
select account as entity_sourceAccount
select subject_username as entity_sourceName
select subject_domain as entity_sourceDomain
select source_hostname as entity_sourceHostname
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceDomain) as entity_sourceDomain_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceName) as entity_sourceName_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("mispIndicator", "category", entity_sourceIP) as indicator
select lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type
select lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
select lu("SecOpsAlertDescription", "alertType", "SecOpsSuspiciousEventlogClearingOrConfigurationChangeActivity") as alertType  
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsSuspiciousEventlogClearingOrConfigurationChangeActivity") as alertMitreTactics  
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsSuspiciousEventlogClearingOrConfigurationChangeActivity") as alertMitreTechniques  
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsSuspiciousEventlogClearingOrConfigurationChangeActivity") as alertPriority
```

## SecOpsSuspiciousEventlogClearUsingWevtutil

**Summary:** Suspicious Eventlog Clear or Configuration Using Wevtutil

**MITRE:** Tactics: Defense Evasion (TA0005) | Techniques: Indicator Removal (T1070)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, mispIndicator, SecOpsLocation, SecOpsAlertDescription

```linq
from box.all.win
where event_id = 1102
group every 5m by message, source_ip, account, subject_username, subject_domain, source_hostname, service, device, client
every 15m
where
((weakhas(message, "wmic.exe") or
weakhas(message, "powershell.exe"))
and
weakhas(message, "Clear-EventLog") or
weakhas(message, "Limit-EventLog") or
weakhas(message, "Remove-EventLog"))
or
((weakhas(message, "wevtutil.exe")
and
(weakhas(message, "clear-log") or
weakhas(message, " cl ") or
weakhas(message, "set-log") or
weakhas(message, " sl "))))
select source_ip as entity_sourceIP
select account as entity_sourceAccount
select subject_username as entity_sourceName
select subject_domain as entity_sourceDomain
select source_hostname as entity_sourceHostname
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceDomain) as entity_sourceDomain_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceName) as entity_sourceName_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("mispIndicator", "category", entity_sourceIP) as indicator
select lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type
select lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsSuspiciousEventlogClearUsingWevtutil") as alertType  
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsSuspiciousEventlogClearUsingWevtutil") as alertMitreTactics  
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsSuspiciousEventlogClearUsingWevtutil") as alertMitreTechniques  
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsSuspiciousEventlogClearUsingWevtutil") as alertPriority
```

## SecOpsSuspiciousPowerShellInvocation

**Summary:** This alert detects the use of suspicious parameters in PowerShell command invocations that may indicate malicious activity.

**MITRE:** Tactics: Execution (TA0002) | Techniques: Command and Scripting Interpreter (T1059)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, mispIndicator, SecOpsAlertDescription

```linq
from box.all.win
where event_id = 4688
select ifthenelse(process_command_line = null, new_process_name, process_command_line) as selected_command_line
where ((weakhas(selected_command_line, "-windowstyle hidden"))
or (weakhas(selected_command_line, "-windowstyle hidden")
and weakhas(selected_command_line, "-enc")))
group every 5m by source_ip, account, subject_username, subject_domain, source_hostname, process_name, device, client
every 5m
select process_name as ServiceName
select source_ip as entity_sourceIP
select account as entity_sourceAccount
select subject_username as entity_sourceName
select subject_domain as entity_sourceDomain
select source_hostname as entity_sourceHostname
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceDomain) as entity_sourceDomain_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceName) as entity_sourceName_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("mispIndicator", "category", entity_sourceIP) as indicator
select lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type
select lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
select lu("SecOpsAlertDescription", "alertType", "SecOpsSuspiciousPowerShellInvocation") as alertType  
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsSuspiciousPowerShellInvocation") as alertMitreTactics  
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsSuspiciousPowerShellInvocation") as alertMitreTechniques  
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsSuspiciousPowerShellInvocation") as alertPriority
```

## SecOpsSuspiciousWMIExecution

**Summary:** Detects WMI executing suspicious commands.

**MITRE:** Tactics: Persistence (TA0003) | Techniques: Event Triggered Execution (T1546)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, mispIndicator, SecOpsLocation, SecOpsAlertDescription

```linq
from box.all.win
where event_id = 4688,
weakhas(message, "path AntiVirusProduct get") or
weakhas(message, "path FirewallProduct get") or
weakhas(message, "shadowcopy delete") or
(weakhas(message, "/NODE:") and weakhas(message, "process call create"))
group every 5m by machine_ip, account, subject_username, subject_domain, source_hostname, process_name, device, client
every 30m
select process_name as ServiceName
select str(machine_ip) as entity_sourceIP
select account as entity_sourceAccount
select subject_username as entity_sourceName
select subject_domain as entity_sourceDomain
select source_hostname as entity_sourceHostname
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceDomain) as entity_sourceDomain_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceName) as entity_sourceName_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("mispIndicator", "category", entity_sourceIP) as indicator
select lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type
select lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsSuspiciousWMIExecution") as alertType  
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsSuspiciousWMIExecution") as alertMitreTactics  
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsSuspiciousWMIExecution") as alertMitreTechniques  
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsSuspiciousWMIExecution") as alertPriority
```

## SecOpsTurlaPNGDropperService

**Summary:** Monitor service creation through changes in the Registry and common utilities using command-line invocation.

**MITRE:** Tactics: Persistence (TA0003) | Techniques: Create or Modify System Process (T1543)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, mispIndicator, SecOpsLocation, SecOpsAlertDescription

```linq
from box.all.win
where event_id = 7045,
toktains(message, "WerFaultSvc")
group every 5m by source_ip, process_name, account, subject_username, subject_domain, source_hostname, device, client
every 15m
select process_name as ServiceName
select account as entity_sourceAccount
select subject_username as entity_sourceName
select subject_domain as entity_sourceDomain
select source_hostname as entity_sourceHostname
select source_ip as entity_sourceIP
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceDomain) as entity_sourceDomain_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceName) as entity_sourceName_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("mispIndicator", "category", entity_sourceIP) as indicator
select lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type
select lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsTurlaPNGDropperService") as alertType  
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsTurlaPNGDropperService") as alertMitreTactics  
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsTurlaPNGDropperService") as alertMitreTechniques  
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsTurlaPNGDropperService") as alertPriority
```

## SecOpsTurlaServiceInstall

**Summary:** Monitor service creation through changes in the Registry and common utilities using command-line invocation.

**MITRE:** Tactics: Persistence (TA0003) | Techniques: Create or Modify System Process (T1543)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, mispIndicator, SecOpsLocation, SecOpsAlertDescription

```linq
from box.all.win
where toktains(object_name, "CurrentVersion\\App Paths\\control.exe") or
toktains(object_name, "Classes\\exefile\\shell\\runas\\command\\isolatedCommand") or
toktains(object_name, "Software\\Classes\\mscfile\\shell\\open\\command")
where event_id = 7045,
eqic(object_name, "srservice") or
eqic(object_name, "ipvpn") or
eqic(object_name, "hkmsvc")
group every 5m by source_ip, object_name, process_name,account, subject_username, subject_domain, source_hostname, device, client
every 15m
select source_ip as entity_sourceIP
select object_name as DLL
select process_name as ProcessName
select account as entity_sourceAccount
select subject_username as entity_sourceName
select subject_domain as entity_sourceDomain
select source_hostname as entity_sourceHostname
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceDomain) as entity_sourceDomain_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceName) as entity_sourceName_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("mispIndicator", "category", entity_sourceIP) as indicator
select lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type
select lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsTurlaServiceInstall") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsTurlaServiceInstall") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsTurlaServiceInstall") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsTurlaServiceInstall") as alertPriority
```

## SecOpsUserAccountChanged

**Summary:** Changes to user accounts should be monitored for suspicious changes by an analyst.

**MITRE:** Tactics: Persistence (TA0003) | Techniques: Account Manipulation (T1098)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, mispIndicator, SecOpsLocation, SecOpsAlertDescription

```linq
from box.all.win
where event_id = 4738
group every 5m by source_ip, subject_username, account, source_hostname, subject_domain, domain, device, client
every 10m
select source_ip as entity_sourceIP
select subject_username as entity_sourceAccount
select account as entity_destionationAccount
select source_hostname as entity_sourceHostname
select subject_domain as entity_sourceDomain
select domain as entity_destionationDomain
select lu("SecOpsAssetRole", "class", str(entity_sourceIP)) as AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select asn(ip4(source_ip)) as enrichStream_entity_sourceIP_ASN
select isp(ip4(source_ip)) as enrichStream_entity_sourceIP_ISP
select countrycode(ip4(source_ip)) as enrichStream_entity_sourceIP_country
select lu("mispIndicator", "category", str(entity_sourceIP)) as indicator
select lu("mispIndicator", "type", str(entity_sourceIP)) as miss_indicator_type
select lu("mispIndicator", "event_id", str(entity_sourceIP)) as misp_indicator_event_id
select lu("SecOpsLocation", "country", str(entity_sourceIP)) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", str(entity_sourceIP)) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", str(entity_sourceIP)) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", str(entity_sourceIP)) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", str(entity_sourceIP)) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsUserAccountChanged") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsUserAccountChanged") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsUserAccountChanged") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsUserAccountChanged") as alertPriority
```

## SecOpsVolumeShadowCopyDeletion

**Summary:** This alert detects the deletion of Volume Shadow Copy storage in Windows logs. Attackers, especially during ransomware operations, frequently delete shadow copies to prevent recovery and ensure that encrypted files cannot be restored.

**Description:** Detects the deletion of Volume Shadow Copy storage in Windows logs. Attackers frequently delete shadow copies to prevent recovery and ensure that encrypted files cannot be restored.

**MITRE:** Tactics: Impact (TA0040) | Techniques: Inhibit System Recovery (T1490)

**Tables:** box.all.win

**Lookups:** none

```linq
from box.all.win
where ((endswith(image,"\\powershell.exe")
or endswith(image, "\\wmic.exe")
or endswith(image, "\\vssadmin.exe")
or endswith(image, "\\diskshadow.exe"))
and (toktains(process_command_line, "shadow", true, true)
and toktains(process_command_line, "delete", true, true)))
or (endswith(image, "\\wbadmin.exe")
and (toktains(process_command_line, "delete", true, true)
and toktains(process_command_line, "catalog", true, true)
and toktains(process_command_line, "quiet", true, true)))
or (endswith(image, "\\vssadmin.exe")
and (toktains(process_command_line, "resize", true, true)
and toktains(process_command_line, "shadowstorage", true, true)
and toktains(process_command_line, "unbounded", true, true)))
group every 5m by username,account,source_ip,destination_ip,source_hostname,destination_hostname,process_name,source, device, client
select collectdistinct(process_command_line) as commands
where round(hllppcount(process_command_line)) > 1
select source_ip as entity_sourceIP
select destination_ip as entity_destionationIP
select source_hostname as entity_sourceHostname
select destination_hostname as entity_destinationHostname
select account as entity_sourceAccount
//<filtering_section>
select "Detection" as alertType
select "Defense Evasion" as alertMitreTactics
select "Subvert Trust Controls" as alertMitreTechniques
select 4 as alertPriority
```

## SecOpsWannaCryBehavior

**Summary:** Detects WannaCry ransomware activity

**MITRE:** Tactics: Impact (TA0040) | Techniques: Data Encrypted for Impact (T1486)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, mispIndicator, SecOpsLocation, SecOpsAlertDescription

```linq
from box.all.win
where event_id = 4688
group every 5m by message, source_ip, account, subject_username, subject_domain, source_hostname, process_name, device, client
every 5m
where
(weakhas(message, "tasksche.exe") or
weakhas(message, "mssecsvc.exe") or
weakhas(message, "taskdl.exe") or
weakhas(message, "@WanaDecryptor@") or
weakhas(message, "WanaDecryptor") or
weakhas(message, "taskhsvc.exe") or
weakhas(message, "taskse.exe") or
weakhas(message, "111.exe") or
weakhas(message, "lhdfrgui.exe") or
weakhas(message, "diskpart.exe") or
weakhas(message, "linuxnew.exe") or
weakhas(message, "wannacry.exe")
)
and
((weakhas(message, "icacls") and
weakhas(message, "/grant Everyone:F /T /C /Q")
)
or
weakhas(message, "bcdedit /set {default} recoveryenabled no") or
weakhas(message, "wbadmin delete catalog -quiet") or
weakhas(message, "@Please_Read_Me@.txt")
)
select process_name as ServiceName
select source_ip as entity_sourceIP
select account as entity_sourceAccount
select subject_username as entity_sourceName
select subject_domain as entity_sourceDomain
select source_hostname as entity_sourceHostname
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceDomain) as entity_sourceDomain_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceName) as entity_sourceName_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("mispIndicator", "category", entity_sourceIP) as indicator
select lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type
select lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
select lu("SecOpsAlertDescription", "alertType", "SecOpsWannaCryBehavior") as alertType  
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsWannaCryBehavior") as alertMitreTactics  
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsWannaCryBehavior") as alertMitreTechniques  
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsWannaCryBehavior") as alertPriority
```

## SecOpsWermgrConnectingToIPCheckWebServices

**Summary:** Adversaries may gather information about the victim's networks that can be used during targeting. This information may include a variety of details, including administrative data as well as specifics regarding its topology and operations.

**MITRE:** Tactics: Reconnaissance (TA0043) | Techniques: Gather Victim Network Information (T1590)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.all.win
where eq(channel, "Microsoft-Windows-Sysmon/Operational") and eq(event_id, 22) and weakhas(image, "\\wermgr.exe")
select source_hostname as entity_sourceHostname
select str(machine_ip) as entity_sourceIP
select str(jqeval(jqcompile(".columns.data.EventData.QueryName"), jsonparse(rawMessage))) as current_queryName
where (weakhas(current_queryName, "wtfismyip.com") or weakhas(current_queryName, "checkip.amazonaws.com") or weakhas(current_queryName, "ipecho.net") or weakhas(current_queryName, "ipinfo.io") or weakhas(current_queryName, "api.ipify.org") or weakhas(current_queryName, "icanhazip.com") or weakhas(current_queryName, "ip.anysrc.com") or weakhas(current_queryName, "api.ip.sb") or weakhas(current_queryName, "ident.me") or weakhas(current_queryName, "www.myexternalip.com") or weakhas(current_queryName, "zen.spamhaus.org") or weakhas(current_queryName, "cbl.abuseat.org") or weakhas(current_queryName, "b.barracudacentral.org") or weakhas(current_queryName, "dnsbl-1.uceprotect.net") or weakhas(current_queryName, "spam.dnsbl.sorbs.net"))
group every 5m by event_id, entity_sourceHostname, entity_sourceIP, image, current_queryName, device, client
every 5m
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsWermgrConnectingToIPCheckWebServices") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsWermgrConnectingToIPCheckWebServices") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsWermgrConnectingToIPCheckWebServices") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsWermgrConnectingToIPCheckWebServices") as alertPriority
```

## SecOpsWinActivateNoCloseGroupPolicyFeature

**Summary:** Adversaries may interact with the Windows Registry to hide configuration information within Registry keys, remove information as part of cleaning up, or as part of other techniques to aid in persistence and execution.

**MITRE:** Tactics: Defense Evasion (TA0005) | Techniques: Modify Registry (T1112)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.all.win
where ((event_id = 1 and channel ="Microsoft-Windows-Sysmon/Operational") or event_id = 4688) and ((weakhas(process_command_line, "reg") and weakhas(process_command_line, "add")) or weakhas(process_command_line, "New-ItemProperty")) and (weakhas(process_command_line,  "NoClose"))
select source_hostname as entity_sourceHostname
select str(machine_ip) as entity_sourceIP
group every 5m by source_name, entity_sourceIP, entity_sourceHostname, process_command_line, device, client
every 5m
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsWinActivateNoCloseGroupPolicyFeature") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsWinActivateNoCloseGroupPolicyFeature") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsWinActivateNoCloseGroupPolicyFeature") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsWinActivateNoCloseGroupPolicyFeature") as alertPriority
```

## SecOpsWinActivateNoControlPanelGroupPolicyFeature

**Summary:** Adversaries may interact with the Windows Registry to hide configuration information within Registry keys, remove information as part of cleaning up, or as part of other techniques to aid in persistence and execution.

**MITRE:** Tactics: Defense Evasion (TA0005) | Techniques: Modify Registry (T1112)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.all.win
where ((event_id = 1 and channel ="Microsoft-Windows-Sysmon/Operational") or event_id = 4688) and ((weakhas(process_command_line, "reg") and weakhas(process_command_line, "add")) or weakhas(process_command_line, "New-ItemProperty")) and (weakhas(process_command_line,  "NoControlPanel"))
select source_hostname as entity_sourceHostname
select str(machine_ip) as entity_sourceIP
group every 5m by source_name, entity_sourceIP, entity_sourceHostname, process_command_line, device, client
every 5m
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsWinActivateNoControlPanelGroupPolicyFeature") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsWinActivateNoControlPanelGroupPolicyFeature") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsWinActivateNoControlPanelGroupPolicyFeature") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsWinActivateNoControlPanelGroupPolicyFeature") as alertPriority
```

## SecOpsWinActivateNoFileMenuGroupPolicyFeature

**Summary:** Adversaries may interact with the Windows Registry to hide configuration information within Registry keys, remove information as part of cleaning up, or as part of other techniques to aid in persistence and execution.

**MITRE:** Tactics: Defense Evasion (TA0005) | Techniques: Modify Registry (T1112)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.all.win
where ((event_id = 1 and channel ="Microsoft-Windows-Sysmon/Operational") or event_id = 4688) and ((weakhas(process_command_line, "reg") and weakhas(process_command_line, "add")) or weakhas(process_command_line, "New-ItemProperty")) and (weakhas(process_command_line,  "NoFileMenu"))
select source_hostname as entity_sourceHostname
select str(machine_ip) as entity_sourceIP
group every 5m by source_name, entity_sourceIP, entity_sourceHostname, process_command_line, device, client
every 5m
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsWinActivateNoFileMenuGroupPolicyFeature") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsWinActivateNoFileMenuGroupPolicyFeature") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsWinActivateNoFileMenuGroupPolicyFeature") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsWinActivateNoFileMenuGroupPolicyFeature") as alertPriority
```

## SecOpsWinActivateNoPropertiesMyDocumentsGroupPolicyFeature

**Summary:** Adversaries may interact with the Windows Registry to hide configuration information within Registry keys, remove information as part of cleaning up, or as part of other techniques to aid in persistence and execution.

**MITRE:** Tactics: Defense Evasion (TA0005) | Techniques: Modify Registry (T1112)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.all.win
where ((event_id = 1 and channel ="Microsoft-Windows-Sysmon/Operational") or event_id = 4688) and ((weakhas(process_command_line, "reg") and weakhas(process_command_line, "add")) or weakhas(process_command_line, "New-ItemProperty")) and (weakhas(process_command_line,  "NoPropertiesMyDocuments"))
select source_hostname as entity_sourceHostname
select str(machine_ip) as entity_sourceIP
group every 5m by source_name, entity_sourceIP, entity_sourceHostname, process_command_line, device, client
every 5m
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsWinActivateNoPropertiesMyDocumentsGroupPolicyFeature") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsWinActivateNoPropertiesMyDocumentsGroupPolicyFeature") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsWinActivateNoPropertiesMyDocumentsGroupPolicyFeature") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsWinActivateNoPropertiesMyDocumentsGroupPolicyFeature") as alertPriority
```

## SecOpsWinActivateNoSetTaskbarGroupPolicyFeature

**Summary:** Adversaries may interact with the Windows Registry to hide configuration information within Registry keys, remove information as part of cleaning up, or as part of other techniques to aid in persistence and execution.

**MITRE:** Tactics: Defense Evasion (TA0005) | Techniques: Modify Registry (T1112)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.all.win
where ((event_id = 1 and channel ="Microsoft-Windows-Sysmon/Operational") or event_id = 4688) and ((weakhas(process_command_line, "reg") and weakhas(process_command_line, "add")) or weakhas(process_command_line, "New-ItemProperty")) and (weakhas(process_command_line,  "NoSetTaskbar"))
select source_hostname as entity_sourceHostname
select str(machine_ip) as entity_sourceIP
group every 5m by source_name, entity_sourceIP, entity_sourceHostname, process_command_line, device, client
every 5m
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsWinActivateNoSetTaskbarGroupPolicyFeature") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsWinActivateNoSetTaskbarGroupPolicyFeature") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsWinActivateNoSetTaskbarGroupPolicyFeature") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsWinActivateNoSetTaskbarGroupPolicyFeature") as alertPriority
```

## SecOpsWinActivateNoTrayContextMenuGroupPolicyFeature

**Summary:** Adversaries may interact with the Windows Registry to hide configuration information within Registry keys, remove information as part of cleaning up, or as part of other techniques to aid in persistence and execution.

**MITRE:** Tactics: Defense Evasion (TA0005) | Techniques: Modify Registry (T1112)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.all.win
where ((event_id = 1 and channel ="Microsoft-Windows-Sysmon/Operational") or event_id = 4688) and ((weakhas(process_command_line, "reg") and weakhas(process_command_line, "add")) or weakhas(process_command_line, "New-ItemProperty")) and (weakhas(process_command_line,  "NoTrayContextMenu"))
select source_hostname as entity_sourceHostname
select str(machine_ip) as entity_sourceIP
group every 5m by source_name, entity_sourceIP, entity_sourceHostname, process_command_line, device, client
every 5m
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsWinActivateNoTrayContextMenuGroupPolicyFeature") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsWinActivateNoTrayContextMenuGroupPolicyFeature") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsWinActivateNoTrayContextMenuGroupPolicyFeature") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsWinActivateNoTrayContextMenuGroupPolicyFeature") as alertPriority
```

## SecOpsWinADDomainEnumeration

**Summary:** Detects potential attempts to enumerate active users on the network.

**MITRE:** Tactics: Credential Access (TA0006) | Techniques: Steal or Forge Kerberos Tickets (T1558)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.all.win
where event_id = 4798 or event_id = 4799
select nvl(caller_pid, peek(message, re("(?<=Process ID:)\\s+(\\S.*?)(?=\\s\\s)"), 1)) as callerProcessId
, nvl(caller_process_name, peek(message, re("(?<=Process Name:)\\s+(\\S.*?)(?=(:?\\s\\s|$))"), 1)) as callerProcessName
group every 5m by subject_security_id, subject_username, subject_domain, subject_logon_id, callerProcessId, callerProcessName, device, client
, target_security_id, target_username, target_domain
, machine
//Entity Mapping Section
select machine as entity_sourceHostname
select subject_username as entity_sourceAccount
select subject_domain as entity_sourceDomain
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceDomain) as entity_sourceDomain_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole
//<filtering_section>
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsWinADDomainEnumeration") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsWinADDomainEnumeration") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsWinADDomainEnumeration") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsWinADDomainEnumeration") as alertPriority
```

## SecOpsWinAddRegistryValueToLoadSrvcInSafeModeWithNetwork

**Summary:** Adversaries may interact with the Windows Registry to hide configuration information within Registry keys, remove information as part of cleaning up, or as part of other techniques to aid in persistence and execution.

**MITRE:** Tactics: Defense Evasion (TA0005) | Techniques: Modify Registry (T1112)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.all.win
where ((event_id = 1 and channel ="Microsoft-Windows-Sysmon/Operational") or event_id = 4688) and ((weakhas(process_command_line, "reg") and weakhas(process_command_line, "add")) or weakhas(process_command_line, "New-ItemProperty")) and (weakhas(process_command_line,  "SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Network"))
select source_hostname as entity_sourceHostname
select str(machine_ip) as entity_sourceIP
group every 5m by source_name, entity_sourceIP, entity_sourceHostname, process_command_line, device, client
every 5m
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsWinAddRegistryValueToLoadSrvcInSafeModeWithNetwork") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsWinAddRegistryValueToLoadSrvcInSafeModeWithNetwork") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsWinAddRegistryValueToLoadSrvcInSafeModeWithNetwork") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsWinAddRegistryValueToLoadSrvcInSafeModeWithNetwork") as alertPriority
```

## SecOpsWinAddRegistryValueToLoadSrvcInSafeModeWONetwork

**Summary:** Adversaries may interact with the Windows Registry to hide configuration information within Registry keys, remove information as part of cleaning up, or as part of other techniques to aid in persistence and execution.

**MITRE:** Tactics: Defense Evasion (TA0005) | Techniques: Modify Registry (T1112)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.all.win
where ((event_id = 1 and channel ="Microsoft-Windows-Sysmon/Operational") or event_id = 4688) and ((weakhas(process_command_line, "reg") and weakhas(process_command_line, "add")) or weakhas(process_command_line, "New-ItemProperty")) and (weakhas(process_command_line,  "SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Minimal"))
select source_hostname as entity_sourceHostname
select str(machine_ip) as entity_sourceIP
group every 5m by source_name, entity_sourceIP, entity_sourceHostname, process_command_line, device, client
every 5m
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsWinAddRegistryValueToLoadSrvcInSafeModeWONetwork") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsWinAddRegistryValueToLoadSrvcInSafeModeWONetwork") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsWinAddRegistryValueToLoadSrvcInSafeModeWONetwork") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsWinAddRegistryValueToLoadSrvcInSafeModeWONetwork") as alertPriority
```

## SecOpsWinAdminRemoteLogon

**Summary:** Detects remote logins by an administrative user account. Administrative account names are tailored to the organization's specific naming conventions.

**MITRE:** Tactics: Initial Access (TA0001) | Techniques: Valid Accounts (T1078)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.all.win
where event_id=4624
where `or`(LogonType="10", LogonType="12") // RemoteInteractive, CachedRemoteInteractive
where weakhas(target_username, "admin")
group every 5m by destination_ip, destination_hostname, subject_security_id, subject_username, subject_domain, subject_logon_id, target_security_id, target_username, target_domain, target_logon_id, workstation, pid, process_name, source_port, token_elevation_type, device, client
//Entity Mapping Section
select destination_hostname as entity_destinationHostname
select str(destination_ip) as entity_destinationIP
select subject_username as entity_sourceAccount
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_destinationIP) as entity_destinationIP_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole
select lu("SecOpsAssetRole", "class", entity_destinationHostname) as entity_destinationHostname_AssetRole
//<filtering_section>
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsWinAdminRemoteLogon") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsWinAdminRemoteLogon") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsWinAdminRemoteLogon") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsWinAdminRemoteLogon") as alertPriority
```

## SecOpsWinAdminShareSuspiciousUse

**Summary:** Detects when a user pivots to an internal host from another internal host via Windows Admin shares.

**MITRE:** Tactics: Lateral Movement (TA0008) | Techniques: Remote Services (T1021)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, mispIndicator, SecOpsLocation, SecOpsAlertDescription

```linq
from box.all.win
where event_id=5140
where weaktoktains(share_name, "admin$")
select peek(message,re("Share Path:\\t\\t(.*)"),1) as sharePath
group every 5m by subject_username, machine_ip, security_id, share_name, sharePath, event_id ,subject_domain, target_domain, target_username, member_security_id, process_name, machine, source_ip, destination_ipv4, source_hostname, device, client
//Entity Mapping Section
select machine as entity_sourceHostname
select subject_username as entity_sourceAccount
select str(machine_ip) as entity_sourceIP
select subject_domain as entity_sourceDomain
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceDomain) as entity_sourceDomain_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole
//<filtering_section>
//Enrichment Mapping
select asn(ip4(entity_sourceIP)) as enrichStream_entity_sourceIP_ASN
select isp(ip4(entity_sourceIP)) as enrichStream_entity_sourceIP_ISP
select countrycode(ip4(entity_sourceIP)) as enrichStream_entity_sourceIP_country
select ifthenelse(toktains(lu("mispIndicator", "eventtags_name_str", str(entity_sourceIP)),"TOR"), true, false) as enrichStream_entity_sourceIP_isAnonymousProxy
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
//Get Enrichment from SecOps
select lu("mispIndicator", "category", entity_sourceIP) as indicator
select lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type
select lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsWinAdminShareSuspiciousUse") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsWinAdminShareSuspiciousUse") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsWinAdminShareSuspiciousUse") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsWinAdminShareSuspiciousUse") as alertPriority
```

## SecOpsWinAnonymousAccountCreated

**Summary:** Detects the creation of suspicious user accounts similar to ANONYMOUS LOGON. These accounts can be created as a means to evade defenses and monitoring by masquerading as a third party service.

**MITRE:** Tactics: Persistence (TA0003) | Techniques: Create Account (T1136)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.all.win
where event_id = 4720
where weaktoktains(target_username, "ANONYMOUS")
group every 5m by subject_username, target_username, source_ip, subject_domain, source_hostname, device, client
every 5m
//Entity Mapping Section
select source_hostname as entity_sourceHostname
select subject_username as entity_sourceAccount
select str(source_ip) as entity_sourceIP
select subject_domain as entity_sourceDomain
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceDomain) as entity_sourceDomain_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole
//<filtering_section>
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsWinAnonymousAccountCreated") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsWinAnonymousAccountCreated") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsWinAnonymousAccountCreated") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsWinAnonymousAccountCreated") as alertPriority
```

## SecOpsWinAppInstallerExecution

**Summary:** Detects a malicious execution of AppInstaller.exe that could be trying to download a file to the target machine.

**Description:** Detected execution of AppInstaller.exe that could be trying to download a file on $srcHost with ip $machineIp. Execution: $message

**MITRE:** Tactics: Command and Control (TA0011) | Techniques: Ingress Tool Transfer (T1105)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.all.win
where eq(event_id,4104) or eq(event_id,4103)
where `or`(toktains(process_command_line,"ms-appinstaller://?source",true,true), toktains(payload,"ms-appinstaller://?source",true,true))
group every 5m by machine_ip, source_hostname, process_command_line, payload, message, device, client
//Entity Mapping Section
select source_hostname as entity_sourceHostname
select machine_ip as entity_sourceIP
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole
//<filtering_section>
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsWinAppInstallerExecution") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsWinAppInstallerExecution") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsWinAppInstallerExecution") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsWinAppInstallerExecution") as alertPriority
```

## SecOpsWinAttackerToolsOnEndpoint

**Summary:** Adversaries may execute active reconnaissance scans to gather information that can be used during targeting by running well-known attacker tools.

**MITRE:** Tactics: Reconnaissance (TA0043) | Techniques: Active Scanning (T1595)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.all.win
where ((event_id = 1 and channel ="Microsoft-Windows-Sysmon/Operational") or event_id = 4688) and (weakhas(process_command_line, "remcom.exe") or weakhas(process_command_line, "pwdump.exe") or weakhas(process_command_line, "pwdump2.exe") or weakhas(process_command_line, "\\nc.exe") or weakhas(process_command_line, "wce.exe") or weakhas(process_command_line, "cain.exe") or weakhas(process_command_line, "nmap.exe") or weakhas(process_command_line, "kidlogger.exe") or weakhas(process_command_line, "isass.exe") or weakhas(process_command_line, "scvh0st.exe") or weakhas(process_command_line, "at.exe") or weakhas(process_command_line, "getmail.exe") or weakhas(process_command_line, "ntdll.exe") or weakhas(process_command_line, "netpass.exe") or weakhas(process_command_line, "WebBrowserPassView.exe") or weakhas(process_command_line, "OutlookAddressBookView.exe") or weakhas(process_command_line, "mailpv.exe") or weakhas(process_command_line, "NLBrute.exe") or weakhas(process_command_line, "selfdel.exe") or weakhas(process_command_line, "masscan.exe") or weakhas(process_command_line, "Massscan_GUI.exe") or weakhas(process_command_line, "KPortScan3.exe") or weakhas(process_command_line, "NLAChecker.exe") or weakhas(process_command_line, "SilverBullet.exe") or weakhas(process_command_line, "kportscan3.exe") or weakhas(process_command_line, "advanced_port_scanner.exe") or weakhas(process_command_line, "mimikatz"))
select source_hostname as entity_sourceHostname
select str(machine_ip) as entity_sourceIP
group every 5m by source_name, entity_sourceIP, entity_sourceHostname, process_command_line, device, client
every 5m
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsWinAttackerToolsOnEndpoint") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsWinAttackerToolsOnEndpoint") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsWinAttackerToolsOnEndpoint") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsWinAttackerToolsOnEndpoint") as alertPriority
```

## SecOpsWinAttemptToAddCertificateToStore

**Summary:** Detects a user attempting to add a certificate to the store via certutil.exe -addstore.

**MITRE:** Tactics: Defense Evasion (TA0005) | Techniques: Subvert Trust Controls (T1553)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, mispIndicator, SecOpsLocation, SecOpsAlertDescription

```linq
from box.all.win
where event_id = 4688, endswith(new_process_name, "certutil.exe"), weaktoktains(process_command_line, "-addstore")
group every 5m by subject_security_id, subject_username, subject_logon_id, subject_domain, machine, machine_ip, mandatory_label, device, client
, new_pid, new_process_name, caller_pid, caller_process_name, process_command_line, parent_process_name, token_elevation_type
//Entity Mapping Section
select str(machine_ip) as entity_sourceIP
select machine as entity_sourceHostname
select subject_username as entity_sourceAccount
select subject_domain as entity_sourceDomain
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceDomain) as entity_sourceDomain_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole
//<filtering_section>
//Enrichment Mapping
select asn(ip4(entity_sourceIP)) as enrichStream_entity_sourceIP_ASN
select isp(ip4(entity_sourceIP)) as enrichStream_entity_sourceIP_ISP
select countrycode(ip4(entity_sourceIP)) as enrichStream_entity_sourceIP_country
select ifthenelse(toktains(lu("mispIndicator", "eventtags_name_str", str(entity_sourceIP)),"TOR"), true, false) as enrichStream_entity_sourceIP_isAnonymousProxy
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
//Get Enrichment from SecOps
select lu("mispIndicator", "category", entity_sourceIP) as indicator
select lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type
select lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsWinAttemptToAddCertificateToStore") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsWinAttemptToAddCertificateToStore") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsWinAttemptToAddCertificateToStore") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsWinAttemptToAddCertificateToStore") as alertPriority
```

## SecOpsWinAuditLogCleared

**Summary:** Detects attempts to clear the Windows Security event log, which is a known adversary defense evasion technique.

**MITRE:** Tactics: Defense Evasion (TA0005) | Techniques: Indicator Removal (T1070)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.all.win
where `or`(event_id=1102, event_id=517), weaktoktains(raw, "cleared")
group every 5m by source_ip, subject_username, event_id, subject_domain, process_name, machine, source_hostname, machine_ip, device, client
every 5m
//Entity Mapping Section
select source_hostname as entity_sourceHostname
select subject_username as entity_sourceAccount
select source_ip as entity_sourceIP
select subject_domain as entity_sourceDomain
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceDomain) as entity_sourceDomain_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole
//<filtering_section>
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsWinAuditLogCleared") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsWinAuditLogCleared") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsWinAuditLogCleared") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsWinAuditLogCleared") as alertPriority
```

## SecOpsWinAutomatedCollectionCmd

**Summary:** Detects a command tha could be trying to compile a list of different sensitive files on the host.

**Description:** Detected a command that may be trying to compile a list of senstive files on $srcHost with ip $machineIp by user $subjectUsername. This activity should be reviewed to determine that this execution is not malicious. execution: $procCmdLine

**MITRE:** Tactics: Collection (TA0009) | Techniques: Automated Collection (T1119)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.all.win
where eq(event_id,4688)
where `or`(toktains(process_command_line,".doc",true,true), toktains(process_command_line,".docx",true,true), toktains(process_command_line,".xls",true,true), toktains(process_command_line,".xlsx",true,true), toktains(process_command_line,".ppt",true,true), toktains(process_command_line,".pptx",true,true), toktains(process_command_line,".rtf",true,true), toktains(process_command_line,".pdf",true,true), toktains(process_command_line,".txt",true,true),toktains(process_command_line,".odt",true,true),toktains(process_command_line,".ods",true,true))
where (toktains(process_command_line,"dir ",true,true) and toktains(process_command_line," /b ",true,true) and toktains(process_command_line," /s ",true,true)) or (weaktoktains(new_process_name,"findstr.exe",true,true) and (toktains(process_command_line," /e ",true,true) or toktains(process_command_line," /si ",true,true)))
group every 5m by machine_ip,subject_username,source_hostname,process_command_line, device, client
//Entity Mapping Section
select source_hostname as entity_sourceHostname
select subject_username as entity_sourceAccount
select machine_ip as entity_sourceIP
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole
//<filtering_section>
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsWinAutomatedCollectionCmd") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsWinAutomatedCollectionCmd") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsWinAutomatedCollectionCmd") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsWinAutomatedCollectionCmd") as alertPriority
```

## SecOpsWinAutomatedCollectionPowershell

**Summary:** Detects a Powershell command that could be trying to compile a list of different sensitive files on the host.

**Description:** Detected a Powershell command that may be trying to compile a list of senstive files on $srcHost with ip $machineIp by user $subjectUsername. This activity should be reviewed to determine that this execution is not malicious. execution: $procCmdLine

**MITRE:** Tactics: Collection (TA0009) | Techniques: Automated Collection (T1119)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.all.win
where eq(event_id,4104)
where `or`(toktains(process_command_line,".doc",true,true), toktains(process_command_line,".docx",true,true), toktains(process_command_line,".xls",true,true), toktains(process_command_line,".xlsx",true,true), toktains(process_command_line,".ppt",true,true), toktains(process_command_line,".pptx",true,true), toktains(process_command_line,".rtf",true,true), toktains(process_command_line,".pdf",true,true), toktains(process_command_line,".txt",true,true),toktains(process_command_line,".odt",true,true),toktains(process_command_line,".ods",true,true))
where toktains(process_command_line,"Get-ChildItem",true,true) and toktains(process_command_line," -Recurse",true,true) and toktains(process_command_line," -Include",true,true)
group every 5m by machine_ip,subject_username,source_hostname,process_command_line, device, client
//Entity Mapping Section
select source_hostname as entity_sourceHostname
select subject_username as entity_sourceAccount
select machine_ip as entity_sourceIP
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole
//<filtering_section>
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsWinAutomatedCollectionPowershell") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsWinAutomatedCollectionPowershell") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsWinAutomatedCollectionPowershell") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsWinAutomatedCollectionPowershell") as alertPriority
```

## SecOpsWinBackupCatalogDeleted

**Summary:** Detects suspicious usage of wbadmin.exe (Windows Backup Administrator Tool) to delete backup files.

**MITRE:** Tactics: Impact (TA0040) | Techniques: Inhibit System Recovery (T1490)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.all.win
where event_id=4688 and toktains(process_command_line, "delete") and `or`(toktains(process_command_line, "catalog"), toktains(process_command_line, "systemstatebackup"))
where weaktoktains(new_process_name, "wbadmin.exe")
group every 5m by subject_username, event_id, subject_domain, process_name, machine, subject_logon_id, source_hostname, new_process_name, device, client
, caller_process_name, process_command_line, machine_ip, target_username, target_domain, target_logon_id
, new_pid, token_elevation_type, mandatory_label, parent_process_name
every 5m
//Entity Mapping Section
select machine as entity_sourceHostname
select subject_username as entity_sourceAccount
select subject_domain as entity_sourceDomain
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceDomain) as entity_sourceDomain_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole
//<filtering_section>
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsWinBackupCatalogDeleted") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsWinBackupCatalogDeleted") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsWinBackupCatalogDeleted") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsWinBackupCatalogDeleted") as alertPriority
```

## SecOpsWinCompressEncryptData

**Summary:** Detects a potentially malicious command that could be compressing and/or encrypting data on the host.

**Description:** Detected a potentially malicious execution of a command trying to compress or encrypt data on $srcHost with ip $machineIp by user $subjectUsername. This activity should be reviewed to determine that this execution is not malicious. execution: $procCmdLine

**MITRE:** Tactics: Collection (TA0009) | Techniques: Archive Collected Data (T1560)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.all.win
where eq(event_id,4688)
where `or`((weaktoktains(new_process_name,"winrar.exe",true,true) or weaktoktains(new_process_name,"rar.exe",true,true)) and weaktoktains(process_command_line," a ",true,true), weaktoktains(new_process_name,"winzip",true,true) and (weaktoktains(process_command_line,"-a ",true,true) or weaktoktains(process_command_line,"-u ",true,true)), weaktoktains(new_process_name,"7z.exe",true,true) and weaktoktains(process_command_line," u ",true,true))
group every 5m by machine_ip,subject_username,source_hostname,process_command_line, device, client
//Entity Mapping Section
select source_hostname as entity_sourceHostname
select subject_username as entity_sourceAccount
select machine_ip as entity_sourceIP
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole
//<filtering_section>
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsWinCompressEncryptData") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsWinCompressEncryptData") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsWinCompressEncryptData") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsWinCompressEncryptData") as alertPriority
```

## SecOpsWinCredentialDumpingNppspy

**Summary:** An adversary may attempt to dump credentials to obtain account login and credential material in the form of clear text passwords.

**MITRE:** Tactics: Credential Access (TA0006) | Techniques: OS Credential Dumping (T1003)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.all.win
where ((event_id = 1 and channel ="Microsoft-Windows-Sysmon/Operational") or event_id = 4688) and weakhas(process_command_line, "NPPSPY.dll")
select source_hostname as entity_sourceHostname
select str(machine_ip) as entity_sourceIP
group every 5m by source_name, entity_sourceIP, entity_sourceHostname, process_command_line, device, client
every 5m
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsWinCredentialDumpingNppspy") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsWinCredentialDumpingNppspy") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsWinCredentialDumpingNppspy") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsWinCredentialDumpingNppspy") as alertPriority
```

## SecOpsWinCritServiceStopped

**Summary:** Detects various sc.exe or net.exe critical services being stopped via the command line.

**MITRE:** Tactics: Defense Evasion (TA0005) | Techniques: Impair Defenses (T1562)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.all.win
where event_id = 4688
where ((weaktoktains(process_command_line, "net") and weaktoktains(process_command_line, "stop")) or (weaktoktains(process_command_line, "sc") and weaktoktains(process_command_line, "stop")))
and (weaktoktains(process_command_line, "windefend") or weaktoktains(process_command_line, "mpssvc") or weaktoktains(process_command_line, "eventlog"))
group every 5m by event_id, machine_ip, subject_username, subject_logon_id, subject_domain, machine, new_pid, new_process_name, token_elevation_type, mandatory_label, process_command_line, parent_process_name, device, client
//Entity Mapping Section
select machine as entity_sourceHostname
select subject_username as entity_sourceAccount
select str(machine_ip) as entity_sourceIP
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole
//<filtering_section>
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsWinCritServiceStopped") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsWinCritServiceStopped") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsWinCritServiceStopped") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsWinCritServiceStopped") as alertPriority
```

## SecOpsWinCurl

**Summary:** Detects a potentially malicious Windows Curl execution.

**Description:** Detected a potentially malicious execution of Windows Curl method on $srcHost with ip $machineIp by user $subjectUsername. This activity should be reviewed to determine that this execution is not malicious. execution: $procCmdLine

**MITRE:** Tactics: Command and Control (TA0011), Exfiltration (TA0010) | Techniques: Ingress Tool Transfer (T1105), Exfiltration Over Alternative Protocol (T1048)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.all.win
where eq(event_id,4688)
where weaktoktains(new_process_name,"curl.exe",true,true)
where weaktoktains(process_command_line,"-F ",true,true) or weaktoktains(process_command_line," --form",true,true) or weaktoktains(process_command_line," -T ",true,true) or weaktoktains(process_command_line," --upload-file ",true,true) or weaktoktains(process_command_line," -d ",true,true) or weaktoktains(process_command_line," --data",true,true)
group every 5m by machine_ip,subject_username,source_hostname,process_command_line, device, client
//Entity Mapping Section
select source_hostname as entity_sourceHostname
select subject_username as entity_sourceAccount
select machine_ip as entity_sourceIP
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole
//<filtering_section>
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsWinCurl") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsWinCurl") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsWinCurl") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsWinCurl") as alertPriority
```

## SecOpsWinDcShadowDetected

**Summary:** Detects usage of Mimikatz modules. Attackers can temporarily set a computer to be a domain controller and make active directory updates.

**MITRE:** Tactics: Defense Evasion (TA0005), Lateral Movement (TA0008) | Techniques: Use Alternate Authentication Material (T1550)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.all.win
where `or`(
weaktoktains(process_command_line, "crypto::capi"),
weaktoktains(process_command_line, "crypto::certificates"),
weaktoktains(process_command_line, "crypto::certtohw"),
weaktoktains(process_command_line, "crypto::cng"),
weaktoktains(process_command_line, "crypto::extract"),
weaktoktains(process_command_line, "crypto::hash"),
weaktoktains(process_command_line, "crypto::keys"),
weaktoktains(process_command_line, "crypto::providers"),
weaktoktains(process_command_line, "crypto::sc"),
weaktoktains(process_command_line, "crypto::scauth"),
weaktoktains(process_command_line, "crypto::stores"),
weaktoktains(process_command_line, "crypto::system"),
weaktoktains(process_command_line, "crypto::tpminfo"),
weaktoktains(process_command_line, "dpapi::blob"),
weaktoktains(process_command_line, "dpapi::cache"),
weaktoktains(process_command_line, "dpapi::capi"),
weaktoktains(process_command_line, "dpapi::chrome"),
weaktoktains(process_command_line, "dpapi::cloudapkd"),
weaktoktains(process_command_line, "dpapi::cloudapreg"),
weaktoktains(process_command_line, "dpapi::cng"),
weaktoktains(process_command_line, "dpapi::create"),
weaktoktains(process_command_line, "dpapi::cred"),
weaktoktains(process_command_line, "dpapi::credhist"),
weaktoktains(process_command_line, "dpapi::luna"),
weaktoktains(process_command_line, "dpapi::masterkey"),
weaktoktains(process_command_line, "dpapi::protect"),
weaktoktains(process_command_line, "dpapi::ps"),
weaktoktains(process_command_line, "dpapi::rdg"),
weaktoktains(process_command_line, "dpapi::sccm"),
weaktoktains(process_command_line, "dpapi::ssh"),
weaktoktains(process_command_line, "dpapi::tpm"),
weaktoktains(process_command_line, "dpapi::vault"),
weaktoktains(process_command_line, "dpapi::wifi"),
weaktoktains(process_command_line, "dpapi::wwman"),
weaktoktains(process_command_line, "event::clear"),
weaktoktains(process_command_line, "event::drop"),
weaktoktains(process_command_line, "kerberos::ask"),
weaktoktains(process_command_line, "kerberos::clist"),
weaktoktains(process_command_line, "kerberos::golden"),
weaktoktains(process_command_line, "kerberos::hash"),
weaktoktains(process_command_line, "kerberos::list"),
weaktoktains(process_command_line, "kerberos::ptc"),
weaktoktains(process_command_line, "kerberos::ptt"),
weaktoktains(process_command_line, "kerberos::purge"),
weaktoktains(process_command_line, "kerberos::tgt"),
weaktoktains(process_command_line, "lsadump::backupkeys"),
weaktoktains(process_command_line, "lsadump::cache"),
weaktoktains(process_command_line, "lsadump::changentlm"),
weaktoktains(process_command_line, "lsadump::dcshadow"),
weaktoktains(process_command_line, "lsadump::dcsync"),
weaktoktains(process_command_line, "lsadump::lsa"),
weaktoktains(process_command_line, "lsadump::mbc"),
weaktoktains(process_command_line, "lsadump::netsync"),
weaktoktains(process_command_line, "lsadump::packages"),
weaktoktains(process_command_line, "lsadump::postzerologon"),
weaktoktains(process_command_line, "lsadump::RpData"),
weaktoktains(process_command_line, "lsadump::sam"),
weaktoktains(process_command_line, "lsadump::secrets"),
weaktoktains(process_command_line, "lsadump::setntlm"),
weaktoktains(process_command_line, "lsadump::trust"),
weaktoktains(process_command_line, "lsadump::zerologon"),
weaktoktains(process_command_line, "misc::aadcookie"),
weaktoktains(process_command_line, "misc::clip"),
weaktoktains(process_command_line, "misc::cmd"),
weaktoktains(process_command_line, "misc::compress"),
weaktoktains(process_command_line, "misc::detours"),
weaktoktains(process_command_line, "misc::efs"),
weaktoktains(process_command_line, "misc::lock"),
weaktoktains(process_command_line, "misc::memssp"),
weaktoktains(process_command_line, "misc::mflt"),
weaktoktains(process_command_line, "misc::ncroutemon"),
weaktoktains(process_command_line, "misc::ngcsign"),
weaktoktains(process_command_line, "misc::printnightmare"),
weaktoktains(process_command_line, "misc::regedit"),
weaktoktains(process_command_line, "misc::sccm"),
weaktoktains(process_command_line, "misc::shadowcopies"),
weaktoktains(process_command_line, "misc::skeleton"),
weaktoktains(process_command_line, "misc::spooler"),
weaktoktains(process_command_line, "misc::taskmgr"),
weaktoktains(process_command_line, "misc::wp"),
weaktoktains(process_command_line, "misc::xor"),
weaktoktains(process_command_line, "net::alias"),
weaktoktains(process_command_line, "net::deleg"),
weaktoktains(process_command_line, "net::group"),
weaktoktains(process_command_line, "net::if"),
weaktoktains(process_command_line, "net::serverinfo"),
weaktoktains(process_command_line, "net::session"),
weaktoktains(process_command_line, "net::share"),
weaktoktains(process_command_line, "net::stats"),
weaktoktains(process_command_line, "net::tod"),
weaktoktains(process_command_line, "net::trust"),
weaktoktains(process_command_line, "net::user"),
weaktoktains(process_command_line, "net::wsession"),
weaktoktains(process_command_line, "privilege::backup"),
weaktoktains(process_command_line, "privilege::debug"),
weaktoktains(process_command_line, "privilege::driver"),
weaktoktains(process_command_line, "privilege::id"),
weaktoktains(process_command_line, "privilege::name"),
weaktoktains(process_command_line, "privilege::restore"),
weaktoktains(process_command_line, "privilege::security"),
weaktoktains(process_command_line, "privilege::sysenv"),
weaktoktains(process_command_line, "privilege::tcb"),
weaktoktains(process_command_line, "process::exports"),
weaktoktains(process_command_line, "process::imports"),
weaktoktains(process_command_line, "process::list"),
weaktoktains(process_command_line, "process::resume"),
weaktoktains(process_command_line, "process::run"),
weaktoktains(process_command_line, "process::runp"),
weaktoktains(process_command_line, "process::start"),
weaktoktains(process_command_line, "process::stop"),
weaktoktains(process_command_line, "process::suspend"),
weaktoktains(process_command_line, "rpc::close"),
weaktoktains(process_command_line, "rpc::connect"),
weaktoktains(process_command_line, "rpc::enum"),
weaktoktains(process_command_line, "rpc::server"),
weaktoktains(process_command_line, "sekurlsa::backupkeys"),
weaktoktains(process_command_line, "sekurlsa::bootkey"),
weaktoktains(process_command_line, "sekurlsa::cloudap"),
weaktoktains(process_command_line, "sekurlsa::credman"),
weaktoktains(process_command_line, "sekurlsa::dpapi"),
weaktoktains(process_command_line, "sekurlsa::dpapisystem"),
weaktoktains(process_command_line, "sekurlsa::ekeys"),
weaktoktains(process_command_line, "sekurlsa::kerberos"),
weaktoktains(process_command_line, "sekurlsa::krbtgt"),
weaktoktains(process_command_line, "sekurlsa::livessp"),
weaktoktains(process_command_line, "sekurlsa::logonpasswords"),
weaktoktains(process_command_line, "sekurlsa::minidump"),
weaktoktains(process_command_line, "sekurlsa::msv"),
weaktoktains(process_command_line, "sekurlsa::process"),
weaktoktains(process_command_line, "sekurlsa::pth"),
weaktoktains(process_command_line, "sekurlsa::ssp"),
weaktoktains(process_command_line, "sekurlsa::tickets"),
weaktoktains(process_command_line, "sekurlsa::trust"),
weaktoktains(process_command_line, "sekurlsa::tspkg"),
weaktoktains(process_command_line, "sekurlsa::wdigest"),
weaktoktains(process_command_line, "service::-"),
weaktoktains(process_command_line, "service::+"),
weaktoktains(process_command_line, "service::preshutdown"),
weaktoktains(process_command_line, "service::remove"),
weaktoktains(process_command_line, "service::resume"),
weaktoktains(process_command_line, "service::shutdown"),
weaktoktains(process_command_line, "service::start"),
weaktoktains(process_command_line, "service::stop"),
weaktoktains(process_command_line, "service::suspend"),
weaktoktains(process_command_line, "sid::add"),
weaktoktains(process_command_line, "sid::clear"),
weaktoktains(process_command_line, "sid::lookup"),
weaktoktains(process_command_line, "sid::modify"),
weaktoktains(process_command_line, "sid::patch"),
weaktoktains(process_command_line, "sid::query"),
weaktoktains(process_command_line, "standard::answer"),
weaktoktains(process_command_line, "standard::base64"),
weaktoktains(process_command_line, "standard::cd"),
weaktoktains(process_command_line, "standard::cls"),
weaktoktains(process_command_line, "standard::coffee"),
weaktoktains(process_command_line, "standard::exit"),
weaktoktains(process_command_line, "standard::hostname"),
weaktoktains(process_command_line, "standard::localtime"),
weaktoktains(process_command_line, "standard::log"),
weaktoktains(process_command_line, "standard::sleep"),
weaktoktains(process_command_line, "standard::version"),
weaktoktains(process_command_line, "token::elevate"),
weaktoktains(process_command_line, "token::list"),
weaktoktains(process_command_line, "token::revert"),
weaktoktains(process_command_line, "token::run"),
weaktoktains(process_command_line, "token::whoami"),
weaktoktains(process_command_line, "ts::logonpasswords"),
weaktoktains(process_command_line, "ts::mstsc"),
weaktoktains(process_command_line, "ts::multirdp"),
weaktoktains(process_command_line, "ts::remote"),
weaktoktains(process_command_line, "ts::sessions"),
weaktoktains(process_command_line, "vault::cred"),
weaktoktains(process_command_line, "vault::list"))
group every 5m by event_id, subject_username, new_process_name, parent_process_name, caller_process_name, process_command_line, machine, subject_domain, machine_ip, device, client
//Entity Mapping Section
select machine as entity_sourceHostname
select subject_username as entity_sourceAccount
select str(machine_ip) as entity_sourceIp
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceIp) as entity_sourceIp_AssetRole
//<filtering_section>
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsWinDcShadowDetected") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsWinDcShadowDetected") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsWinDcShadowDetected") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsWinDcShadowDetected") as alertPriority
```

## SecOpsWinDefenderDownloadActivity

**Summary:** Detects the use of Microsoft Defender to download files.

**MITRE:** Tactics: Command and Control (TA0011) | Techniques: Ingress Tool Transfer (T1105)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, mispIndicator, SecOpsLocation, SecOpsAlertDescription

```linq
from box.all.win
where event_id=4688
where weaktoktains(new_process_name, "mpcmdrun.exe"), weaktoktains(process_command_line, "downloadfile"), weaktoktains(process_command_line, "url")
group every 5m by subject_security_id, subject_username, subject_logon_id, subject_domain, machine, machine_ip, device, client
, target_security_id, target_username, target_logon_id, target_domain, parent_process_name
, new_pid, new_process_name, token_elevation_type, mandatory_label, process_command_line
//Entity Mapping Section
select machine as entity_sourceHostname
select subject_username as entity_sourceAccount
select str(machine_ip) as entity_sourceIP
select subject_domain as entity_sourceDomain
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceDomain) as entity_sourceDomain_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole
//<filtering_section>
//Enrichment Mapping
select asn(ip4(entity_sourceIP)) as enrichStream_entity_sourceIP_ASN
select isp(ip4(entity_sourceIP)) as enrichStream_entity_sourceIP_ISP
select countrycode(ip4(entity_sourceIP)) as enrichStream_entity_sourceIP_country
select ifthenelse(toktains(lu("mispIndicator", "eventtags_name_str", str(entity_sourceIP)),"TOR"), true, false) as enrichStream_entity_sourceIP_isAnonymousProxy
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
//Get Enrichment from SecOps
select lu("mispIndicator", "category", entity_sourceIP) as indicator
select lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type
select lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsWinDefenderDownloadActivity") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsWinDefenderDownloadActivity") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsWinDefenderDownloadActivity") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsWinDefenderDownloadActivity") as alertPriority
```

## SecOpsWinDisableAntispywareRegistry

**Summary:** Detects users enabling the DisableAntiSpyware registry key. Attackers may utilize this technique for evasion.

**MITRE:** Tactics: Defense Evasion (TA0005) | Techniques: Impair Defenses (T1562)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.all.win
where event_id = 4657, object_value_name="DisableAntiSpyware"
where new_value = "1"
group every 5m by source_ip, subject_username, event_id,subject_domain, process_name, machine, source_hostname, object_name, device, client
, object_value_name, new_value, machine_ip
every 5m
//Entity Mapping Section
select source_hostname as entity_sourceHostname
select subject_username as entity_sourceAccount
select source_ip as entity_sourceIP
select subject_domain as entity_sourceDomain
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceDomain) as entity_sourceDomain_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole
//<filtering_section>
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsWinDisableAntispywareRegistry") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsWinDisableAntispywareRegistry") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsWinDisableAntispywareRegistry") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsWinDisableAntispywareRegistry") as alertPriority
```

## SecOpsWinDisableUac

**Summary:** Detects users modifying registry keys that control the enforcement of Windows User Account Control (UAC).

**MITRE:** Tactics: Defense Evasion (TA0005) | Techniques: Modify Registry (T1112)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, mispIndicator, SecOpsLocation, SecOpsAlertDescription

```linq
from box.all.win
where event_id=4657
where weaktoktains(object_name, "microsoft\\windows\\currentversion\\policies\\system"), weaktoktains(object_value_name, "EnableLUA"), new_value="0"
group every 5m by source_ip, subject_username, event_id,subject_domain, process_name, machine, source_hostname, object_name, device, client
, object_value_name, new_value, machine_ip
every 5m
//Entity Mapping Section
select source_hostname as entity_sourceHostname
select subject_username as entity_sourceAccount
select source_ip as entity_sourceIP
select subject_domain as entity_sourceDomain
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceDomain) as entity_sourceDomain_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole
//<filtering_section>
//Enrichment Mapping
select asn(ip4(entity_sourceIP)) as enrichStream_entity_sourceIP_ASN
select isp(ip4(entity_sourceIP)) as enrichStream_entity_sourceIP_ISP
select countrycode(ip4(entity_sourceIP)) as enrichStream_entity_sourceIP_country
select ifthenelse(toktains(lu("mispIndicator", "eventtags_name_str", str(entity_sourceIP)),"TOR"), true, false) as enrichStream_entity_sourceIP_isAnonymousProxy
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
//Get Enrichment from SecOps
select lu("mispIndicator", "category", entity_sourceIP) as indicator
select lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type
select lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsWinDisableUac") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsWinDisableUac") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsWinDisableUac") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsWinDisableUac") as alertPriority
```

## SecOpsWinDnsExeParentProcess

**Summary:** Detects DNS.EXE program spawning other processes.

**MITRE:** Tactics: Persistence (TA0003) | Techniques: External Remote Services (T1133)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.all.win
where event_id = 4688
where weaktoktains(parent_process_name, "dns.exe") and isnotnull(new_process_name)
group every 5m by subject_username, subject_domain, subject_logon_id, new_pid, new_process_name, token_elevation_type, pid, process_command_line, target_security_id, target_username, target_domain, target_logon_id, parent_process_name, mandatory_label, machine, machine_ip, device, client
every 5m
//Entity Mapping Section
select machine as entity_sourceHostname
select subject_username as entity_sourceAccount
select subject_domain as entity_sourceDomain
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceDomain) as entity_sourceDomain_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole
//<filtering_section>
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsWinDnsExeParentProcess") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsWinDnsExeParentProcess") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsWinDnsExeParentProcess") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsWinDnsExeParentProcess") as alertPriority
```

## SecOpsWinDomainTrustActivity

**Summary:** Detects when a user has attempted to gather information on the domain trust.

**MITRE:** Tactics: Discovery (TA0007) | Techniques: Domain Trust Discovery (T1482)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.all.win
where event_id = 4688
where (weaktoktains(process_command_line, "nltest") and weaktoktains(process_command_line, "/domain_trusts")) or weaktoktains(process_command_line, "dsquery")
group every 5m by event_id, machine_ip, subject_username, subject_logon_id, subject_domain, machine, new_pid, new_process_name, token_elevation_type, mandatory_label, process_command_line, parent_process_name, device, client
//Entity Mapping Section
select machine as entity_sourceHostname
select subject_username as entity_sourceAccount
select str(machine_ip) as entity_sourceIp
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceIp) as entity_sourceIp_AssetRole
//<filtering_section>
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsWinDomainTrustActivity") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsWinDomainTrustActivity") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsWinDomainTrustActivity") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsWinDomainTrustActivity") as alertPriority
```

## SecOpsWinExcessiveUserInteractiveLogin

**Summary:** Detects when a user performs a significant number of Windows interactive logins to multiple destination hosts in a 24 hour period.

**MITRE:** Tactics: Persistence (TA0003) | Techniques: Valid Accounts (T1078)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, mispIndicator, SecOpsLocation, SecOpsAlertDescription

```linq
from box.all.win
where event_id=4624
where LogonType="2" or LogonType="10"
group every 10m by event_id, account, source_ip, subject_domain, device, client
select count() as count, int(hllppcount(source_hostname)) as host_count
where host_count >=5
select first(eventdate) as first_seen
select last (eventdate) as last_seen
//Entity Mapping Section
select nnlast(source_hostname) as entity_sourceHostname
select account as entity_sourceAccount
select source_ip as entity_sourceIP
select subject_domain as entity_sourceDomain
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceDomain) as entity_sourceDomain_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole
//<filtering_section>
//Enrichment Mapping
select asn(ip4(source_ip)) as enrichStream_entity_sourceIP_ASN
select isp(ip4(source_ip)) as enrichStream_entity_sourceIP_ISP
select countrycode(ip4(source_ip)) as enrichStream_entity_sourceIP_country
select ifthenelse(toktains(lu("mispIndicator", "eventtags_name_str", str(entity_sourceIP)),"TOR"), true, false) as enrichStream_entity_sourceIP_isAnonymousProxy
//Get Enrichment from SecOps
select lu("mispIndicator", "category", entity_sourceIP) as indicator
select lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type
select lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsWinExcessiveUserInteractiveLogin") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsWinExcessiveUserInteractiveLogin") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsWinExcessiveUserInteractiveLogin") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsWinExcessiveUserInteractiveLogin") as alertPriority
```

## SecOpsWinExternalDeviceInstallationDenied

**Summary:** Detects hardware installation failures due to policy. Device installation logging must be configured (see logging related reference links).

**MITRE:** Tactics: Collection (TA0009), Exfiltration (TA0010), Command and Control (TA0011) | Techniques: Data from Removable Media (T1025), Exfiltration Over Physical Medium (T1052), Communication Through Removable Media (T1092)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, mispIndicator, SecOpsLocation, SecOpsAlertDescription

```linq
from box.all.win
where event_id=6423
group every 5m by subject_username, subject_domain, subject_logon_id, device, client
, machine_ip, machine, device_id, device_name, class_id, class_name
//Entity Mapping Section
select machine as entity_sourceHostname
select subject_username as entity_sourceAccount
select str(machine_ip) as entity_sourceIP
select subject_domain as entity_sourceDomain
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceDomain) as entity_sourceDomain_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole
//<filtering_section>
//Enrichment Mapping
select asn(ip4(entity_sourceIP)) as enrichStream_entity_sourceIP_ASN
select isp(ip4(entity_sourceIP)) as enrichStream_entity_sourceIP_ISP
select countrycode(ip4(entity_sourceIP)) as enrichStream_entity_sourceIP_country
select ifthenelse(toktains(lu("mispIndicator", "eventtags_name_str", str(entity_sourceIP)),"TOR"), true, false) as enrichStream_entity_sourceIP_isAnonymousProxy
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
//Get Enrichment from SecOps
select lu("mispIndicator", "category", entity_sourceIP) as indicator
select lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type
select lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsWinExternalDeviceInstallationDenied") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsWinExternalDeviceInstallationDenied") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsWinExternalDeviceInstallationDenied") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsWinExternalDeviceInstallationDenied") as alertPriority
```

## SecOpsWinFakeProcesses

**Summary:** Detects instances of known Windows processes executing outside of standard directories. Malware authors often utilize masquerading to hide malicious executables behind legitimate Windows executable names.

**MITRE:** Tactics: Defense Evasion (TA0005) | Techniques: Masquerading (T1036)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.all.win
where event_id=4688
where not(`or`(weaktoktains(new_process_name, ":\\Windows\\System32\\"), weaktoktains(new_process_name, ":\\Windows\\SysWOW64")))
where `or`( weaktoktains(new_process_name, "svchost.exe") , weaktoktains(new_process_name, "smss.exe")
, weaktoktains(new_process_name, "wininit.exe"), weaktoktains(new_process_name, "taskhost.exe")
, weaktoktains(new_process_name, "lsass.exe") , weaktoktains(new_process_name, "winlogon.exe")
, weaktoktains(new_process_name, "csrss.exe"), weaktoktains(new_process_name, "services.exe")
, weaktoktains(new_process_name, "lsm.exe"), weaktoktains(new_process_name, "explorer.exe")
)
group every 5m by subject_security_id, subject_username, subject_logon_id, subject_domain, machine, machine_ip, device, client
, new_pid, new_process_name, caller_pid, caller_process_name, token_elevation_type, mandatory_label, process_command_line, parent_process_name
//Entity Mapping Section
select str(machine_ip) as entity_sourceIP
select machine as entity_sourceHostname
select subject_username as entity_sourceAccount
select subject_domain as entity_sourceDomain
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceDomain) as entity_sourceDomain_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole
//<filtering_section>
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsWinFakeProcesses") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsWinFakeProcesses") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsWinFakeProcesses") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsWinFakeProcesses") as alertPriority
```

## SecOpsWinFsutilDeleteChangeJournal

**Summary:** An adversary may attempt to delete the persistent logs of all changes made to files on a volume to hide his actions.

**MITRE:** Tactics: Defense Evasion (TA0005) | Techniques: Hide Artifacts (T1564)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.all.win
where ((event_id = 1 and channel ="Microsoft-Windows-Sysmon/Operational") or event_id = 4688) and (weakhas(process_command_line, "fsutil") and weakhas(process_command_line, "deletejournal"))
select source_hostname as entity_sourceHostname
select str(machine_ip) as entity_sourceIP
group every 5m by source_name, entity_sourceIP, entity_sourceHostname, process_command_line, device, client
every 5m
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsWinFsutilDeleteChangeJournal") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsWinFsutilDeleteChangeJournal") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsWinFsutilDeleteChangeJournal") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsWinFsutilDeleteChangeJournal") as alertPriority
```

## SecOpsWinFTPScriptExecution

**Summary:** Detects a potentially malicious execution of FTP binary.

**Description:** Detected a potentially malicious ftp execution on $srcHost with ip $machineIp by user $subjectUsername. This activity should be reviewed to determine that this execution is not malicious. execution: $procCmdLine

**MITRE:** Tactics: Command and Control (TA0011), Exfiltration (TA0010) | Techniques: Ingress Tool Transfer (T1105), Exfiltration Over Alternative Protocol (T1048)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.all.win
where eq(event_id,4688)
where weaktoktains(new_process_name,"ftp.exe",true,true)
where `or`(weaktoktains(process_command_line," /s:",true,true),weaktoktains(process_command_line," -s:",true,true))
group every 5m by machine_ip,subject_username,source_hostname,process_command_line, device, client
//Entity Mapping Section
select source_hostname as entity_sourceHostname
select subject_username as entity_sourceAccount
select machine_ip as entity_sourceIP
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole
//<filtering_section>
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsWinFTPScriptExecution") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsWinFTPScriptExecution") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsWinFTPScriptExecution") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsWinFTPScriptExecution") as alertPriority
```

## SecOpsWinGatherVictimIdentitySAMInfo

**Summary:** The Samlib.dll module is being abused by adversaries, threat actors, and red teamers to access information on SAM objects or access credentials information in DC. Information about the victim's identity can be used during targeting.

**MITRE:** Tactics: Reconnaissance (TA0043) | Techniques: Gather Victim Identity Information (T1589)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.all.win
where (eq(event_id, 7) and eq(channel, "Microsoft-Windows-Sysmon/Operational"))
select source_hostname as entity_sourceHostname
select str(machine_ip) as entity_sourceIP
select str(jqeval(jqcompile(".columns.data.EventData.ImageLoaded"), jsonparse(rawMessage))) as new_imageLoaded
where ((weakhas(new_imageLoaded, "\\samlib.dll") and eqic(original_file_name, "samlib.dll")) or (weakhas(new_imageLoaded, "\\samcli.dll") and eqic(original_file_name, "samcli.dll"))) and not (weakhas(image, "C:\\Windows\\") or weakhas(image, "C:\\Program File") or weakhas(image, "%systemroot%\\"))
group every 5m by source_name, channel, event_id, entity_sourceIP, entity_sourceHostname, original_file_name, image, new_imageLoaded, device, client
every 5m
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsWinGatherVictimIdentitySAMInfo") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsWinGatherVictimIdentitySAMInfo") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsWinGatherVictimIdentitySAMInfo") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsWinGatherVictimIdentitySAMInfo") as alertPriority
```

## SecOpsWinGoldenSamlCertificateExport

**Summary:** Detects for potential certificate export to bypass authentication mechanisms.

**MITRE:** Tactics: Credential Access (TA0006) | Techniques: Steal or Forge Kerberos Tickets (T1558)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.all.win
where ((event_id = 1 and channel ="Microsoft-Windows-Sysmon/Operational") or event_id = 4688) and ((weakhas(process_command_line, "certutil.exe") and weakhas(process_command_line, "-exportPFX")) or (weakhas(process_command_line, "Export-PfxCertificate")) or (weakhas(process_command_line, "MICROSOFT##WID")))
select source_hostname as entity_sourceHostname
select str(machine_ip) as entity_sourceIP
group every 5m by source_name, entity_sourceIP, entity_sourceHostname, process_command_line, device, client
every 5m
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsWinRegistryModificationActivateNoRunGroupPolicy") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsWinRegistryModificationActivateNoRunGroupPolicy") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsWinRegistryModificationActivateNoRunGroupPolicy") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsWinRegistryModificationActivateNoRunGroupPolicy") as alertPriority
```

## SecOpsWinIcmpExfiltration

**Summary:** Detects exfiltration via ICMP.

**Description:** Detected a possible data exfiltration over ICMP on $srcHost with ip $machineIp by user $subjectUsername. This activity should be reviewed to determine that this execution is not malicious. execution: $procCmdLine

**MITRE:** Tactics: Exfiltration (TA0010) | Techniques: Exfiltration Over Alternative Protocol (T1048)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.all.win
where eq(event_id,4688) or eq(event_id,4104) or eq(event_id,4103)
where weaktoktains(rawMessage,"New-Object",true,true) and weaktoktains(process_command_line,"System.Net.NetworkInformation.Ping",true,true) and weaktoktains(process_command_line,".Send(",true,true)
group every 5m by machine_ip,subject_username,source_hostname,process_command_line, device, client
//Entity Mapping Section
select source_hostname as entity_sourceHostname
select subject_username as entity_sourceAccount
select machine_ip as entity_sourceIP
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole
//<filtering_section>
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsWinIcmpExfiltration") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsWinIcmpExfiltration") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsWinIcmpExfiltration") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsWinIcmpExfiltration") as alertPriority
```

## SecOpsWinIISWebRootProcessExecution

**Summary:** The execution of a process from inside a web hosting directory. cand indicate when adversaries upload a malicious file to the web server and run the file as a process.

**MITRE:** Tactics: Persistence (TA0003) | Techniques: Server Software Component (T1505)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.all.win
where ((event_id = 1 and channel ="Microsoft-Windows-Sysmon/Operational") or event_id = 4688) and (weakhas(new_process_name, "C:\\Inetpub\\wwwroot\\") or weakhas(current_directory,  "C:\\Inetpub\\wwwroot\\"))
select source_hostname as entity_sourceHostname
select str(machine_ip) as entity_sourceIP
group every 5m by source_name, entity_sourceIP, entity_sourceHostname, process_command_line, current_directory, new_process_name, device, client
every 5m
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsWinIISWebRootProcessExecution") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsWinIISWebRootProcessExecution") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsWinIISWebRootProcessExecution") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsWinIISWebRootProcessExecution") as alertPriority
```

## SecOpsWinInvokewebrequestUse

**Summary:** Detects a potentially malicious Invoke-WebRequest method execution.

**Description:** Detected a potentially malicious execution of a Invoke-WebRequest method on $srcHost with ip $machineIp by user $subjectUsername. This activity should be reviewed to determine that this execution is not malicious. execution: $procCmdLine

**MITRE:** Tactics: Command and Control (TA0011), Exfiltration (TA0010) | Techniques: Ingress Tool Transfer (T1105), Exfiltration Over Alternative Protocol (T1048)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.all.win
where eq(event_id,4688)
where weaktoktains(new_process_name,"powershell",true,true)
where weaktoktains(process_command_line,"Invoke-WebRequest",true,true) or weaktoktains(process_command_line,"iwr ",true,true)
where weaktoktains(process_command_line,"-Uri",true,true) or weaktoktains(process_command_line,"Post ",true,true) or weaktoktains(process_command_line,"Put ",true,true) or weaktoktains(process_command_line,"-OutFile",true,true)
group every 5m by machine_ip,subject_username,source_hostname,process_command_line, device, client
//Entity Mapping Section
select source_hostname as entity_sourceHostname
select subject_username as entity_sourceAccount
select machine_ip as entity_sourceIP
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole
//<filtering_section>
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsWinInvokewebrequestUse") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsWinInvokewebrequestUse") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsWinInvokewebrequestUse") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsWinInvokewebrequestUse") as alertPriority
```

## SecOpsWinKerberosUserEnumeration

**Summary:** Adversaries may gather information about the victim's identity that can be used during targeting. Information about identities may include a variety of details, including personal data as well as sensitive details such as credentials.

**MITRE:** Tactics: Reconnaissance (TA0043) | Techniques: Gather Victim Identity Information (T1589)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.all.win
where eq(str(event_id), "4768") and eq(status, "0x6")
select source_hostname as entity_sourceHostname
select str(machine_ip) as entity_sourceIP
select account as entity_destinationAccount
group every 5m by event_id, entity_sourceHostname, entity_sourceIP, device, client
every 5m
select int(hllppcount(entity_destinationAccount)) as num_accounts
where num_accounts > 5
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsWinKerberosUserEnumeration") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsWinKerberosUserEnumeration") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsWinKerberosUserEnumeration") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsWinKerberosUserEnumeration") as alertPriority
```

## SecOpsWinLocalSystemExecuteWhoami

**Summary:** Detects a local system executing whoami.exe on the command prompt. Adversaries often run this command to understand account privileges. Investigate the parent process and user account for other related, suspicious activity.

**MITRE:** Tactics: Discovery (TA0007) | Techniques: System Owner/User Discovery (T1033)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.all.win
where event_id = 4688 and weaktoktains(process_command_line, "whoami")
where endswith(new_process_name, "whoami.exe")
group every 5m by subject_security_id, subject_username, subject_logon_id, subject_domain, machine, machine_ip, device, client
, target_security_id, target_username, target_logon_id, target_domain, token_elevation_type, mandatory_label
, new_pid, new_process_name, caller_pid, caller_process_name, process_command_line, parent_process_name
//Entity Mapping Section
select machine as entity_sourceHostname
select subject_username as entity_sourceAccount
select subject_domain as entity_sourceDomain
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceDomain) as entity_sourceDomain_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole
//<filtering_section>
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsWinLocalSystemExecuteWhoami") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsWinLocalSystemExecuteWhoami") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsWinLocalSystemExecuteWhoami") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsWinLocalSystemExecuteWhoami") as alertPriority
```

## SecOpsWinLockoutsEndpoint

**Summary:** Multiple Windows account lockouts detected on same endpoint.

**MITRE:** Tactics: Credential Access (TA0006) | Techniques: Brute Force (T1110)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.all.win
where event_id=4740
group every 1h by source_hostname, source_ip, event_id, machine, machine_ip, device, client
select int(hllppcount(account)) as accounts_locked_out
where accounts_locked_out >=2
select first(eventdate) as first_seen, last (eventdate) as last_seen, collectdistinct(account) as accounts
//Entity Mapping Section
select source_hostname as entity_sourceHostname
select source_ip as entity_sourceIP
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole
//<filtering_section>
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsWinLockoutsEndpoint") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsWinLockoutsEndpoint") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsWinLockoutsEndpoint") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsWinLockoutsEndpoint") as alertPriority
```

## SecOpsWinLsassKeyModification

**Summary:** Monitors for changes to lsass.exe-related registry keys that are often edited to enable or obfuscate activity related to dumping the process.

**MITRE:** Tactics: Defense Evasion (TA0005) | Techniques: Modify Registry (T1112)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.all.win
where toktains (raw,"LSA") or toktains (raw,"WDigest")
where event_id = 4657
group every 5m by machine, machine_ip, subject_security_id, subject_username, subject_domain, subject_logon_id, device, client
, pid, process_name, object_name, object_value_name, new_value
//Entity Mapping Section
select machine as entity_sourceHostname
select subject_username as entity_sourceAccount
select str(machine_ip) as entity_sourceIP
select subject_domain as entity_sourceDomain
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceDomain) as entity_sourceDomain_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole
//<filtering_section>
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsWinLsassKeyModification") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsWinLsassKeyModification") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsWinLsassKeyModification") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsWinLsassKeyModification") as alertPriority
```

## SecOpsWinLsassMemDump

**Summary:** Detects and attempt to access lsass using mimikatz and/or a possible mimikatz driver load

**Description:** Detects attempts to access credential material stored in the process memory of the Local Security Authority Subsystem Service (LSASS). In addition to that, it will also detect if the mimikatz driver was loaded.

**MITRE:** Tactics: Credential Access (TA0006) | Techniques: OS Credential Dumping (T1003)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.all.win
where (event_id = 4697 and isnull(process_name)) or
(
    event_id = 4663 and
    access_mask = "0x10" and
    toktains(lower(object_name),"lsass")
)
where not toktains(account, "$")
select ifthenelse(event_id=4697, service_file_name,"N/A") as serviceName
group every 5m by source_hostname, source_ip, serviceName, event_id, process_name, object_name, machine, machine_ip, device, client
//Entity Mapping Section
select source_hostname as entity_sourceHostname
select source_ip as entity_sourceIP
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole
//<filtering_section>
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsWinLsassMemDump") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsWinLsassMemDump") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsWinLsassMemDump") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsWinLsassMemDump") as alertPriority
```

## SecOpsWinMapSmbShare

**Summary:** Detects a potentially malicious command that could be related to a mapping of an SMB share.

**Description:** Detected a potentially malicious execution of a command trying to mount an smb share on $srcHost with ip $machineIp by user $subjectUsername. This activity should be reviewed to determine that this execution is not malicious. execution: $procCmdLine

**MITRE:** Tactics: Command and Control (TA0011), Exfiltration (TA0010), Lateral Movement (TA0008) | Techniques: Ingress Tool Transfer (T1105), Exfiltration Over Alternative Protocol (T1048), Remote Services (T1021)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.all.win
where eq(event_id,4688)
where `and`(weaktoktains(process_command_line,"net use ",true,true),weaktoktains(process_command_line,"\\",true,true) or weaktoktains(process_command_line,"$",true,true))
group every 5m by machine_ip,subject_username,source_hostname,process_command_line, device, client
//Entity Mapping Section
select source_hostname as entity_sourceHostname
select subject_username as entity_sourceAccount
select machine_ip as entity_sourceIP
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole
//<filtering_section>
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsWinMapSmbShare") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsWinMapSmbShare") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsWinMapSmbShare") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsWinMapSmbShare") as alertPriority
```

## SecOpsWinMemoryCorruptionVulnerability

**Summary:** Detects exploitation of Microsoft Office Memory Corruption Vulnerability (CVE-2015-1641) allowing remote code execution.

**MITRE:** Tactics: Defense Evasion (TA0005) | Techniques: Masquerading (T1036)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.all.win
where eq(str(event_id), "4688") and weakhas(parent_process_name, "winword.exe"), weakhas(new_process_name, "microscmgmt.exe")
select source_hostname as entity_sourceHostname
select str(machine_ip) as entity_sourceIP
group every 5m by source_name, entity_sourceIP, entity_sourceHostname, parent_process_name, new_process_name, process_command_line, device, client
every 5m
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsWinMemoryCorruptionVulnerability") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsWinMemoryCorruptionVulnerability") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsWinMemoryCorruptionVulnerability") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsWinMemoryCorruptionVulnerability") as alertPriority
```

## SecOpsWinMimikatzLsadump

**Summary:** An adversary may attempt to dump credentials to obtain account login and credential material in the form of hashes or clear text passwords.

**MITRE:** Tactics: Credential Access (TA0006) | Techniques: OS Credential Dumping (T1003)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.all.win
where (event_id = 4663 or event_id = 4659 or event_id = 4656 or event_id = 4660 or event_id = 4658) and
isnotnull(object_name)
where toktains(lower(object_name), ".dmp") or toktains(lower(object_name), ".kirbi")
select source_hostname as entity_sourceHostname
select str(machine_ip) as entity_sourceIP
group every 5m by source_name, entity_sourceIP, entity_sourceHostname, object_name, device, client
every 5m
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsWinMimikatzLsadump") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsWinMimikatzLsadump") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsWinMimikatzLsadump") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsWinMimikatzLsadump") as alertPriority
```

## SecOpsWinModifyShowCompressColorAndInfoTipRegistry

**Summary:** Adversaries may interact with the Windows Registry to hide configuration information within Registry keys, remove information as part of cleaning up, or as part of other techniques to aid in persistence and execution.

**MITRE:** Tactics: Defense Evasion (TA0005) | Techniques: Modify Registry (T1112)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.all.win
where ((event_id = 1 and channel ="Microsoft-Windows-Sysmon/Operational") or event_id = 4688) and ((weakhas(process_command_line, "reg") and weakhas(process_command_line, "add")) or weakhas(process_command_line, "New-ItemProperty")) and ( weakhas(process_command_line, "ShowInfoTip") or weakhas(process_command_line, "ShowCompColor"))
select source_hostname as entity_sourceHostname
group every 5m by entity_sourceHostname, device, client
every 5m
select int(hllppcount(process_command_line)) as num_added_regKeys
where num_added_regKeys = 2
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsWinModifyShowCompressColorAndInfoTipRegistry") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsWinModifyShowCompressColorAndInfoTipRegistry") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsWinModifyShowCompressColorAndInfoTipRegistry") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsWinModifyShowCompressColorAndInfoTipRegistry") as alertPriority
```

## SecOpsWinMsiExecInstallWeb

**Summary:** Detects when a suspicious MsiExec process starts with a web address as a parameter.

**MITRE:** Tactics: Defense Evasion (TA0005) | Techniques: System Binary Proxy Execution (T1218)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.all.win
where event_id = 4688
where weaktoktains(new_process_name, "msiexec.exe") and toktains(process_command_line, "://")
group every 5m by subject_security_id, subject_username, subject_domain, subject_logon_id, new_pid, new_process_name, token_elevation_type, device, client
, pid, process_command_line, target_security_id, target_username, target_domain, target_logon_id, parent_process_name, mandatory_label
, machine, machine_ip
every 5m
//Entity Mapping Section
select machine as entity_sourceHostname
select subject_username as entity_sourceAccount
select subject_domain as entity_sourceDomain
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceDomain) as entity_sourceDomain_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole
//<filtering_section>
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsWinMsiExecInstallWeb") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsWinMsiExecInstallWeb") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsWinMsiExecInstallWeb") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsWinMsiExecInstallWeb") as alertPriority
```

## SecOpsWinNetworkShareCreated

**Summary:** Detects the creation of a new Windows network share.

**MITRE:** Tactics: Lateral Movement (TA0008) | Techniques: Remote Services (T1021)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, mispIndicator, SecOpsLocation, SecOpsAlertDescription

```linq
from box.all.win
where event_id=5142 or event_id=5143
select peek(message,re("Share Path:\\t\\t(.*)"),1) as sharePath
group every 5m by subject_username, machine_ip, security_id, share_name, sharePath, event_id ,subject_domain, target_domain, target_username, member_security_id, process_name, machine, source_ip, destination_ipv4, source_hostname, device, client
//Entity Mapping Section
select machine as entity_sourceHostname
select subject_username as entity_sourceAccount
select str(machine_ip) as entity_sourceIP
select subject_domain as entity_sourceDomain
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceDomain) as entity_sourceDomain_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole
//<filtering_section>
//Enrichment Mapping
select asn(ip4(entity_sourceIP)) as enrichStream_entity_sourceIP_ASN
select isp(ip4(entity_sourceIP)) as enrichStream_entity_sourceIP_ISP
select countrycode(ip4(entity_sourceIP)) as enrichStream_entity_sourceIP_country
select ifthenelse(toktains(lu("mispIndicator", "eventtags_name_str", str(entity_sourceIP)),"TOR"), true, false) as enrichStream_entity_sourceIP_isAnonymousProxy
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
//Get Enrichment from SecOps
select lu("mispIndicator", "category", entity_sourceIP) as indicator
select lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type
select lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsWinNetworkShareCreated") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsWinNetworkShareCreated") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsWinNetworkShareCreated") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsWinNetworkShareCreated") as alertPriority
```

## SecOpsWinNewPsDrive

**Summary:** Detects a command mounting a new PS-drive.

**Description:** Detected a command that may be trying to mount new persistent drive on $srcHost with ip $machineIp by user $subjectUsername. This activity should be reviewed to determine that this execution is not malicious. execution: $procCmdLine

**MITRE:** Tactics: Command and Control (TA0011), Exfiltration (TA0010) | Techniques: Ingress Tool Transfer (T1105), Exfiltration Over Alternative Protocol (T1048)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.all.win
where eq(event_id,4688) or eq(event_id,4104) or eq(event_id,4103)
where weaktoktains(rawMessage,"New-PSDrive",true,true) and weaktoktains(process_command_line,"-PSProvider",true,true) and weaktoktains(process_command_line,"filesystem",true,true)
group every 5m by machine_ip,subject_username,source_hostname,process_command_line, device, client
//Entity Mapping Section
select source_hostname as entity_sourceHostname
select subject_username as entity_sourceAccount
select machine_ip as entity_sourceIP
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole
//<filtering_section>
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsWinNewPsDrive") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsWinNewPsDrive") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsWinNewPsDrive") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsWinNewPsDrive") as alertPriority
```

## SecOpsWinOfficeBrowserLaunchingShell

**Summary:** Detects a shell launched by an Office product or browser that should not be spawning shell processes. Attackers may inject code into Office documents or abuse Windows utilities to spawn shells that will execute malicious commands.

**MITRE:** Tactics: Execution (TA0002) | Techniques: Command and Scripting Interpreter (T1059)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.all.win
where event_id = 4688 and `or`(weaktoktains(new_process_name, "powershell.exe"), weaktoktains(new_process_name, "cmd.exe"))
where `or`(
weaktoktains(parent_process_name, "winword.exe"), weaktoktains(parent_process_name, "EXCEL.EXE"), weaktoktains(parent_process_name, "OUTLOOK.EXE")
, weaktoktains(parent_process_name, "POWERPNT.EXE"), weaktoktains(parent_process_name, "visio.exe"), weaktoktains(parent_process_name, "mspub.exe")
, weaktoktains(parent_process_name, "chrome.exe"), weaktoktains(parent_process_name, "iexplore.exe"), weaktoktains(parent_process_name, "opera.exe")
)
group every 5m by subject_security_id, subject_username, subject_logon_id, subject_domain, machine, machine_ip, device, client
, target_security_id, target_username, target_logon_id, target_domain, parent_process_name
, new_pid, new_process_name, token_elevation_type, mandatory_label, process_command_line
//Entity Mapping Section
select str(machine_ip) as entity_sourceIP
select machine as entity_sourceHostname
select subject_username as entity_sourceAccount
select subject_domain as entity_sourceDomain
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceDomain) as entity_sourceDomain_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole
//<filtering_section>
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsWinOfficeBrowserLaunchingShell") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsWinOfficeBrowserLaunchingShell") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsWinOfficeBrowserLaunchingShell") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsWinOfficeBrowserLaunchingShell") as alertPriority
```

## SecOpsWinPermissionGroupDiscovery

**Summary:** Detects when a user attempts to gather information about local and domain groups as well as permission settings.

**MITRE:** Tactics: Discovery (TA0007) | Techniques: Permission Groups Discovery (T1069)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.all.win
where event_id = 4688
where (weaktoktains(new_process_name, "net.exe") or weaktoktains(new_process_name, "net1.exe"))
and (weaktoktains(process_command_line, "group") or (weaktoktains(process_command_line, "localgroup") or (weaktoktains(process_command_line, "accounts") or (weaktoktains(process_command_line, "use") or (weaktoktains(process_command_line, "stop") or (weaktoktains(process_command_line, "administrators")))))))
or (weaktoktains(process_command_line, "domain") and (weaktoktains(process_command_line, "computers")))
or (weaktoktains(process_command_line, "domain") and (weaktoktains(process_command_line, "admins")))
and subject_username /= "null"
group every 5m by subject_security_id, subject_username, subject_domain, subject_logon_id, new_pid, new_process_name, token_elevation_type, device, client
, pid, process_command_line, target_security_id, target_username, target_domain, target_logon_id, parent_process_name, mandatory_label
, machine, machine_ip
every 5m
//Entity Mapping Section
select machine as entity_sourceHostname
select subject_username as entity_sourceAccount
select str(machine_ip) as entity_machineIp
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_machineIp) as entity_machineIp_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole
//<filtering_section>
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsWinPermissionGroupDiscovery") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsWinPermissionGroupDiscovery") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsWinPermissionGroupDiscovery") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsWinPermissionGroupDiscovery") as alertPriority
```

## SecOpsWinPotentialPassTheHash

**Summary:** Adversaries may pass the hash using stolen password hashes to move laterally within an environment, bypassing normal system access controls.

**MITRE:** Tactics: Lateral Movement (TA0008) | Techniques: Use Alternate Authentication Material (T1550)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.all.win
where event_id = 4624
select nvl(str(jqeval(jqcompile(".columns.data.EventData.SubjectUserSid"), jsonparse(rawMessage))),str(jqeval(jqcompile(".SubjectUserSid"), jsonparse(rawMessage)))) as SubjectUser_Sid
select str(machine_ip) as entity_sourceIP
select account as entity_sourceAccount
select machine as entity_sourceHostname
select logon_type
select nvl(str(jqeval(jqcompile(".columns.data.EventData.KeyLength"), jsonparse(rawMessage))),str(jqeval(jqcompile(".KeyLength"), jsonparse(rawMessage)))) as KeyLength
select nvl(str(jqeval(jqcompile(".columns.data.EventData.LogonProcessName"), jsonparse(rawMessage))),str(jqeval(jqcompile(".LogonProcessName"), jsonparse(rawMessage)))) as LogonProcessName
select nvl(str(jqeval(jqcompile(".columns.data.EventData.TargetUserName"), jsonparse(rawMessage))),str(jqeval(jqcompile(".TargetUserName"), jsonparse(rawMessage)))) as TargetUserName
where not eq(TargetUserName,"ANONYMOUS LOGON") and ((eq(SubjectUser_Sid, "S-1-0-0") and eq(logon_type, "3") and eq(LogonProcessName, "NtLmSsp") and eq(KeyLength, "0")) or (eq(logon_type, "9") and eq(LogonProcessName, "seclogo")))
group every 5m by tag, event_id, SubjectUser_Sid, entity_sourceIP, entity_sourceAccount, entity_sourceHostname, KeyLength, logon_type, LogonProcessName, TargetUserName, device, client
every 5m
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsWinPotentialPassTheHash") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsWinPotentialPassTheHash") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsWinPotentialPassTheHash") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsWinPotentialPassTheHash") as alertPriority
```

## SecOpsWinPowerSettings

**Summary:** Detects unexpected changes to configuration files associated with the power settings of a system.

**MITRE:** Tactics: Persistence (TA0003) | Techniques: Power Settings (T1653)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.all.win
where (event_id = 4656 or event_id = 4660 or event_id =4663 or event_id =4670)
and (has(process_command_line,"powercfg") or has(file_path,"powercfg"))
group every 5m by machine, machine_ip, subject_username, subject_domain, device, client
//Entity Mapping Section
select machine as entity_sourceHostname
select subject_username as entity_sourceAccount
select str(machine_ip) as entity_sourceIP
select subject_domain as entity_sourceDomain
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceDomain) as entity_sourceDomain_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole
//<filtering_section>
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsWinPowerSettings") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsWinPowerSettings") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsWinPowerSettings") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsWinPowerSettings") as alertPriority
```

## SecOpsWinPowershellKeyloggin

**Summary:** Detects execution of a Powershell script that could be trying to log user keystrokes on the target machine.

**Description:** Detected execution of a Powershell script that could be trying to log keystrokes on $srcHost with ip $machineIp. Execution: $procCmdLine

**MITRE:** Tactics: Collection (TA0009) | Techniques: Input Capture (T1056)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.all.win
where eq(event_id,4104)
where `or`(toktains(process_command_line,"Get-Keystrokes",true,true), toktains(process_command_line,"Get-ProcAddress user32.dll GetAsyncKeyState",true,true) and toktains(process_command_line,"Get-ProcAddress user32.dll GetForegroundWindow",true,true))
group every 5m by machine_ip,source_hostname, process_command_line, device, client
//Entity Mapping Section
select source_hostname as entity_sourceHostname
select machine_ip as entity_sourceIP
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole
//<filtering_section>
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsWinPowershellKeyloggin") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsWinPowershellKeyloggin") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsWinPowershellKeyloggin") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsWinPowershellKeyloggin") as alertPriority
```

## SecOpsWinPowershellProcessDiscovery

**Summary:** Detects the use of various Get-Process PowerShell commands to discover information about running processes.

**MITRE:** Tactics: Discovery (TA0007) | Techniques: Process Discovery (T1057)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.all.win
where event_id = 4688
where (weaktoktains(process_name, "powershell.exe") or weaktoktains(new_process_name, "powershell.exe"))
and weaktoktains(process_command_line, "get-process")
group every 5m by subject_security_id, subject_username, subject_logon_id, subject_domain, machine, device, client
, target_security_id, target_username, target_logon_id, target_domain, token_elevation_type, mandatory_label
, new_pid, new_process_name, parent_process_name, process_command_line, machine_ip
//Entity Mapping Section
select machine as entity_sourceHostname
select subject_username as entity_sourceAccount
select str(machine_ip) as entity_sourceIp
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceIp) as entity_sourceIp_AssetRole
//<filtering_section>
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsWinPowershellProcessDiscovery") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsWinPowershellProcessDiscovery") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsWinPowershellProcessDiscovery") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsWinPowershellProcessDiscovery") as alertPriority
```

## SecOpsWinPowershellSetExecutionPolicyBypass

**Summary:** Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries.

**MITRE:** Tactics: Execution (TA0002) | Techniques: Command and Scripting Interpreter (T1059)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.all.win
where ((event_id = 1 and channel ="Microsoft-Windows-Sysmon/Operational") or event_id = 4688) and ( weakhas(process_command_line, "Set-ExecutionPolicy") and weakhas(process_command_line, "Bypass"))
select source_hostname as entity_sourceHostname
select str(machine_ip) as entity_sourceIP
group every 5m by source_name, entity_sourceIP, entity_sourceHostname, process_command_line, device, client
every 5m
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsWinPowershellSetExecutionPolicyBypass") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsWinPowershellSetExecutionPolicyBypass") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsWinPowershellSetExecutionPolicyBypass") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsWinPowershellSetExecutionPolicyBypass") as alertPriority
```

## SecOpsWinRcloneExecution

**Summary:** Detects exfiltration using Rclone utility.

**Description:** Detected a possible data exfiltration using Rclone utility on $srcHost with ip $machineIp by user $subjectUsername. This activity should be reviewed to determine that this execution is not malicious. execution: $procCmdLine

**MITRE:** Tactics: Exfiltration (TA0010) | Techniques: Exfiltration Over Alternative Protocol (T1048)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.all.win
where eq(event_id,4688)
where weaktoktains(new_process_name,"rclone",true,true)
where `or`(weaktoktains(process_command_line," pass ",true,true),weaktoktains(process_command_line," user ",true,true),weaktoktains(process_command_line," copy ",true,true),weaktoktains(process_command_line," mega ",true,true),weaktoktains(process_command_line," sync ",true,true),weaktoktains(process_command_line," config ",true,true),weaktoktains(process_command_line," lsd ",true,true),weaktoktains(process_command_line," remote ",true,true),weaktoktains(process_command_line," ls ",true,true))
group every 5m by machine_ip,subject_username,source_hostname,process_command_line, device, client
//Entity Mapping Section
select source_hostname as entity_sourceHostname
select subject_username as entity_sourceAccount
select machine_ip as entity_sourceIP
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole
//<filtering_section>
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsWinRcloneExecution") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsWinRcloneExecution") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsWinRcloneExecution") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsWinRcloneExecution") as alertPriority
```

## SecOpsWinRegistryModificationActivateNoRunGroupPolicy

**Summary:** Adversaries may interact with the Windows Registry to hide configuration information within Registry keys, remove information as part of cleaning up, or as part of other techniques to aid in persistence and execution.

**MITRE:** Tactics: Defense Evasion (TA0005) | Techniques: Modify Registry (T1112)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.all.win
where ((event_id = 1 and channel ="Microsoft-Windows-Sysmon/Operational") or event_id = 4688) and ((weakhas(process_command_line, "reg") and weakhas(process_command_line, "add")) or weakhas(process_command_line, "New-ItemProperty")) and (weakhas(process_command_line,  "NoRun"))
select source_hostname as entity_sourceHostname
select str(machine_ip) as entity_sourceIP
group every 5m by source_name, entity_sourceIP, entity_sourceHostname, process_command_line, device, client
every 5m
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsWinRegistryModificationActivateNoRunGroupPolicy") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsWinRegistryModificationActivateNoRunGroupPolicy") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsWinRegistryModificationActivateNoRunGroupPolicy") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsWinRegistryModificationActivateNoRunGroupPolicy") as alertPriority
```

## SecOpsWinRegistryModificationDisableChangePasswdFeature

**Summary:** Adversaries may interact with the Windows Registry to hide configuration information within Registry keys, remove information as part of cleaning up, or as part of other techniques to aid in persistence and execution.

**MITRE:** Tactics: Defense Evasion (TA0005) | Techniques: Modify Registry (T1112)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.all.win
where ((event_id = 1 and channel ="Microsoft-Windows-Sysmon/Operational") or event_id = 4688) and ((weakhas(process_command_line, "reg") and weakhas(process_command_line, "add")) or weakhas(process_command_line, "New-ItemProperty")) and (weakhas(process_command_line,  "DisableChangePassword"))
select source_hostname as entity_sourceHostname
select source_ip as entity_sourceIP
group every 5m by source_ip, source_name, entity_sourceIP, entity_sourceHostname, process_command_line, device, client
every 5m
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsWinRegistryModificationDisableChangePasswdFeature") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsWinRegistryModificationDisableChangePasswdFeature") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsWinRegistryModificationDisableChangePasswdFeature") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsWinRegistryModificationDisableChangePasswdFeature") as alertPriority
```

## SecOpsWinRegistryModificationDisableCMDApp

**Summary:** Adversaries may interact with the Windows Registry to hide configuration information within Registry keys, remove information as part of cleaning up, or as part of other techniques to aid in persistence and execution.

**MITRE:** Tactics: Defense Evasion (TA0005) | Techniques: Modify Registry (T1112)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.all.win
where ((event_id = 1 and channel ="Microsoft-Windows-Sysmon/Operational") or event_id = 4688) and ((weakhas(process_command_line, "reg") and weakhas(process_command_line, "add")) or weakhas(process_command_line, "New-ItemProperty")) and weakhas(process_command_line,  "DisableCMD")
select source_hostname as entity_sourceHostname
select str(machine_ip) as entity_sourceIP
group every 5m by source_name, entity_sourceIP, entity_sourceHostname, process_command_line, device, client
every 5m
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsWinRegistryModificationDisableCMDApp") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsWinRegistryModificationDisableCMDApp") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsWinRegistryModificationDisableCMDApp") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsWinRegistryModificationDisableCMDApp") as alertPriority
```

## SecOpsWinRegistryModificationDisableLockWSFeature

**Summary:** Adversaries may interact with the Windows Registry to hide configuration information within Registry keys, remove information as part of cleaning up, or as part of other techniques to aid in persistence and execution.

**MITRE:** Tactics: Defense Evasion (TA0005) | Techniques: Modify Registry (T1112)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.all.win
where ((event_id = 1 and channel ="Microsoft-Windows-Sysmon/Operational") or event_id = 4688) and ((weakhas(process_command_line, "reg") and weakhas(process_command_line, "add")) or weakhas(process_command_line, "New-ItemProperty")) and (weakhas(process_command_line,  "DisableLockWorkstation"))
select source_hostname as entity_sourceHostname
select str(machine_ip) as entity_sourceIP
group every 5m by source_name, entity_sourceIP, entity_sourceHostname, process_command_line, device, client
every 5m
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsWinRegistryModificationDisableLockWSFeature") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsWinRegistryModificationDisableLockWSFeature") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsWinRegistryModificationDisableLockWSFeature") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsWinRegistryModificationDisableLockWSFeature") as alertPriority
```

## SecOpsWinRegistryModificationDisableLogOffButton

**Summary:** Adversaries may interact with the Windows Registry to hide configuration information within Registry keys, remove information as part of cleaning up, or as part of other techniques to aid in persistence and execution.

**MITRE:** Tactics: Defense Evasion (TA0005) | Techniques: Modify Registry (T1112)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.all.win
where ((event_id = 1 and channel ="Microsoft-Windows-Sysmon/Operational") or event_id = 4688) and ((weakhas(process_command_line, "reg") and weakhas(process_command_line, "add")) or weakhas(process_command_line, "New-ItemProperty")) and (weakhas(process_command_line,  "NoLogOff") or weakhas(process_command_line,  "StartMenuLogOff"))
select source_hostname as entity_sourceHostname
select str(machine_ip) as entity_sourceIP
group every 5m by source_name, entity_sourceIP, entity_sourceHostname, process_command_line, device, client
every 5m
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsWinRegistryModificationDisableLogOffButton") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsWinRegistryModificationDisableLogOffButton") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsWinRegistryModificationDisableLogOffButton") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsWinRegistryModificationDisableLogOffButton") as alertPriority
```

## SecOpsWinRegistryModificationDisableNotificationCenter

**Summary:** Adversaries may interact with the Windows Registry to hide configuration information within Registry keys, remove information as part of cleaning up, or as part of other techniques to aid in persistence and execution.

**MITRE:** Tactics: Defense Evasion (TA0005) | Techniques: Modify Registry (T1112)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.all.win
where ((event_id = 1 and channel ="Microsoft-Windows-Sysmon/Operational") or event_id = 4688) and ((weakhas(process_command_line, "reg") and weakhas(process_command_line, "add")) or weakhas(process_command_line, "New-ItemProperty")) and weakhas(process_command_line,  "DisableNotificationCenter")
select source_hostname as entity_sourceHostname
select str(machine_ip) as entity_sourceIP
group every 5m by source_name, entity_sourceIP, entity_sourceHostname, process_command_line, device, client
every 5m
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsWinRegistryModificationDisableNotificationCenter") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsWinRegistryModificationDisableNotificationCenter") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsWinRegistryModificationDisableNotificationCenter") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsWinRegistryModificationDisableNotificationCenter") as alertPriority
```

## SecOpsWinRegistryModificationDisableRegistryTool

**Summary:** Adversaries may interact with the Windows Registry to hide configuration information within Registry keys, remove information as part of cleaning up, or as part of other techniques to aid in persistence and execution.

**MITRE:** Tactics: Defense Evasion (TA0005) | Techniques: Modify Registry (T1112)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.all.win
where ((event_id = 1 and channel ="Microsoft-Windows-Sysmon/Operational") or event_id = 4688) and ( weakhas(process_command_line, "reg") and weakhas(process_command_line, "add") and weakhas(process_command_line, "Software\\Microsoft\\Windows\\CurrentVersion\\policies\\system") and weakhas(process_command_line,  "DisableRegistryTools"))
select source_hostname as entity_sourceHostname
select machine_ip as entity_sourceIP
group every 5m by source_name, entity_sourceIP, entity_sourceHostname, process_command_line, device, client
every 5m
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsWinRegistryModificationDisableRegistryTool") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsWinRegistryModificationDisableRegistryTool") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsWinRegistryModificationDisableRegistryTool") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsWinRegistryModificationDisableRegistryTool") as alertPriority
```

## SecOpsWinRegistryModificationDisableShutdownButton

**Summary:** Adversaries may interact with the Windows Registry to hide configuration information within Registry keys, remove information as part of cleaning up, or as part of other techniques to aid in persistence and execution.

**MITRE:** Tactics: Defense Evasion (TA0005) | Techniques: Modify Registry (T1112)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.all.win
where ((event_id = 1 and channel ="Microsoft-Windows-Sysmon/Operational") or event_id = 4688) and ((weakhas(process_command_line, "reg") and weakhas(process_command_line, "add")) or weakhas(process_command_line, "New-ItemProperty")) and (weakhas(process_command_line,  "shutdownwithoutlogon") and (weakhas(process_command_line,  "/d 0") or weakhas(process_command_line,  "-Value 0") ))
select source_hostname as entity_sourceHostname
select str(machine_ip) as entity_sourceIP
group every 5m by source_name, entity_sourceIP, entity_sourceHostname, process_command_line, device, client
every 5m
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsWinRegistryModificationDisableShutdownButton") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsWinRegistryModificationDisableShutdownButton") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsWinRegistryModificationDisableShutdownButton") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsWinRegistryModificationDisableShutdownButton") as alertPriority
```

## SecOpsWinRegistryModificationDisableTaskmgr

**Summary:** Adversaries may interact with the Windows Registry to hide configuration information within Registry keys, remove information as part of cleaning up, or as part of other techniques to aid in persistence and execution.

**MITRE:** Tactics: Defense Evasion (TA0005) | Techniques: Modify Registry (T1112)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.all.win
where ((event_id = 1 and channel ="Microsoft-Windows-Sysmon/Operational") or event_id = 4688) and ((weakhas(process_command_line, "reg") and weakhas(process_command_line, "add")) or weakhas(process_command_line, "New-ItemProperty")) and weakhas(process_command_line,  "DisableTaskmgr")
select source_hostname as entity_sourceHostname
select str(machine_ip) as entity_sourceIP
group every 5m by source_name, entity_sourceIP, entity_sourceHostname, process_command_line, device, client
every 5m
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsWinRegistryModificationDisableTaskmgr") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsWinRegistryModificationDisableTaskmgr") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsWinRegistryModificationDisableTaskmgr") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsWinRegistryModificationDisableTaskmgr") as alertPriority
```

## SecOpsWinRegistryModificationGlobalFolderOptions

**Summary:** An adversary may attempt to change the global folder options to hide his actions.

**MITRE:** Tactics: Defense Evasion (TA0005) | Techniques: Hide Artifacts (T1564)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.all.win
where ((event_id = 1 and channel ="Microsoft-Windows-Sysmon/Operational") or event_id = 4688) and ( weakhas(process_command_line, "reg") and weakhas(process_command_line, "add") and weakhas(process_command_line,  "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced") )
select source_hostname as entity_sourceHostname
select str(machine_ip) as entity_sourceIP
group every 5m by source_name, entity_sourceIP, entity_sourceHostname, process_command_line, device, client
every 5m
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsWinRegistryModificationGlobalFolderOptions") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsWinRegistryModificationGlobalFolderOptions") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsWinRegistryModificationGlobalFolderOptions") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsWinRegistryModificationGlobalFolderOptions") as alertPriority
```

## SecOpsWinRegistryModificationHideClockGroupPolicyFeature

**Summary:** Adversaries may interact with the Windows Registry to hide configuration information within Registry keys, remove information as part of cleaning up, or as part of other techniques to aid in persistence and execution.

**MITRE:** Tactics: Defense Evasion (TA0005) | Techniques: Modify Registry (T1112)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.all.win
where ((event_id = 1 and channel ="Microsoft-Windows-Sysmon/Operational") or event_id = 4688) and ((weakhas(process_command_line, "reg") and weakhas(process_command_line, "add")) or weakhas(process_command_line, "New-ItemProperty")) and (weakhas(process_command_line,  "HideClock"))
select source_hostname as entity_sourceHostname
select str(machine_ip) as entity_sourceIP
group every 5m by source_name, entity_sourceIP, entity_sourceHostname, process_command_line, device, client
every 5m
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsWinRegistryModificationHideClockGroupPolicyFeature") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsWinRegistryModificationHideClockGroupPolicyFeature") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsWinRegistryModificationHideClockGroupPolicyFeature") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsWinRegistryModificationHideClockGroupPolicyFeature") as alertPriority
```

## SecOpsWinRegistryModificationHideSCAHealth

**Summary:** Adversaries may interact with the Windows Registry to hide configuration information within Registry keys, remove information as part of cleaning up, or as part of other techniques to aid in persistence and execution.

**MITRE:** Tactics: Defense Evasion (TA0005) | Techniques: Modify Registry (T1112)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.all.win
where ((event_id = 1 and channel ="Microsoft-Windows-Sysmon/Operational") or event_id = 4688) and ((weakhas(process_command_line, "reg") and weakhas(process_command_line, "add")) or weakhas(process_command_line, "New-ItemProperty")) and (weakhas(process_command_line,  "HideSCAHealth"))
select source_hostname as entity_sourceHostname
select str(machine_ip) as entity_sourceIP
group every 5m by source_name, entity_sourceIP, entity_sourceHostname, process_command_line, device, client
every 5m
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsWinRegistryModificationHideSCAHealth") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsWinRegistryModificationHideSCAHealth") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsWinRegistryModificationHideSCAHealth") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsWinRegistryModificationHideSCAHealth") as alertPriority
```

## SecOpsWinRegistryModificationHideSCANetwork

**Summary:** Adversaries may interact with the Windows Registry to hide configuration information within Registry keys, remove information as part of cleaning up, or as part of other techniques to aid in persistence and execution.

**MITRE:** Tactics: Defense Evasion (TA0005) | Techniques: Modify Registry (T1112)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.all.win
where ((event_id = 1 and channel ="Microsoft-Windows-Sysmon/Operational") or event_id = 4688) and ((weakhas(process_command_line, "reg") and weakhas(process_command_line, "add")) or weakhas(process_command_line, "New-ItemProperty")) and (weakhas(process_command_line,  "HideSCANetwork"))
select source_hostname as entity_sourceHostname
select str(machine_ip) as entity_sourceIP
group every 5m by source_name, entity_sourceIP, entity_sourceHostname, process_command_line, device, client
every 5m
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsWinRegistryModificationHideSCANetwork") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsWinRegistryModificationHideSCANetwork") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsWinRegistryModificationHideSCANetwork") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsWinRegistryModificationHideSCANetwork") as alertPriority
```

## SecOpsWinRegistryModificationHideSCAPower

**Summary:** Adversaries may interact with the Windows Registry to hide configuration information within Registry keys, remove information as part of cleaning up, or as part of other techniques to aid in persistence and execution.

**MITRE:** Tactics: Defense Evasion (TA0005) | Techniques: Modify Registry (T1112)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.all.win
where ((event_id = 1 and channel ="Microsoft-Windows-Sysmon/Operational") or event_id = 4688) and ((weakhas(process_command_line, "reg") and weakhas(process_command_line, "add")) or weakhas(process_command_line, "New-ItemProperty")) and (weakhas(process_command_line,  "HideSCAPower"))
select source_hostname as entity_sourceHostname
select str(machine_ip) as entity_sourceIP
group every 5m by source_name, entity_sourceIP, entity_sourceHostname, process_command_line, device, client
every 5m
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsWinRegistryModificationHideSCAPower") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsWinRegistryModificationHideSCAPower") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsWinRegistryModificationHideSCAPower") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsWinRegistryModificationHideSCAPower") as alertPriority
```

## SecOpsWinRegistryModificationHideSCAVolume

**Summary:** Adversaries may interact with the Windows Registry to hide configuration information within Registry keys, remove information as part of cleaning up, or as part of other techniques to aid in persistence and execution.

**MITRE:** Tactics: Defense Evasion (TA0005) | Techniques: Modify Registry (T1112)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.all.win
where ((event_id = 1 and channel ="Microsoft-Windows-Sysmon/Operational") or event_id = 4688) and ((weakhas(process_command_line, "reg") and weakhas(process_command_line, "add")) or weakhas(process_command_line, "New-ItemProperty")) and (weakhas(process_command_line,  "HideSCAVolume"))
select source_hostname as entity_sourceHostname
select str(machine_ip) as entity_sourceIP
group every 5m by source_name, entity_sourceIP, entity_sourceHostname, process_command_line, device, client
every 5m
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsWinRegistryModificationHideSCAVolume") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsWinRegistryModificationHideSCAVolume") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsWinRegistryModificationHideSCAVolume") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsWinRegistryModificationHideSCAVolume") as alertPriority
```

## SecOpsWinRegistryModificationIExplorerSecZone

**Summary:** Adversaries may interact with the Windows Registry to hide configuration information within Registry keys, remove information as part of cleaning up, or as part of other techniques to aid in persistence and execution.

**MITRE:** Tactics: Defense Evasion (TA0005) | Techniques: Modify Registry (T1112)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.all.win
where ((event_id = 1 and channel ="Microsoft-Windows-Sysmon/Operational") or event_id = 4688) and ( weakhas(process_command_line, "reg") and weakhas(process_command_line,  "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings"))
select source_hostname as entity_sourceHostname
select str(machine_ip) as entity_sourceIP
group every 5m by source_name, entity_sourceIP, entity_sourceHostname, process_command_line, device, client
every 5m
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsWinRegistryModificationIExplorerSecZone") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsWinRegistryModificationIExplorerSecZone") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsWinRegistryModificationIExplorerSecZone") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsWinRegistryModificationIExplorerSecZone") as alertPriority
```

## SecOpsWinRegistryModificationNewTrustedSite

**Summary:** Adversaries may add new domain trusts or modify the properties of existing domain trusts to evade defenses.

**MITRE:** Tactics: Defense Evasion (TA0005) | Techniques: Domain Policy Modification (T1484)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.all.win
where ((event_id = 1 and channel ="Microsoft-Windows-Sysmon/Operational") or event_id = 4688) and ( (weakhas(process_command_line, "reg") and weakhas(process_command_line, "add")) or weakhas(process_command_line, "new-itemproperty")) and weakhas(process_command_line,  "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\ZoneMap") and weakhas(process_command_line, "Domains")
group every 5m by source_ip, source_hostname, source_name, process_command_line, device, client
every 5m
select source_hostname as entity_sourceHostname
select source_ip as entity_sourceIP
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsWinRegistryModificationNewTrustedSite") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsWinRegistryModificationNewTrustedSite") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsWinRegistryModificationNewTrustedSite") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsWinRegistryModificationNewTrustedSite") as alertPriority
```

## SecOpsWinRegistryModificationNoDesktopGroupPolicy

**Summary:** Adversaries may interact with the Windows Registry to hide configuration information within Registry keys, remove information as part of cleaning up, or as part of other techniques to aid in persistence and execution.

**MITRE:** Tactics: Defense Evasion (TA0005) | Techniques: Modify Registry (T1112)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.all.win
where ((event_id = 1 and channel ="Microsoft-Windows-Sysmon/Operational") or event_id = 4688) and ((weakhas(process_command_line, "reg") and weakhas(process_command_line, "add")) or weakhas(process_command_line, "New-ItemProperty")) and (weakhas(process_command_line,  "NoDesktop"))
select source_hostname as entity_sourceHostname
select str(machine_ip) as entity_sourceIP
group every 5m by source_name, entity_sourceIP, entity_sourceHostname, process_command_line, device, client
every 5m
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsWinRegistryModificationNoDesktopGroupPolicy") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsWinRegistryModificationNoDesktopGroupPolicy") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsWinRegistryModificationNoDesktopGroupPolicy") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsWinRegistryModificationNoDesktopGroupPolicy") as alertPriority
```

## SecOpsWinRegistryModificationNoFindGroupPolicyFeature

**Summary:** Adversaries may interact with the Windows Registry to hide configuration information within Registry keys, remove information as part of cleaning up, or as part of other techniques to aid in persistence and execution.

**MITRE:** Tactics: Defense Evasion (TA0005) | Techniques: Modify Registry (T1112)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.all.win
where ((event_id = 1 and channel ="Microsoft-Windows-Sysmon/Operational") or event_id = 4688) and ((weakhas(process_command_line, "reg") and weakhas(process_command_line, "add")) or weakhas(process_command_line, "New-ItemProperty")) and (weakhas(process_command_line,  "NoFind"))
select source_hostname as entity_sourceHostname
select str(machine_ip) as entity_sourceIP
group every 5m by source_name, entity_sourceIP, entity_sourceHostname, process_command_line, device, client
every 5m
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsWinRegistryModificationNoFindGroupPolicyFeature") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsWinRegistryModificationNoFindGroupPolicyFeature") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsWinRegistryModificationNoFindGroupPolicyFeature") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsWinRegistryModificationNoFindGroupPolicyFeature") as alertPriority
```

## SecOpsWinRegistryModificationPowershellLoggingDisabled

**Summary:** Adversaries may interact with the Windows Registry to hide configuration information within Registry keys, remove information as part of cleaning up, or as part of other techniques to aid in persistence and execution.

**MITRE:** Tactics: Defense Evasion (TA0005) | Techniques: Modify Registry (T1112)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.all.win
where ((event_id = 1 and channel ="Microsoft-Windows-Sysmon/Operational") or event_id = 4688) and ((weakhas(process_command_line, "reg") and weakhas(process_command_line, "add")) or weakhas(process_command_line, "New-ItemProperty")) and (weakhas(process_command_line,  "EnableModuleLogging") or weakhas(process_command_line,  "EnableScriptBlockLogging") or weakhas(process_command_line,  "EnableTranscripting") or weakhas(process_command_line,  "EnableScripts")) and (weakhas(process_command_line,  "/d 0") or weakhas(process_command_line,  "-Value 0") )
select source_hostname as entity_sourceHostname
select str(machine_ip) as entity_sourceIP
group every 5m by source_name, entity_sourceIP, entity_sourceHostname, process_command_line, device, client
every 5m
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsWinRegistryModificationPowershellLoggingDisabled") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsWinRegistryModificationPowershellLoggingDisabled") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsWinRegistryModificationPowershellLoggingDisabled") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsWinRegistryModificationPowershellLoggingDisabled") as alertPriority
```

## SecOpsWinRegistryModificationRunKeyAdded

**Summary:** Adversaries may achieve persistence by adding a program to a startup folder or referencing it with a Registry run key.

**MITRE:** Tactics: Persistence (TA0003) | Techniques: Boot or Logon Autostart Execution (T1547)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.all.win
where ((event_id = 1 and channel ="Microsoft-Windows-Sysmon/Operational") or event_id = 4688) and (weakhas(process_command_line, "reg") and weakhas(process_command_line, "add") and weakhas(process_command_line, "Software\\Microsoft\\Windows\\CurrentVersion\\Run"))
select source_hostname as entity_sourceHostname
select str(machine_ip) as entity_sourceIP
group every 5m by source_name, entity_sourceIP, entity_sourceHostname, process_command_line, device, client
every 5m
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsWinRegistryModificationRunKeyAdded") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsWinRegistryModificationRunKeyAdded") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsWinRegistryModificationRunKeyAdded") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsWinRegistryModificationRunKeyAdded") as alertPriority
```

## SecOpsWinRegistryModificationStoreLogonCred

**Summary:** An attacker may modify the Windows registry to force the WDigest to store credentials in plaintext the next time someone logs on to the target system.

**MITRE:** Tactics: Credential Access (TA0006) | Techniques: Credentials from Password Stores (T1555)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.all.win
where ((event_id = 1 and channel ="Microsoft-Windows-Sysmon/Operational") or event_id = 4688) and (weakhas(process_command_line, "reg") and weakhas(process_command_line, "add") and weakhas(process_command_line, "SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest /v UseLogonCredential /t REG_DWORD /d 1"))
select source_hostname as entity_sourceHostname
select str(machine_ip) as entity_sourceIP
group every 5m by source_name, entity_sourceIP, entity_sourceHostname, process_command_line, device, client
every 5m
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsWinRegistryModificationStoreLogonCred") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsWinRegistryModificationStoreLogonCred") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsWinRegistryModificationStoreLogonCred") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsWinRegistryModificationStoreLogonCred") as alertPriority
```

## SecOpsWinRegistryQuery

**Summary:** Identifies queries to the registry. Adversaries often query the registry to gather information about the system, its configuration, and installed software.

**MITRE:** Tactics: Discovery (TA0007) | Techniques: Query Registry (T1012)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.all.win
where toktains(raw,"reg.exe"), (toktains(raw,"SYSTEM") or toktains(raw,"SOFTWARE"))
where event_id = 4656
where isnotnull(process_name)
group every 5m by machine, machine_ip, subject_security_id, subject_username, subject_domain, subject_logon_id, object_server, object_type, object_name, object_handle, process_name, pid, accesses, access_mask, device, client
//Entity Mapping Section
select machine as entity_sourceHostname
select subject_username as entity_sourceAccount
select str(machine_ip) as entity_sourceIP
select subject_domain as entity_sourceDomain
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceDomain) as entity_sourceDomain_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole
//<filtering_section>
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsWinRegistryQuery") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsWinRegistryQuery") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsWinRegistryQuery") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsWinRegistryQuery") as alertPriority
```

## SecOpsWinRegUtilityHiveExport

**Summary:** Detects the use of reg.exe to access Windows Registry SAM, system, or security hives containing credentials. Adversaries may use this technique to export registry hives for offline credential access attacks.

**MITRE:** Tactics: Credential Access (TA0006) | Techniques: OS Credential Dumping (T1003)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.all.win
where weaktoktains(raw, "reg.exe")
where (
event_id=4688
and `or`(weaktoktains(process_command_line, "system"), weaktoktains(process_command_line, "sam"), weaktoktains(process_command_line, "security"))
and `or`(weaktoktains(process_command_line, "save"), weaktoktains(process_command_line, "export"))
) or (
event_id=4656
and weaktoktains(raw, "reg.exe")
and `or`(weaktoktains(raw, "system"), weaktoktains(raw, "sam"), weaktoktains(raw, "security"))
)
select ifthenelse(event_id=4688, new_process_name, process_name) as pName
// May wish to filter on accesses and accessMask to restrict alerting on only specific type of accesses for keys.
group every 5m by event_id, machine, machine_ip, device, client
, subject_username, subject_domain, subject_logon_id
, pName, parent_process_name, process_command_line
, object_server, object_type, object_name, object_handle, object_resource_attribute
, accesses, access_mask
select machine as entity_sourceHostname
select subject_username as entity_sourceAccount
select str(machine_ip) as entity_sourceIP
select subject_domain as entity_sourceDomain
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceDomain) as entity_sourceDomain_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole
//<filtering_section>
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsWinRegUtilityHiveExport") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsWinRegUtilityHiveExport") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsWinRegUtilityHiveExport") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsWinRegUtilityHiveExport") as alertPriority
```

## SecOpsWinRemoteSystemDiscovery

**Summary:** Detects the use of nbtstat.exe or arp.exe that may be used to attempt to get a listing of other systems by IP address, hostname, or other logical identifier on a network that may be used for Lateral Movement from the current system.

**MITRE:** Tactics: Discovery (TA0007) | Techniques: Remote System Discovery (T1018)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.all.win
where event_id = 4688
where (weaktoktains(process_command_line, "nbtstat") and `or`(weaktoktains(process_command_line, "-n"), weaktoktains(process_command_line, "-s")))
or (weaktoktains(process_command_line, "arp") and weaktoktains(process_command_line, "-a"))
where `or`(weaktoktains(new_process_name, "nbtstat.exe"), weaktoktains(new_process_name, "arp.exe"))
group every 5m by subject_security_id, subject_username, subject_logon_id, subject_domain, machine, device, client
, target_security_id, target_username, target_logon_id, target_domain, token_elevation_type, mandatory_label
, new_pid, new_process_name, parent_process_name, process_command_line, machine_ip
//Entity Mapping Section
select machine as entity_sourceHostname
select subject_username as entity_sourceAccount
select subject_domain as entity_sourceDomain
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceDomain) as entity_sourceDomain_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole
//<filtering_section>
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsWinRemoteSystemDiscovery") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsWinRemoteSystemDiscovery") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsWinRemoteSystemDiscovery") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsWinRemoteSystemDiscovery") as alertPriority
```

## SecOpsWinRunasCommandExecution

**Summary:** Detects the use the of runas.exe process. Adversaries can abuse the runas.exe process to gain elevated privileges on the target host.

**Description:** Detects the use of the runas.exe process. Adversaries can abuse the runas.exe process to gain elevated privileges on the target host.

**MITRE:** Tactics: Defense Evasion (TA0005) | Techniques: Access Token Manipulation (T1134)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.all.win
where event_id = 4688
where weaktoktains(new_process_name, "runas.exe")
group every 5m by subject_security_id, subject_username, subject_domain, subject_logon_id, new_pid, new_process_name, token_elevation_type, device, client
, pid, process_command_line, target_security_id, target_username, target_domain, target_logon_id, parent_process_name, mandatory_label
, machine, machine_ip
//Entity Mapping Section
select machine as entity_sourceHostname
select subject_username as entity_sourceAccount
select subject_domain as entity_sourceDomain
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceDomain) as entity_sourceDomain_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole
//<filtering_section>
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsWinRunasCommandExecution") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsWinRunasCommandExecution") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsWinRunasCommandExecution") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsWinRunasCommandExecution") as alertPriority
```

## SecOpsWinSamStopped

**Summary:** Detects when the Windows Security Account Manager (SAM) is stopped via the command-line. This is consistent with ransomware infections across a fleet of endpoints.

**MITRE:** Tactics: Impact (TA0040) | Techniques: Service Stop (T1489)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.all.win
where event_id=4688
where weaktoktains(process_command_line, "samss")
where (weaktoktains(new_process_name, "net.exe") and weaktoktains(process_command_line, "stop")) or (weaktoktains(new_process_name, "sc.exe") and weaktoktains(process_command_line, "disabled"))
group every 5m by subject_security_id, subject_username, subject_domain, subject_logon_id, new_pid, new_process_name, token_elevation_type, device, client
, pid, process_command_line, target_security_id, target_username, target_domain, target_logon_id, parent_process_name, mandatory_label
, machine, machine_ip
every 5m
//Entity Mapping Section
select machine as entity_sourceHostname
select subject_username as entity_sourceAccount
select subject_domain as entity_sourceDomain
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceDomain) as entity_sourceDomain_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole
//<filtering_section>
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsWinSamStopped") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsWinSamStopped") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsWinSamStopped") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsWinSamStopped") as alertPriority
```

## SecOpsWinScheduledTaskCreation

**Summary:** Detects when a scheduled task is created in Windows.

**MITRE:** Tactics: Execution (TA0002), Persistence (TA0003), Privilege Escalation (TA0004) | Techniques: Scheduled Task/Job (T1053)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.all.win
where event_id = 4698
group every 5m by machine, machine_ip, subject_security_id, subject_username, subject_domain, subject_logon_id, task_name, task_content, device, client
every 5m
//Entity Mapping Section
select subject_domain as entity_sourceHostName
select str(machine_ip) as entity_sourceIp
select subject_username as entity_sourceAccount
select subject_domain as entity_sourceDomain
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceDomain) as entity_sourceDomain_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceHostName) as entity_sourceHostName_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceIp) as entity_sourceIp_AssetRole
//<filtering_section>
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsWinScheduledTaskCreation") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsWinScheduledTaskCreation") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsWinScheduledTaskCreation") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsWinScheduledTaskCreation") as alertPriority
```

## SecOpsWinSchtasksForcedReboot

**Summary:** Alerts when flags are passed to schtasks.exe on the command-line that indicate that a forced system reboot is scheduled.

**MITRE:** Tactics: Execution (TA0002) | Techniques: Scheduled Task/Job (T1053)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.all.win
where event_id = 4688
where weaktoktains(new_process_name, "schtasks.exe") and weaktoktains(process_command_line, "/create") and weaktoktains(process_command_line, "shutdown")
group every 5m by subject_security_id, subject_username, subject_domain, subject_logon_id, new_pid, new_process_name, token_elevation_type, pid, process_command_line, target_security_id, target_username, target_domain, target_logon_id, parent_process_name, mandatory_label, machine, machine_ip, device, client
every 5m
//Entity Mapping Section
select machine as entity_sourceHostname
select subject_username as entity_sourceAccount
select subject_domain as entity_sourceDomain
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceDomain) as entity_sourceDomain_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole
//<filtering_section>
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsWinSchtasksForcedReboot") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsWinSchtasksForcedReboot") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsWinSchtasksForcedReboot") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsWinSchtasksForcedReboot") as alertPriority
```

## SecOpsWinSchtasksRemoteSystem

**Summary:** Detects flags passed to schtasks.exe on the command-line that indicate a job is being scheduled on a remote system.

**MITRE:** Tactics: Execution (TA0002) | Techniques: Scheduled Task/Job (T1053)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.all.win
where event_id = 4688
where weaktoktains(new_process_name, "schtasks.exe") and weaktoktains(process_command_line, "/create") and weaktoktains(process_command_line, "/s")
group every 5m by subject_security_id, subject_username, subject_domain, subject_logon_id, new_pid, new_process_name, token_elevation_type, device, client
, pid, process_command_line, target_security_id, target_username, target_domain, target_logon_id, parent_process_name, mandatory_label
, machine, machine_ip
every 5m
//Entity Mapping Section
select str(machine_ip) as entity_sourceIP
select machine as entity_sourceHostname
select subject_username as entity_sourceAccount
select subject_domain as entity_sourceDomain
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceDomain) as entity_sourceDomain_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole
//<filtering_section>
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsWinSchtasksRemoteSystem") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsWinSchtasksRemoteSystem") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsWinSchtasksRemoteSystem") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsWinSchtasksRemoteSystem") as alertPriority
```

## SecOpsWinSensitiveFiles

**Summary:** Detects a new process which involves a Windows local system sensitive file.

**Description:** Detected a potentially malicious new process which involves a sensitive Windows file on $srcHost with ip $machineIp by user $subjectUsername. This activity should be reviewed to determine that this execution is not malicious. execution: $procCmdLine

**MITRE:** Tactics: Exfiltration (TA0010), Collection (TA0009) | Techniques: Data from Local System (T1005)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.all.win
where eq(event_id,4688)
where `or`(weaktoktains(process_command_line,"repair\\sam",true,true),weaktoktains(process_command_line,"regback\\sam",true,true),weaktoktains(process_command_line,"repair\\system",true,true),weaktoktains(process_command_line,"repair\\software",true,true),weaktoktains(process_command_line,"repair\\security",true,true),weaktoktains(process_command_line,"netsetup.log",true,true),weaktoktains(process_command_line,"httperr1.log",true,true),weaktoktains(process_command_line,"sysrep.inf",true,true),weaktoktains(process_command_line,"sysrep.xml",true,true),weaktoktains(process_command_line,"Unattended.xml",true,true),weaktoktains(process_command_line,"appevent.evt",true,true),weaktoktains(process_command_line,"secevent.evt",true,true),weaktoktains(process_command_line,"default.sav",true,true),weaktoktains(process_command_line,"security.sav",true,true),weaktoktains(process_command_line,"software.sav",true,true),weaktoktains(process_command_line,"system.sav",true,true),weaktoktains(process_command_line,"applicationhost.config",true,true),weaktoktains(process_command_line,"aspnet_schema.xml",true,true),weaktoktains(process_command_line,"etc\\hosts",true,true),weaktoktains(process_command_line,"etc\\networks",true,true),weaktoktains(process_command_line,"config\\sam",true,true))
group every 5m by machine_ip,subject_username,source_hostname,process_command_line, device, client
//Entity Mapping Section
select source_hostname as entity_sourceHostname
select subject_username as entity_sourceAccount
select machine_ip as entity_sourceIP
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole
//<filtering_section>
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsWinSensitiveFiles") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsWinSensitiveFiles") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsWinSensitiveFiles") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsWinSensitiveFiles") as alertPriority
```

## SecOpsWinServiceCreatedNonStandardPath

**Summary:** Adversaries may attempt to create malicious Services for lateral movement or remote code execution as well as persistence and execution. The Clop ransomware has also been seen in the wild abusing Windows services.

**Description:** Adversaries may attempt to create malicious Services for lateral movement or remote code execution as well as persistence and execution. The Clop ransomware has also been seen abusing Windows services.

**MITRE:** Tactics: Execution (TA0002) | Techniques: System Services (T1569)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.all.win
where event_id = 7045 and weakhas(service_file_name, ".exe") and not (weakhas(service_file_name, "C:\\Windows\\") or weakhas(service_file_name, "C:\\Program File") or weakhas(service_file_name, "C:\\Programdata") or weakhas(service_file_name, "%systemroot%"))
select source_hostname as entity_sourceHostname
select str(machine_ip) as entity_sourceIP
select username as entity_sourceAccount
group every 5m by event_id, entity_sourceHostname, entity_sourceIP, entity_sourceAccount, service, service_file_name, device, client
every 5m
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsWinServiceCreatedNonStandardPath") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsWinServiceCreatedNonStandardPath") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsWinServiceCreatedNonStandardPath") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsWinServiceCreatedNonStandardPath") as alertPriority
```

## SecOpsWinShadowCopyDetected

**Summary:** Observes for Ntdsutil, Vssadmin, WMIC, or PowerShell creating shadow copies. This is another method to extract credentials.

**Description:** Observes for ntdsutil, vssadmin, wmic, or PowerShell creating shadow copies. This is another method to extract credentials.

**MITRE:** Tactics: Credential Access (TA0006) | Techniques: OS Credential Dumping (T1003)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.all.win
where event_id = 4688
where (
weaktoktains(new_process_name, "ntdsutil.exe")
or weaktoktains(new_process_name, "vssadmin.exe")
or weaktoktains(new_process_name, "wmic.exe")
or weaktoktains(new_process_name, "powershell.exe")
)
and (
(weaktoktains(process_command_line, "ntds") and weaktoktains(process_command_line, "create"))
or (weaktoktains(process_command_line, "shadow") and weaktoktains(process_command_line, "create"))
or (weaktoktains(process_command_line, "shadowcopy") and weaktoktains(process_command_line, "create"))
)
group every 5m by subject_security_id, subject_username, subject_logon_id, subject_domain, machine, device, client
, target_security_id, target_username, target_logon_id, target_domain, token_elevation_type, mandatory_label
, new_pid, new_process_name, parent_process_name, process_command_line, machine_ip
//Entity Mapping Section
select machine as entity_sourceHostname
select subject_username as entity_sourceAccount
select machine_ip as entity_sourceIp
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceIp) as entity_sourceIp_AssetRole
//<filtering_section>
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsWinShadowCopyDetected") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsWinShadowCopyDetected") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsWinShadowCopyDetected") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsWinShadowCopyDetected") as alertPriority
```

## SecOpsWinSmtpExfiltration

**Summary:** Detects exfiltration via SMTP.

**Description:** Detected a possible data exfiltration over SMTP on $srcHost with ip $machineIp by user $subjectUsername. This activity should be reviewed to determine that this execution is not malicious. execution: $procCmdLine

**MITRE:** Tactics: Exfiltration (TA0010) | Techniques: Exfiltration Over Alternative Protocol (T1048)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.all.win
where eq(event_id,4688) or eq(event_id,4104) or eq(event_id,4103)
where weaktoktains(rawMessage,"Send-MailMessage",true,true) and (weaktoktains(process_command_line,"-Attachments",true,true) or weaktoktains(process_command_line,"-Body",true,true) or weaktoktains(process_command_line,"-BodyAsHtml",true,true))
group every 5m by machine_ip,subject_username,source_hostname,process_command_line, device, client
//Entity Mapping Section
select source_hostname as entity_sourceHostname
select subject_username as entity_sourceAccount
select machine_ip as entity_sourceIP
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole
//<filtering_section>
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsWinSmtpExfiltration") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsWinSmtpExfiltration") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsWinSmtpExfiltration") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsWinSmtpExfiltration") as alertPriority
```

## SecOpsWinSpoolsvExeAbnormalProcessSpawn

**Summary:** Detects Spoolsv.exe launching unexpected child processes. This activity may be related to behavior in CVE-2018-8440.

**MITRE:** Tactics: Privilege Escalation (TA0004) | Techniques: Exploitation for Privilege Escalation (T1068)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.all.win
where eq(str(event_id), "4688") and weakhas(parent_process_name, "spoolsv.exe") and isnotnull(new_process_name)
// Modify query to ignore common child processes as necessary
where not(weakhas(new_process_name, "splwow64.exe")) and not(weakhas(new_process_name, "PDFCreator.exe")) and not(weakhas(new_process_name, "acrodist.exe")) and not(weakhas(new_process_name, "spoolsv.exe")) and not(weakhas(new_process_name, "msiexec.exe")) and not(weakhas(new_process_name, "route.exe")) and not(weakhas(new_process_name, "WerFault.exe")) and not(weakhas(process_command_line, "\\WINDOWS\\system32\\spool\\DRIVERS")) and not(weakhas(new_process_name,"net.exe") and (weakhas(process_command_line, "stop") or weakhas(process_command_line, "stop"))) and not(weakhas(new_process_name,"netsh.exe") and (weakhas(process_command_line, "add portopening") or weakhas(process_command_line, "rule name"))) and not(weakhas(new_process_name,"regsvr32.exe") and (weakhas(process_command_line, "PrintConfig.dll"))) and not((weakhas(new_process_name,"cmd.exe") or weakhas(new_process_name,"powershell.exe")) and (weakhas(process_command_line, ".spl") or weakhas(process_command_line, "route add") or weakhas(process_command_line, "program files")))
select source_hostname as entity_sourceHostname
select str(machine_ip) as entity_sourceIP
group every 5m by source_name, entity_sourceIP, entity_sourceHostname, parent_process_name, new_process_name, process_command_line, device, client
every 5m
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsWinSpoolsvExeAbnormalProcessSpawn") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsWinSpoolsvExeAbnormalProcessSpawn") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsWinSpoolsvExeAbnormalProcessSpawn") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsWinSpoolsvExeAbnormalProcessSpawn") as alertPriority
```

## SecOpsWinSuspiciousExternalDeviceInstallation

**Summary:** Detects the installation of hardware that was previously denied by policy. Device installation logging must be configured (see logging related reference links).

**MITRE:** Tactics: Collection (TA0009), Exfiltration (TA0010), Command and Control (TA0011) | Techniques: Data from Removable Media (T1025), Exfiltration Over Physical Medium (T1052), Communication Through Removable Media (T1092)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, mispIndicator, SecOpsLocation, SecOpsAlertDescription

```linq
from box.all.win
where event_id=6424
group every 5m by subject_username, subject_domain, subject_logon_id, device, client
, machine_ip, machine, device_id, device_name, class_id, class_name
//Entity Mapping Section
select machine as entity_sourceHostname
select subject_username as entity_sourceAccount
select str(machine_ip) as entity_sourceIP
select subject_domain as entity_sourceDomain
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceDomain) as entity_sourceDomain_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole
//<filtering_section>
//Enrichment Mapping
select asn(ip4(entity_sourceIP)) as enrichStream_entity_sourceIP_ASN
select isp(ip4(entity_sourceIP)) as enrichStream_entity_sourceIP_ISP
select countrycode(ip4(entity_sourceIP)) as enrichStream_entity_sourceIP_country
select ifthenelse(toktains(lu("mispIndicator", "eventtags_name_str", str(entity_sourceIP)),"TOR"), true, false) as enrichStream_entity_sourceIP_isAnonymousProxy
select lu("SecOpsLocation", "country", entity_sourceIP) as enrichStream_entity_sourceIP_locationCountry
select lu("SecOpsLocation", "city", entity_sourceIP) as enrichStream_entity_sourceIP_locationCity
select lu("SecOpsLocation", "state", entity_sourceIP) as enrichStream_entity_sourceIP_locationState
select lu("SecOpsLocation", "lat", entity_sourceIP) as enrichStream_entity_sourceIP_locationLat
select lu("SecOpsLocation", "lon", entity_sourceIP) as enrichStream_entity_sourceIP_locationLon
//Get Enrichment from SecOps
select lu("mispIndicator", "category", entity_sourceIP) as indicator
select lu("mispIndicator", "type", entity_sourceIP) as misp_indicator_type
select lu("mispIndicator", "event_id", entity_sourceIP) as misp_indicator_event_id
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsWinSuspiciousExternalDeviceInstallation") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsWinSuspiciousExternalDeviceInstallation") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsWinSuspiciousExternalDeviceInstallation") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsWinSuspiciousExternalDeviceInstallation") as alertPriority
```

## SecOpsWinSuspiciousWritesToRecycleBin

**Summary:** Adversaries may attempt to manipulate features of their artifacts to make them appear legitimate. Masquerading occurs when the name or location of an object is manipulated or abused for the sake of evading defenses and observation.

**Description:** Adversaries may attempt to manipulate features of their artifacts to make them appear legitimate. Masquerading occurs when the name or location of an object is manipulated.

**MITRE:** Tactics: Defense Evasion (TA0005) | Techniques: Masquerading (T1036)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.all.win
where event_id = 11 and channel = "sysmon" and not weakhas(image, "explorer.exe")
//select str(jqeval(jqcompile(".TargetFilename"), jsonparse(rawMessage))) as target_fileName
select image as source_process
where weakhas(target_file_name, "$Recycle.Bin")
select str(machine_ip) as entity_sourceIP
select source_hostname as entity_sourceHostname
group every 5m by source_process, entity_sourceHostname, entity_sourceIP, target_file_name, message, device, client
every 5m
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsWinSuspiciousWritesToRecycleBin") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsWinSuspiciousWritesToRecycleBin") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsWinSuspiciousWritesToRecycleBin") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsWinSuspiciousWritesToRecycleBin") as alertPriority
```

## SecOpsWinSysInfoGatheringUsingDxdiag

**Summary:** Using dxdiag.exe adversaries may gather information about the victim's hosts that can be used during targeting. Information about hosts may include a variety of details, including administrative data.

**MITRE:** Tactics: Reconnaissance (TA0043) | Techniques: Gather Victim Host Information (T1592)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.all.win
where ((event_id = 1 and channel ="Microsoft-Windows-Sysmon/Operational") or event_id = 4688) and (weakhas(process_command_line, "dxdiag.exe") and weakhas(process_command_line, "/t"))
select source_hostname as entity_sourceHostname
select str(machine_ip) as entity_sourceIP
group every 5m by source_name, entity_sourceIP, entity_sourceHostname, process_command_line, device, client
every 5m
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsWinSysInfoGatheringUsingDxdiag") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsWinSysInfoGatheringUsingDxdiag") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsWinSysInfoGatheringUsingDxdiag") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsWinSysInfoGatheringUsingDxdiag") as alertPriority
```

## SecOpsWinSysInternalsActivityDetected

**Summary:** Checks for the Accepted Sysinternals EULA from the registry key "HKCU\Software\Sysinternals\[TOOL]\". When a Sysinternals tool is first to run on a system, the EULA must be accepted. This writes a value called EulaAccepted under that key.

**MITRE:** Tactics: Execution (TA0002), Resource Development (TA0042) | Techniques: Windows Management Instrumentation (T1047), Obtain Capabilities (T1588)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.all.win
where weaktoktains(raw,"Sysinternals"), weaktoktains(raw, "EulaAccepted")
where event_id = 4657
where object_value_name="EulaAccepted"
group every 5m by subject_security_id, subject_username, subject_logon_id, subject_domain, machine, machine_ip, device, client
,object_name, object_value_name, new_value, pid, process_name
//Entity Mapping Section
select machine as entity_sourceHostname
select subject_username as entity_sourceAccount
select subject_domain as entity_sourceDomain
select str(machine_ip) as entity_sourceIP
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceDomain) as entity_sourceDomain_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole
//<filtering_section>
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsWinSysInternalsActivityDetected") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsWinSysInternalsActivityDetected") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsWinSysInternalsActivityDetected") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsWinSysInternalsActivityDetected") as alertPriority
```

## SecOpsWinSysTimeDiscovery

**Summary:** Detects the use of various commands to query the system time.

**MITRE:** Tactics: Discovery (TA0007) | Techniques: System Location Discovery (T1614)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.all.win
where toktains(raw,"tzutil") or toktains(raw,"w32tm")
where event_id=4688
where isnotnull(process_command_line)
group every 5m by subject_security_id, subject_username, subject_logon_id, subject_domain, machine, device, client
, target_security_id, target_username, target_logon_id, target_domain
, new_pid, new_process_name, caller_pid, caller_process_name, token_elevation_type, mandatory_label, process_command_line
select count() as count
//Entity Mapping Section
select machine as entity_sourceHostname
select subject_username as entity_sourceAccount
select subject_domain as entity_sourceDomain
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceDomain) as entity_sourceDomain_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole
//<filtering_section>
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsWinSysTimeDiscovery") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsWinSysTimeDiscovery") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsWinSysTimeDiscovery") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsWinSysTimeDiscovery") as alertPriority
```

## SecOpsWinTFTPExecution

**Summary:** Detects a potentially malicious execution of TFTP.

**Description:** Detected a potentially malicious TFTP execution on $srcHost with ip $machineIp by user $subjectUsername. This activity should be reviewed to determine that the execution is not malicious. execution: $procCmdLine

**MITRE:** Tactics: Command and Control (TA0011), Exfiltration (TA0010) | Techniques: Ingress Tool Transfer (T1105), Exfiltration Over Alternative Protocol (T1048)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.all.win
where event_id=4688
where weaktoktains(new_process_name,"tftp.exe",true,true)
where `or`(weaktoktains(process_command_line,"tftp",true,true),weaktoktains(process_command_line," PUT ",true,true),weaktoktains(process_command_line," GET ",true,true))
group every 5m by machine_ip,subject_username,source_hostname,process_command_line, device, client
//Entity Mapping Section
select source_hostname as entity_sourceHostname
select subject_username as entity_sourceAccount
select machine_ip as entity_sourceIP
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole
//<filtering_section>
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsWinTFTPExecution") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsWinTFTPExecution") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsWinTFTPExecution") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsWinTFTPExecution") as alertPriority
```

## SecOpsWinUserAddedPrivlegedSecGroup

**Summary:** UnPrivileged account added to Global Security Group

**Description:** Alerts when an unprivileged account is added to a global security group like domain administrators.

**MITRE:** Tactics: Execution (TA0002), Resource Development (TA0042) | Techniques: Obtain Capabilities (T1588), Windows Management Instrumentation (T1047)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.all.win
where isnotnull(subject_security_id) and
event_id = 4728 or event_id = 4732 or event_id = 4756
group every 5m by event_id, member_name, member_security_id, target_username, target_domain, target_security_id, subject_security_id, subject_username, subject_domain, subject_logon_id, group_security_id, group_name, privilege_list, machine_ip, machine, device, client
//Entity Mapping Section
select ifthenelse(isnull(machine), "UNK", machine) as entity_sourceHostname,
subject_username as entity_sourceAccount,
ifthenelse(isnull(str(machine_ip)), "UNK", str(machine_ip)) as entity_sourceIp,
group_security_id as entity_group_ssid,
group_name as entity_group_name
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceIp) as entity_sourceIp_AssetRole
//<filtering_section>
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsWinUserAddedPrivlegedSecGroup") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsWinUserAddedPrivlegedSecGroup") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsWinUserAddedPrivlegedSecGroup") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsWinUserAddedPrivlegedSecGroup") as alertPriority
```

## SecOpsWinUserAddedSelfToSecGroup

**Summary:** Identifies when a user account has added themselves to the Windows security group. This could indicate a user attempting to escalate their privileges.

**MITRE:** Tactics: Persistence (TA0003) | Techniques: Account Manipulation (T1098)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.all.win
where event_id=4728 or event_id=4732 or event_id=4756
where subject_security_id = member_security_id
group every 5m by source_ip, subject_username,subject_domain, subject_security_id, target_domain, target_username, member_security_id, machine, machine_ip, source_hostname, member_name, device, client
every 5m
//Entity Mapping Section
select source_hostname as entity_sourceHostname
select subject_username as entity_sourceAccount
select subject_domain as entity_sourceDomain

// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceDomain) as entity_sourceDomain_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole
//<filtering_section>
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsWinUserAddedSelfToSecGroup") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsWinUserAddedSelfToSecGroup") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsWinUserAddedSelfToSecGroup") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsWinUserAddedSelfToSecGroup") as alertPriority
```

## SecOpsWinUserAddedToLocalSecurityEnabledGroup

**Summary:** Attackers may attempt to escalate privileges to a user account by adding it to a local security-enabled group. This could indicate privilege abuse or potentially malicious activity.

**MITRE:** Tactics: Persistence (TA0003) | Techniques: Account Manipulation (T1098)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.all.win
where event_id=4732
where isnotnull(member_name)
// For local groups only Local Administrator Group monitored.
select ifthenelse(member_name = "-", ifthenelse(target_security_id = "S-1-5-32-544", target_security_id, "-"), member_name) as genMemberName
where not member_name = "-"
group every 5m by source_ip, subject_username,subject_domain, target_domain, target_username, target_security_id, machine, machine_ip, source_hostname, genMemberName, device, client
every 5m
//Entity Mapping Section
select source_hostname as entity_sourceHostname
select subject_username as entity_sourceAccount
select source_ip as entity_sourceIP
select subject_domain as entity_sourceDomain
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceDomain) as entity_sourceDomain_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole
//<filtering_section>
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsWinUserAddedToLocalSecurityEnabledGroup") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsWinUserAddedToLocalSecurityEnabledGroup") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsWinUserAddedToLocalSecurityEnabledGroup") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsWinUserAddedToLocalSecurityEnabledGroup") as alertPriority
```

## SecOpsWinUserCreationAbnormalNamingConvention

**Summary:** Detects new user accounts that do not match a user-specified naming convention. The `namePattern` selector value should be populated with a regular expression that matches the organization's naming convention.

**MITRE:** Tactics: Persistence (TA0003) | Techniques: Create Account (T1136)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.all.win
where event_id = 4720
where shannonentropy(account) > 3.9 and length(account) >= 20
group every 5m by source_hostname, source_ip, subject_username, subject_domain, target_username, device, client
select source_hostname as entity_sourceHostname, source_ip as entity_sourceIP, subject_username as entity_sourceAccount, subject_domain as entity_sourceDomain
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceDomain) as entity_sourceDomain_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole
//<filtering_section>
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsWinUserCreationAbnormalNamingConvention") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsWinUserCreationAbnormalNamingConvention") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsWinUserCreationAbnormalNamingConvention") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsWinUserCreationAbnormalNamingConvention") as alertPriority
```

## SecOpsWinUserCredentialDumpRegistry

**Summary:** Monitors for use of reg.exe with parameters indicating the attempted export of hashed credentials.

**MITRE:** Tactics: Credential Access (TA0006) | Techniques: OS Credential Dumping (T1003)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.all.win
where toktains(raw,"reg.exe"), `or`(toktains(raw,"Secrets"), toktains(raw,"SAM"), toktains(raw,"Cache"))
where event_id = 4663
group every 5m by source_ip, source_hostname, machine, machine_ip, subject_security_id, subject_username, subject_domain, subject_logon_id, device, client
, object_server, object_type, object_name, object_handle
, process_name, pid
, accesses, access_mask
//Entity Mapping Section
select source_hostname as entity_sourceHostname
select subject_username as entity_sourceAccount
select source_ip as entity_sourceIP
select subject_domain as entity_sourceDomain
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceDomain) as entity_sourceDomain_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole
//<filtering_section>
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsWinUserCredentialDumpRegistry") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsWinUserCredentialDumpRegistry") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsWinUserCredentialDumpRegistry") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsWinUserCredentialDumpRegistry") as alertPriority
```

## SecOpsWinWebclientClassUse

**Summary:** Detects a potentially malicious WebClient method execution.

**Description:** Detected a potentially malicious execution of a WebClient method on $srcHost with ip $machineIp by user $subjectUsername. This activity should be reviewed to determine that this execution is not malicious. execution: $procCmdLine

**MITRE:** Tactics: Command and Control (TA0011), Exfiltration (TA0010) | Techniques: Ingress Tool Transfer (T1105), Exfiltration Over Alternative Protocol (T1048)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.all.win
where eq(event_id,4688)
where weaktoktains(new_process_name,"powershell",true,true)
where weaktoktains(process_command_line,"WebClient",true,true)
where `or`(weaktoktains(process_command_line,"OpenWrite",true,true),weaktoktains(process_command_line,"OpenWriteAsync",true,true),weaktoktains(process_command_line,"UploadData",true,true),weaktoktains(process_command_line,"UploadDataAsync",true,true),weaktoktains(process_command_line,"UploadFile",true,true),weaktoktains(process_command_line,"UploadFileAsync",true,true),weaktoktains(process_command_line,"UploadValues",true,true),weaktoktains(process_command_line,"UploadValuesAsync",true,true),weaktoktains(process_command_line,"UploadString",true,true),weaktoktains(process_command_line,"UploadStringAsync",true,true),weaktoktains(process_command_line,"OpenRead",true,true),weaktoktains(process_command_line,"OpenReadAsync",true,true),weaktoktains(process_command_line,"DownloadData",true,true),weaktoktains(process_command_line,"DownloadDataAsync",true,true),weaktoktains(process_command_line,"DownloadFile",true,true),weaktoktains(process_command_line,"DownloadFileAsync",true,true),weaktoktains(process_command_line,"DownloadString",true,true),weaktoktains(process_command_line,"DownloadStringAsync",true,true))
where `or`(weaktoktains(process_command_line,"http:",true,true),weaktoktains(process_command_line,"https:",true,true),weaktoktains(process_command_line,"ftp:",true,true))
group every 5m by machine_ip,subject_username,source_hostname,process_command_line, device, client
//Entity Mapping Section
select source_hostname as entity_sourceHostname
select subject_username as entity_sourceAccount
select machine_ip as entity_sourceIP
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole
//<filtering_section>
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsWinWebclientClassUse") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsWinWebclientClassUse") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsWinWebclientClassUse") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsWinWebclientClassUse") as alertPriority
```

## SecOpsWinWifiCredHarvestNetsh

**Summary:** Detects the harvesting of WIFI credentials using netsh.exe.

**MITRE:** Tactics: Credential Access (TA0006) | Techniques: Unsecured Credentials (T1552)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.all.win
where event_id = 4688 and toktains(message, "netsh.exe")
where weaktoktains(process_command_line, "wlan"), weaktoktains(process_command_line, "show"), toktains(process_command_line, "profile")
, weaktoktains(process_command_line, "key"), weaktoktains(process_command_line, "=clear")
where weaktoktains(new_process_name, "netsh.exe")
group every 5m by subject_security_id, subject_username, subject_logon_id, subject_domain, machine, device, client
, target_security_id, target_username, target_logon_id, target_domain
, new_pid, new_process_name, caller_pid, caller_process_name, process_command_line
//Entity Mapping Section
select machine as entity_sourceHostname
select subject_username as entity_sourceAccount
select subject_domain as entity_sourceDomain
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceDomain) as entity_sourceDomain_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole
//<filtering_section>
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsWinWifiCredHarvestNetsh") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsWinWifiCredHarvestNetsh") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsWinWifiCredHarvestNetsh") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsWinWifiCredHarvestNetsh") as alertPriority
```

## SecOpsWinWmiExecVbsScript

**Summary:** Detects suspicious file execution by wscript and cscript. Adversaries can use this mechanism to execute malicious code for persistence or privilege escalation.

**MITRE:** Tactics: Execution (TA0002) | Techniques: Command and Scripting Interpreter (T1059)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.all.win
where event_id=4688
where `or`(weaktoktains(new_process_name, "cscript.exe"), weaktoktains(new_process_name, "wscript.exe")) and toktains(process_command_line, "vbs")
where not endswith(subject_username, "$")
where not toktains(new_process_name,"MonitorKnowledgeDiscovery.vbs")
group every 5m by event_id, machine_ip, subject_security_id, subject_username, subject_logon_id, subject_domain, machine, target_security_id, target_username, target_logon_id, target_domain, new_pid, new_process_name, token_elevation_type, mandatory_label, process_command_line, parent_process_name, device, client
//Entity Mapping Section
select str(machine_ip) as entity_sourceIP
select machine as entity_sourceHostname
select subject_username as entity_sourceAccount
select subject_domain as entity_sourceDomain
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceDomain) as entity_sourceDomain_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole
//<filtering_section>
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsWinWmiExecVbsScript") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsWinWmiExecVbsScript") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsWinWmiExecVbsScript") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsWinWmiExecVbsScript") as alertPriority
```

## SecOpsWinWmiLaunchingShell

**Summary:** Detects WMI by creating a child process of cmd.exe or PowerShell. An attacker can use WMI to launch a shell on the local or remote host to bypass application whitelisting since WMI is a native Windows management tool.

**MITRE:** Tactics: Execution (TA0002) | Techniques: Windows Management Instrumentation (T1047)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.all.win
where event_id = 4688 and `or`(weaktoktains(parent_process_name, "wmiprvse.exe"), weaktoktains(parent_process_name, "wmi.exe"))
where `or`(weaktoktains(new_process_name, "powershell.exe"), weaktoktains(new_process_name, "cmd.exe"))
group every 5m by subject_security_id, subject_username, subject_logon_id, subject_domain, machine, machine_ip, device, client
, target_security_id, target_username, target_logon_id, target_domain
, new_pid, new_process_name, caller_pid, caller_process_name, token_elevation_type, mandatory_label, process_command_line, parent_process_name
//Entity Mapping Section
select str(machine_ip) as entity_sourceIP
select machine as entity_sourceHostname
select subject_username as entity_sourceAccount
select subject_domain as entity_sourceDomain
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceDomain) as entity_sourceDomain_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole
//<filtering_section>
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsWinWmiLaunchingShell") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsWinWmiLaunchingShell") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsWinWmiLaunchingShell") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsWinWmiLaunchingShell") as alertPriority
```

## SecOpsWINWmiMOFProcessExecution

**Summary:** Windows Management Instrumentation enables system administrators to perform tasks locally and remotely. Adversaries may utilize The Managed Object Format (MOF) compiler to compile and execute their malicious code within the WMI Repository.

**MITRE:** Tactics: Persistence (TA0003) | Techniques: Event Triggered Execution (T1546)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.all.win
where ((event_id = 1 and channel ="Microsoft-Windows-Sysmon/Operational") or event_id = 4688) and (weakhas(process_command_line,  "mofcomp.exe") and weakhas(process_command_line,  ".mof"))
select source_hostname as entity_sourceHostname
select str(machine_ip) as entity_sourceIP
group every 5m by source_name, entity_sourceIP, entity_sourceHostname, process_command_line, device, client
every 5m
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsWINWmiMOFProcessExecution") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsWINWmiMOFProcessExecution") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsWINWmiMOFProcessExecution") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsWINWmiMOFProcessExecution") as alertPriority
```

## SecOpsWinWMIPermanentEventSubscription

**Summary:** WMI can be used to install event filters, providers, consumers, and bindings that execute code when a defined event occurs. WMI subscription execution is proxied by the process WmiPrvSe.exe and may result in elevated SYSTEM privileges.

**MITRE:** Tactics: Execution (TA0002) | Techniques: Windows Management Instrumentation (T1047)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.all.win
where eq(source_name, "Microsoft-Windows-Sysmon") and eq(event_id, 21)
select source_hostname as entity_sourceHostname
select str(machine_ip) as entity_sourceIP
select username as entity_sourceAccount
select jqeval(jqcompile(".columns.data.EventData"), jsonparse(rawMessage)) as EventSubscriptionData
group every 5m by entity_sourceHostname, entity_sourceIP, entity_sourceAccount, EventSubscriptionData, device, client
every 5m
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsWinWMIPermanentEventSubscription") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsWinWMIPermanentEventSubscription") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsWinWMIPermanentEventSubscription") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsWinWMIPermanentEventSubscription") as alertPriority
```

## SecOpsWinWmiProcessCallCreate

**Summary:** Detects usage of WMI to create processes on local the local or remote hosts. WMI is a native Windows tool and can be used to bypass application whitelisting.

**MITRE:** Tactics: Execution (TA0002) | Techniques: Windows Management Instrumentation (T1047)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.all.win
where event_id = 4688 and toktains(rawMessage, "process call create") and weaktoktains(rawMessage, "wmic.exe")
where weaktoktains(new_process_name, "wmic.exe")
group every 5m by subject_security_id, subject_username, subject_logon_id, subject_domain, machine, machine_ip, device, client
, target_security_id, target_username, target_logon_id, target_domain
, new_pid, new_process_name, caller_pid, caller_process_name, token_elevation_type, mandatory_label, process_command_line
//Entity Mapping Section
select str(machine_ip) as entity_sourceIP
select machine as entity_sourceHostname
select subject_username as entity_sourceAccount
select subject_domain as entity_sourceDomain
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceDomain) as entity_sourceDomain_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole
//<filtering_section>
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsWinWmiProcessCallCreate") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsWinWmiProcessCallCreate") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsWinWmiProcessCallCreate") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsWinWmiProcessCallCreate") as alertPriority
```

## SecOpsWinWmiprvseSpawningProcess

**Summary:** Detects child processes spawned by WMIPRVSE. Adversaries can use this to obscure parent-child relationships or launch cmd.exe or PowerShell.

**MITRE:** Tactics: Persistence (TA0003) | Techniques: Event Triggered Execution (T1546)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.all.win
where event_id = 4688 and weaktoktains(rawMessage, "wmiprvse.exe")
where weaktoktains(caller_process_name, "wmiprvse.exe")
group every 5m by subject_security_id, subject_username, subject_logon_id, subject_domain, machine, machine_ip, device, client
, target_security_id, target_username, target_logon_id, target_domain
, new_pid, new_process_name, caller_pid, caller_process_name, token_elevation_type, mandatory_label, process_command_line, parent_process_name
//Entity Mapping Section
select str(machine_ip) as entity_sourceIP
select machine as entity_sourceHostname
select subject_username as entity_sourceAccount
select subject_domain as entity_sourceDomain
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceDomain) as entity_sourceDomain_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole
//<filtering_section>
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsWinWmiprvseSpawningProcess") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsWinWmiprvseSpawningProcess") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsWinWmiprvseSpawningProcess") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsWinWmiprvseSpawningProcess") as alertPriority
```

## SecOpsWinWMIReconRunningProcessOrSrvcs

**Summary:** Adversaries may gather information about the victim's hosts that can be used during targeting. Information about hosts may include a variety of details, including administrative data.

**MITRE:** Tactics: Reconnaissance (TA0043) | Techniques: Gather Victim Host Information (T1592)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.all.win
where eq(str(event_id), "4104") and (weakhas(process_command_line, "SELECT") and (weakhas(process_command_line, "Win32_Process") or weakhas(process_command_line, "Win32_Service")))
select source_hostname as entity_sourceHostname
select str(machine_ip) as entity_sourceIP
group every 5m by source_name, channel, event_id, entity_sourceIP, entity_sourceHostname, process_command_line, device, client
every 5m
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsWinWMIReconRunningProcessOrSrvcs") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsWinWMIReconRunningProcessOrSrvcs") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsWinWMIReconRunningProcessOrSrvcs") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsWinWMIReconRunningProcessOrSrvcs") as alertPriority
```

## SecOpsWinWmiScriptExecution

**Summary:** Detects the WMI standard event consumer launching a script. Validate the running script as this is a rare occurrence in Windows environments.

**MITRE:** Tactics: Execution (TA0002) | Techniques: Command and Scripting Interpreter (T1059)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.all.win
where event_id = 4688 and toktains(message, "scrcons.exe")
where `or`(endswith(process_name, "scrcons.exe"), endswith(new_process_name, "scrcons.exe"), endswith(parent_process_name, "scrcons.exe"))
group every 5m by subject_security_id, subject_username, subject_logon_id, subject_domain, machine, machine_ip, device, client
, target_security_id, target_username, target_logon_id, target_domain, parent_process_name
, new_pid, new_process_name, token_elevation_type, mandatory_label, process_command_line
//Entity Mapping Section
select str(machine_ip) as entity_sourceIP
select machine as entity_sourceHostname
select subject_username as entity_sourceAccount
select subject_domain as entity_sourceDomain
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceDomain) as entity_sourceDomain_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceIP) as entity_sourceIP_AssetRole
//<filtering_section>
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsWinWmiScriptExecution") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsWinWmiScriptExecution") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsWinWmiScriptExecution") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsWinWmiScriptExecution") as alertPriority
```

## SecOpsWinWmiTemporaryEventSubscription

**Summary:** WMI can be used to install event filters, providers, consumers, and bindings that execute code when a defined event occurs. WMI subscription execution is proxied by the process WmiPrvSe.exe and may result in elevated SYSTEM privileges.

**MITRE:** Tactics: Execution (TA0002) | Techniques: Windows Management Instrumentation (T1047)

**Tables:** box.all.win

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.all.win
where source = "box.win_winlogbeat" and eq(str(event_id), "5860")
select str(jqeval(jqcompile(".winlog.user_data.Query"), jsonparse(rawMessage))) as current_query
select jqeval(jqcompile(".host.ip"), jsonparse(rawMessage)) as all_machine_ips
select computer_name as entity_sourceHostname
select username as entity_sourceAccount
where not eq(current_query, "SELECT * FROM Win32_ProcessStartTrace WHERE ProcessName = 'wsmprovhost.exe'") and not eq(current_query, "SELECT * FROM __InstanceOperationEvent WHERE TargetInstance ISA 'AntiVirusProduct' OR TargetInstance ISA 'FirewallProduct' OR TargetInstance ISA 'AntiSpywareProduct'")
group every 5m by source, event_id, entity_sourceHostname, all_machine_ips, entity_sourceAccount, current_query, device, client
every 5m
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole // Get asset role from SecOpsRole Lookup
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole // Get asset role from SecOpsRole Lookup
//<filtering_section>
select lu("SecOpsAlertDescription", "alertType", "SecOpsWinWmiTemporaryEventSubscription") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsWinWmiTemporaryEventSubscription") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsWinWmiTemporaryEventSubscription") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsWinWmiTemporaryEventSubscription") as alertPriority
```
