# Detection library: LINUX

Linux/Unix host detections (box.unix, auth.unix). Source: Devo "Query and alert library" (docs.devo.com). Queries are verbatim from the docs; `lu(...)` enrichments need the lookups listed in INDEX.md.

Detections (52):

- SecOpsLinuxAbMaliciousExecution
- SecOpsLinuxAddFilestoCrontabDir
- SecOpsLinuxAppendCommandToProfileConfig
- SecOpsLinuxAppendCronjobEntry
- SecOpsLinuxAudioCapture
- SecOpsLinuxAuditdMaxFailedLoginAttempts
- SecOpsLinuxBashShellProfileMod
- SecOpsLinuxClipboardCopyXclip
- SecOpsLinuxCommandExecutionWebUser
- SecOpsLinuxCompressEncryptData
- SecOpsLinuxCurlExecution
- SecOpsLinuxDeletionofService
- SecOpsLinuxDeletionofSslCert
- SecOpsLinuxDeletionSSHKey
- SecOpsLinuxDoasConfigCreate
- SecOpsLinuxDoasToolExec
- SecOpsLinuxExtNetworkviaTelnet
- SecOpsLinuxFileCreateInitBoot
- SecOpsLinuxFileCreateProfile
- SecOpsLinuxFileDDOverwrite
- SecOpsLinuxFileOwnerNowRoot
- SecOpsLinuxHiddenFilesCreated
- SecOpsLinuxHighFileDeletesEtc
- SecOpsLinuxHijackLibraryCalls
- SecOpsLinuxInitDaemonDeletion
- SecOpsLinuxInsertKernelInsmod
- SecOpsLinuxInstallKernelModprobe
- SecOpsLinuxIntNetworkviaTelnet
- SecOpsLinuxIrregularLogin
- SecOpsLinuxIrregularLoginSsh
- SecOpsLinuxMaxSessionsPerUser
- SecOpsLinuxNcUseDetected
- SecOpsLinuxNOPASSWDSudoers
- SecOpsLinuxPamdKeylogging
- SecOpsLinuxPhpServerStarted
- SecOpsLinuxPotentialDisableSELinux
- SecOpsLinuxPythonServerStarted
- SecOpsLinuxRdpMountShare
- SecOpsLinuxRestrictedShellBreakoutSSH
- SecOpsLinuxRubyHttpServerStarted
- SecOpsLinuxSCPDetect
- SecOpsLinuxSetuidUsingChmod
- SecOpsLinuxSetuiSecapUtility
- SecOpsLinuxSshAuthKeyModification
- SecOpsLinuxStrangeProcessExec
- SecOpsLinuxSudoFileModification
- SecOpsLinuxSuspciousExecutionCommand
- SecOpsLinuxSvcEnabled
- SecOpsLinuxSvcFileCreated
- SecOpsLinuxSystemLogFileDeletion
- SecOpsLinuxWebserverAccessLogsDeleted
- SecOpsLinuxWgetUseDetected

## SecOpsLinuxAbMaliciousExecution

**Summary:** Detects a potentially malicious Ab execution.

**Description:** Detected use of ab command on $entity_sourceHostname with ip $entity_sourceIp. Audit message: $message

**MITRE:** Tactics: Command and Control (TA0011), Exfiltration (TA0010) | Techniques: Ingress Tool Transfer (T1105), Exfiltration Over Alternative Protocol (T1048)

**Tables:** box.unix

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.unix
where toktains(message, "type=EXECVE")
where toktains(message,"ab\"",true,true)
where toktains(message,"\"-p\"",true,true) or weaktoktains(message,"\"http",true,true)
group every 5m by machine,machineIp,message, client
every 5m
//Entity Mapping Section
select machine as entity_sourceHostname
select str(machineIp) as entity_sourceIp
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceIp) as entity_sourceIp_AssetRole
//<filtering_section>
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsLinuxAbMaliciousExecution") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsLinuxAbMaliciousExecution") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsLinuxAbMaliciousExecution") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsLinuxAbMaliciousExecution") as alertPriority
```

## SecOpsLinuxAddFilestoCrontabDir

**Summary:** Detects potentially suspicious file creation in cron table directories.

**MITRE:** Tactics: Privilege Escalation (TA0004) | Techniques: Scheduled Task/Job (T1053)

**Tables:** box.unix

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.unix
where toktains(message, "nametype=CREATE"),
toktains(message, "/etc/cron") or
toktains(message, "/etc/anacrontab") or
toktains(message, "/var/spool/cron")
select mode as usercol1
where ne(mode, "010060") as usrcol1
select ouid as UID,
name as filemod,
appName as CronCreated
group every 5m by machine, machineIp, facility, level, application, message, UID, CronCreated, client
every 5m
//Entity Mapping Section
select machine as entity_sourceHostname
select str(machineIp) as entity_sourceIp
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceIp) as entity_sourceIp_AssetRole
//<filtering_section>
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsLinuxAddFilestoCrontabDir") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsLinuxAddFilestoCrontabDir") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsLinuxAddFilestoCrontabDir") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsLinuxAddFilestoCrontabDir") as alertPriority
```

## SecOpsLinuxAppendCommandToProfileConfig

**Summary:** Detects command-line functions that relate to modifying user account files to run scripts on machine reboot.

**MITRE:** Tactics: Privilege Escalation (TA0004) | Techniques: Event Triggered Execution (T1546)

**Tables:** box.unix

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.unix
where toktains(message, "nametype=CREATE"),
toktains(message, ".bashrc\"") or
toktains(message, ".bash_profile\"") or
toktains(message, "/etc/profile") or
toktains(message, ".bash_login\"") or
toktains(message, ".profile\"") or
toktains(message, ".bash_logout\"")
select ouid as UID,
name as filemod
select split(filemod, " ", 0) as ProfileFileMod
group every 5m by machine, machineIp, facility, level, application, ProfileFileMod, UID, message, client
every 5m
//Entity Mapping Section
select machine as entity_sourceHostname
select str(machineIp) as entity_sourceIp
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceIp) as entity_sourceIp_AssetRole
//<filtering_section>
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsLinuxAppendCommandToProfileConfig") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsLinuxAppendCommandToProfileConfig") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsLinuxAppendCommandToProfileConfig") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsLinuxAppendCommandToProfileConfig") as alertPriority
```

## SecOpsLinuxAppendCronjobEntry

**Summary:** Detects appends to existing cronjob files.

**MITRE:** Tactics: Privilege Escalation (TA0004) | Techniques: Scheduled Task/Job (T1053)

**Tables:** box.unix

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.unix
where
toktains(message, "nametype=NORMAL"),
toktains(message, "item=1"),
toktains(message, "/var/spool/cron/") or
toktains(message, "/etc/cron.") or
toktains(message, "/etc/anacrontab")
select peek(message, re("name=(.+ )"), 1) as file
select split(file, " ", 0) as cronTabAppended
group every 5m by machine, machineIp, facility, level, application, message, cronTabAppended, client
every 5m
//Entity Mapping Section
select machine as entity_sourceHostname
select str(machineIp) as entity_sourceIp
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceIp) as entity_sourceIp_AssetRole
//<filtering_section>
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsLinuxAppendCronjobEntry") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsLinuxAppendCronjobEntry") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsLinuxAppendCronjobEntry") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsLinuxAppendCronjobEntry") as alertPriority
```

## SecOpsLinuxAudioCapture

**Summary:** Detects attempts to record audio with a record utility.

**Description:** Detects attempts of recording audio using arecord tool on $srcHost with ip $machineIp. This activity should be reviewed to determine that this execution is not malicious. Audit message: $message

**MITRE:** Tactics: Collection (TA0009) | Techniques: Audio Capture (T1123)

**Tables:** box.unix

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.unix
where eq(auditType, "EXECVE")
where toktains(message,"arecord\"",true,true)
where toktains(message,"-f\"",true,true) or toktains(message,"-format=",true,true) or toktains(message,"-fdat",true,true)
group every 5m by machine,machineIp,message, client
every 5m
//Entity Mapping Section
select machine as entity_sourceHostname
select str(machineIp) as entity_sourceIp
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceIp) as entity_sourceIp_AssetRole
//<filtering_section>
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsLinuxAudioCapture") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsLinuxAudioCapture") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsLinuxAudioCapture") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsLinuxAudioCapture") as alertPriority
```

## SecOpsLinuxAuditdMaxFailedLoginAttempts

**Summary:** Detects the maximum number of failed login attempts for a user on a Linux host.

**MITRE:** Tactics: Initial Access (TA0001) | Techniques: Valid Accounts (T1078)

**Tables:** box.unix

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.unix
where toktains(message, "PAM 2 more authentication failures")
select user as username
group every 5m by machine, machineIp, facility, level, appName, processId, message, username, client
every 5m
//Entity Mapping Section
select machine as entity_sourceHostname
select str(machineIp) as entity_sourceIp
select username as entity_sourceAccount
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceIp) as entity_sourceIp_AssetRole
//<filtering_section>
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsLinuxAuditdMaxFailedLoginAttempts") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsLinuxAuditdMaxFailedLoginAttempts") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsLinuxAuditdMaxFailedLoginAttempts") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsLinuxAuditdMaxFailedLoginAttempts") as alertPriority
```

## SecOpsLinuxBashShellProfileMod

**Summary:** Detects when modifications are made to a bash shell profile. Bash shell profiles could be modified to execute malicious scripts on machine reboot, or whenever a user logs into the machine.

**MITRE:** Tactics: Persistence (TA0003) | Techniques: Boot or Logon Initialization Scripts (T1037)

**Tables:** box.unix

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.unix
select ouid as OUID
where toktains(message, " nametype=CREATE")
where toktains(message, ".bashrc") or toktains(message, ".profile") or toktains(message, ".bash_profile ") or toktains(message, "rc.local") or toktains(message, ".profile1") or toktains(message, ".bash_profile1") or toktains(message, ".zshenv")
group every 5m by OUID, machine, machineIp, facility, level, application, message, client
every 5m
//Entity Mapping Section
select machine as entity_sourceHostname
select str(machineIp) as entity_sourceIp
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceIp) as entity_sourceIp_AssetRole
//<filtering_section>
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsLinuxBashShellProfileMod") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsLinuxBashShellProfileMod") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsLinuxBashShellProfileMod") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsLinuxBashShellProfileMod") as alertPriority
```

## SecOpsLinuxClipboardCopyXclip

**Summary:** Detects attempts to collect data from the clipboard using xclip tool.

**Description:** Detects attempts of collecting data from the clipboard using xclip tool on $srcHost with ip $machineIp by user $subjectUsername. This activity should be reviewed. Audit message: $message

**MITRE:** Tactics: Collection (TA0009) | Techniques: Clipboard Data (T1115)

**Tables:** box.unix

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.unix
where eq(auditType, "EXECVE")
where toktains(message,"xclip\"",true,true) and (toktains(message,"\"-selection\"",true,true) or toktains(message,"\"-sel\"",true,true)) and (toktains(message,"\"clipboard\"",true,true) or toktains(message,"\"clip\"",true,true))
group every 5m by machine,machineIp,message,user,client
every 5m
//Entity Mapping Section
select machine as entity_sourceHostname
select str(machineIp) as entity_sourceIp
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceIp) as entity_sourceIp_AssetRole
//<filtering_section>
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsLinuxClipboardCopyXclip") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsLinuxClipboardCopyXclip") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsLinuxClipboardCopyXclip") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsLinuxClipboardCopyXclip") as alertPriority
```

## SecOpsLinuxCommandExecutionWebUser

**Summary:** Detects possible command execution by a web application/web shell.

**Description:** Rules like the following should be added to the audit.rules file in order to track this events: -a always, exit -F arch=b32 -S execve -F euid=33 -k detect_execve_www. 33 is the common uid of a www-data user.

**MITRE:** Tactics: Persistence (TA0003) | Techniques: Server Software Component (T1505)

**Tables:** box.unix

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.unix
where eq(auditType, "SYSCALL")
where eq(uid,33)
where weaktoktains(message,"SYSCALL=execve",true,true)
group every 5m by machine,machineIp,message,uid, client
every 5m
//Entity Mapping Section
select machine as entity_sourceHostname
select str(machineIp) as entity_sourceIp
select str(uid) as entity_sourceAccount
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceIp) as entity_sourceIp_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole
//<filtering_section>
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsLinuxCommandExecutionWebUser") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsLinuxCommandExecutionWebUser") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsLinuxCommandExecutionWebUser") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsLinuxCommandExecutionWebUser") as alertPriority
```

## SecOpsLinuxCompressEncryptData

**Summary:** Detects a potentially malicious command that could be compressing and/or encrypting data on the host.

**Description:** Detected a potentially malicious execution of a command trying to compress or encrypt data on $srcHost with ip $machineIp by user $user. This activity should be reviewed to determine that this execution is not malicious. Audit message: $message

**MITRE:** Tactics: Collection (TA0009) | Techniques: Archive Collected Data (T1560)

**Tables:** box.unix

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.unix
where eq(auditType, "EXECVE")
where toktains(message,"zip\"",true,true) or toktains(message,"gzip\"",true,true) or toktains(message,"gunzip\"",true,true) or toktains(message,"tar\"",true,true)
group every 5m by machine,machineIp,message,user,client
every 5m
//Entity Mapping Section
select machine as entity_sourceHostname
select str(machineIp) as entity_sourceIp
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceIp) as entity_sourceIp_AssetRole
//<filtering_section>
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsLinuxCompressEncryptData") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsLinuxCompressEncryptData") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsLinuxCompressEncryptData") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsLinuxCompressEncryptData") as alertPriority
```

## SecOpsLinuxCurlExecution

**Summary:** Detects a potentially malicious Curl execution. This could indicate that an attacker could be trying to exfiltrate from or download a file to the target machine.

**Description:** Detected use of curl command on $entity_sourceHostname with ip $entity_sourceIp. Audit message: $message

**MITRE:** Tactics: Command and Control (TA0011), Exfiltration (TA0010) | Techniques: Ingress Tool Transfer (T1105), Exfiltration Over Alternative Protocol (T1048)

**Tables:** box.unix

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.unix
where toktains(message, "type=EXECVE")
where weaktoktains(message,"curl\"",true,true)
where weaktoktains(message,"http",true,true) or weaktoktains(message,"ftp",true,true)
where weaktoktains(message,"\"-o\"",true,true) or weaktoktains(message,"\"POST\"",true,true) or weaktoktains(message,"\"PUT\"",true,true) or weaktoktains(message,"\"-d\"",true,true) or weaktoktains(message,"\"-F\"",true,true)
group every 5m by machine,machineIp,message, client
every 5m
//Entity Mapping Section
select machine as entity_sourceHostname
select str(machineIp) as entity_sourceIp
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceIp) as entity_sourceIp_AssetRole
//<filtering_section>
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsLinuxCurlExecution") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsLinuxCurlExecution") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsLinuxCurlExecution") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsLinuxCurlExecution") as alertPriority
```

## SecOpsLinuxDeletionofService

**Summary:** Detects deletion of services on a Linux machine.

**MITRE:** Tactics: Impact (TA0040) | Techniques: Data Destruction (T1485)

**Tables:** box.unix

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.unix
where toktains(message, "nametype=DELETE"),
toktains(message, ".service"),
toktains(message, "/etc/systemd/") or
toktains(message, "/usr/lib/systemd/")
select peek(message, re("name=(.+ )"), 1) as namemsg
select split(namemsg, "\"",1) as serviceDeleted
group every 5m by machine, machineIp, facility, level, application, message, serviceDeleted, client
every 5m
//Entity Mapping Section
select machine as entity_sourceHostname
select str(machineIp) as entity_sourceIp
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceIp) as entity_sourceIp_AssetRole
//<filtering_section>
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsLinuxDeletionofService") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsLinuxDeletionofService") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsLinuxDeletionofService") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsLinuxDeletionofService") as alertPriority
```

## SecOpsLinuxDeletionofSslCert

**Summary:** Detects deletion of SSL certificate on Linux host. Deletion of an SSL certificate could indicate a compromised Linux machine.

**MITRE:** Tactics: Impact (TA0040) | Techniques: Data Destruction (T1485)

**Tables:** box.unix

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.unix
where toktains(message, "nametype=DELETE")
select peek(message, re("name=(.+ )"), 1) as Peak
select split(Peak, " ", 0) as FileName
where toktains(FileName, ".crt") or toktains(FileName, ".pem")
group every 5m by FileName, machine, machineIp, facility, application, level, message, client
every 5m
//Entity Mapping Section
select machine as entity_sourceHostname
select str(machineIp) as entity_sourceIp
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceIp) as entity_sourceIp_AssetRole
//<filtering_section>
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsLinuxDeletionofSslCert") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsLinuxDeletionofSslCert") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsLinuxDeletionofSslCert") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsLinuxDeletionofSslCert") as alertPriority
```

## SecOpsLinuxDeletionSSHKey

**Summary:** Detects the deletion of SSH Key.

**MITRE:** Tactics: Impact (TA0040) | Techniques: Data Destruction (T1485)

**Tables:** box.unix

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.unix
where toktains(message, "nametype=DELETE")
where toktains(message, "/etc/ssh")
group every 5m by machine, machineIp, facility, level, application, message, client
every 5m
//Entity Mapping Section
select machine as entity_sourceHostname
select str(machineIp) as entity_sourceIp
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceIp) as entity_sourceIp_AssetRole
//<filtering_section>
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsLinuxDeletionSSHKey") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsLinuxDeletionSSHKey") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsLinuxDeletionSSHKey") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsLinuxDeletionSSHKey") as alertPriority
```

## SecOpsLinuxDoasConfigCreate

**Summary:** Detects the creation of doas.conf file on Linux host. This allows the use of the doas utility tool, which permits users to execute commands as other accounts.

**MITRE:** Tactics: Privilege Escalation (TA0004) | Techniques: Abuse Elevation Control Mechanism (T1548)

**Tables:** box.unix

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.unix
where toktains(message, "nametype=CREATE"),
toktains(message, "/etc/doas.conf")
select ouid as UID
select name as conf
select split(conf, " ", 0) as doasFileCreated
group every 5m by machine, machineIp, level, application,UID,doasFileCreated, message, client
every 5m
//Entity Mapping Section
select machine as entity_sourceHostname
select str(machineIp) as entity_sourceIp
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceIp) as entity_sourceIp_AssetRole
//<filtering_section>
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsLinuxDoasConfigCreate") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsLinuxDoasConfigCreate") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsLinuxDoasConfigCreate") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsLinuxDoasConfigCreate") as alertPriority
```

## SecOpsLinuxDoasToolExec

**Summary:** Detects the use of the doas tool. Doas allows users to run commands as another account, commonly used for root privileges.

**MITRE:** Tactics: Privilege Escalation (TA0004) | Techniques: Abuse Elevation Control Mechanism (T1548)

**Tables:** box.unix

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.unix
where toktains(message, "\"doas\"")
where toktains(message, "type=EXECVE")
group every 5m by machine, machineIp, facility, level, application, message, client
every 5m
//Entity Mapping Section
select machine as entity_sourceHostname
select str(machineIp) as entity_sourceIp
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceIp) as entity_sourceIp_AssetRole
//<filtering_section>
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsLinuxDoasToolExec") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsLinuxDoasToolExec") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsLinuxDoasToolExec") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsLinuxDoasToolExec") as alertPriority
```

## SecOpsLinuxExtNetworkviaTelnet

**Summary:** Detects connections to an external network via Telnet.

**MITRE:** Tactics: Lateral Movement (TA0008) | Techniques: Remote Services (T1021)

**Tables:** box.unix

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.unix
where toktains(message,"Telnet")
select peek(message, re("SRC=(.+ )"), 1) as ip
select ip4(split(ip, " ", 0)) as srcIP,
ispublic(srcIP) as PublicIP
where PublicIP = true
group every 5m by machine, machineIp, facility, level, application, message, srcIP, PublicIP, client
every 5m
//Entity Mapping Section
select machine as entity_sourceHostname
select str(srcIP) as entity_sourceIp
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceIp) as entity_sourceIp_AssetRole
//<filtering_section>
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsLinuxExtNetworkviaTelnet") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsLinuxExtNetworkviaTelnet") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsLinuxExtNetworkviaTelnet") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsLinuxExtNetworkviaTelnet") as alertPriority
```

## SecOpsLinuxFileCreateInitBoot

**Summary:** Detects file creation in init system directories. File creation in these directories can be used for script execution on machine boot.

**MITRE:** Tactics: Privilege Escalation (TA0004) | Techniques: Boot or Logon Initialization Scripts (T1037)

**Tables:** box.unix

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.unix
where toktains(message, "nametype=CREATE"),
toktains(message, "name=\"/etc/init.d/") or
toktains(message, "name=\"/etc/rc.d/") or
toktains(message, "name=\"/sbin/init.d/")or
toktains(message, "name=\"/etc/rc.local/")
select peek(message, re("name=(.+ )"), 1) as namemsg
select split(namemsg, " ", 0) as initScriptCreated
group every 5m by machine, machineIp, facility, level, message, initScriptCreated, client
every 5m
//Entity Mapping Section
select machine as entity_sourceHostname
select str(machineIp) as entity_sourceIp
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceIp) as entity_sourceIp_AssetRole
//<filtering_section>
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsLinuxFileCreateInitBoot") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsLinuxFileCreateInitBoot") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsLinuxFileCreateInitBoot") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsLinuxFileCreateInitBoot") as alertPriority
```

## SecOpsLinuxFileCreateProfile

**Summary:** Detects file creation in /etc/profile.d directory. Files created here can automatically execute scripts on the boot up of the machine.

**MITRE:** Tactics: Privilege Escalation (TA0004) | Techniques: Event Triggered Execution (T1546)

**Tables:** box.unix

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.unix
where toktains(message, "nametype=CREATE"),
toktains(message, "name=\"/etc/profile.d/")
select user as username,
ouid as UID,
name as file,
split(file, " ", 0) as ProfileFileCreated
group every 5m by machine, machineIp, facility, level, UID, ProfileFileCreated, message, client
every 5m
//Entity Mapping Section
select machine as entity_sourceHostname
select str(machineIp) as entity_sourceIp
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceIp) as entity_sourceIp_AssetRole
//<filtering_section>
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsLinuxFileCreateProfile") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsLinuxFileCreateProfile") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsLinuxFileCreateProfile") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsLinuxFileCreateProfile") as alertPriority
```

## SecOpsLinuxFileDDOverwrite

**Summary:** Detects for the dd command being used to overwrite a file. This is a powerful tool that can be abused for data destruction purposes, and could potentially render data irrecoverable.

**MITRE:** Tactics: Impact (TA0040) | Techniques: Data Destruction (T1485)

**Tables:** box.unix

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.unix
where toktains(message, "dd") and toktains(message, "of=")
group every 5m by machine, machineIp, facility, level, application, message, srcUser, client
every 5m
//Entity Mapping Section
select machine as entity_sourceHostname
select str(machineIp) as entity_sourceIp
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceIp) as entity_sourceIp_AssetRole
//<filtering_section>
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsLinuxFileDDOverwrite") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsLinuxFileDDOverwrite") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsLinuxFileDDOverwrite") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsLinuxFileDDOverwrite") as alertPriority
```

## SecOpsLinuxFileOwnerNowRoot

**Summary:** Detected the file owner being changed to root using the chown command.

**MITRE:** Tactics: Defense Evasion (TA0005) | Techniques: File and Directory Permissions Modification (T1222)

**Tables:** box.all.unix

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.all.unix
where weaktoktains(command, "chown") and weaktoktains(user, "root")
group every 5m by machine, rhost_string, source_ip, user, command, client
//Entity Mapping Section
select rhost_string as entity_sourceHostname
select str(source_ip) as entity_sourceIp
select user as entity_sourceAccount
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceIp) as entity_sourceIp_AssetRole
//<filtering_section>
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsLinuxFileOwnerNowRoot") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsLinuxFileOwnerNowRoot") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsLinuxFileOwnerNowRoot") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsLinuxFileOwnerNowRoot") as alertPriority
```

## SecOpsLinuxHiddenFilesCreated

**Summary:** Detects for creation of files or folders that begin with "." or "/." by a user. This could indicate an attacker attempting to hide files on the system that are easily overlooked. [NOTICE] Requires the auditing of 'execve'.

**MITRE:** Tactics: Defense Evasion (TA0005) | Techniques: Hide Artifacts (T1564)

**Tables:** box.unix

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.unix
where toktains(message, "type=EXECVE"),
toktains (message, "/.")or
toktains (message,"a1=\".")
select peek(message, re(" a1=\"(.+)"), 1) as hiddenFileOrDirectory
group every 5m by machine, machineIp, facility, level, application, message, hiddenFileOrDirectory, client
every 5m
//Entity Mapping Section
select machine as entity_sourceHostname
select str(machineIp) as entity_sourceIp
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceIp) as entity_sourceIp_AssetRole
//<filtering_section>
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsLinuxHiddenFilesCreated") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsLinuxHiddenFilesCreated") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsLinuxHiddenFilesCreated") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsLinuxHiddenFilesCreated") as alertPriority
```

## SecOpsLinuxHighFileDeletesEtc

**Summary:** Detects high frequency of file deletion within a small timeframe.

**MITRE:** Tactics: Impact (TA0040) | Techniques: Data Destruction (T1485)

**Tables:** box.unix

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.unix
where toktains(message, "nametype=DELETE"),
toktains(message, "/etc")
group every 45m by machineIp, machine, client
every 45m
select count() as count
where count > 100
//Entity Mapping Section
select machine as entity_sourceHostname
select str(machineIp) as entity_sourceIp
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceIp) as entity_sourceIp_AssetRole
//<filtering_section>
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsLinuxHighFileDeletesEtc") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsLinuxHighFileDeletesEtc") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsLinuxHighFileDeletesEtc") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsLinuxHighFileDeletesEtc") as alertPriority
```

## SecOpsLinuxHijackLibraryCalls

**Summary:** Detects a command that could hijack a library function. This detection looks for the use of LD_PRELOAD command to hijack library functions.

**MITRE:** Tactics: Privilege Escalation (TA0004) | Techniques: Hijack Execution Flow (T1574)

**Tables:** box.unix

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.unix
where message -> "LD_PRELOAD"
group every 5m by machine, machineIp, facility, level, application, message, cmd, client
every 5m
//Entity Mapping Section
select machine as entity_sourceHostname
select str(machineIp) as entity_sourceIp
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceIp) as entity_sourceIp_AssetRole
//<filtering_section>
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsLinuxHijackLibraryCalls") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsLinuxHijackLibraryCalls") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsLinuxHijackLibraryCalls") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsLinuxHijackLibraryCalls") as alertPriority
```

## SecOpsLinuxInitDaemonDeletion

**Summary:** Detects deletion of init daemon script in Linux. Deletion of daemon scripts could be used to disable security features on a Linux machine.

**MITRE:** Tactics: Impact (TA0040) | Techniques: Data Destruction (T1485)

**Tables:** box.unix

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.unix
where toktains(message, "nametype=DELETE"),
toktains(message, "name=\"/etc/init.d/")
select peek(message, re("name=(.+ )"), 1) as name3
select split(name3, " ", 0) as ScriptDeleted
group every 5m by machine, machineIp, facility, level, application, message, ScriptDeleted, client
every 5m
//Entity Mapping Section
select machine as entity_sourceHostname
select str(machineIp) as entity_sourceIp
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceIp) as entity_sourceIp_AssetRole
//<filtering_section>
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsLinuxInitDaemonDeletion") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsLinuxInitDaemonDeletion") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsLinuxInitDaemonDeletion") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsLinuxInitDaemonDeletion") as alertPriority
```

## SecOpsLinuxInsertKernelInsmod

**Summary:** Detects insertion of linux kernel module using insmod utility function. This could indicate the installation of a rootkit or other malicious kernel modules.

**MITRE:** Tactics: Privilege Escalation (TA0004) | Techniques: Boot or Logon Autostart Execution (T1547)

**Tables:** box.unix

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.unix
where weaktoktains(message, "COMMAND=/usr/sbin/insmod")
group every 5m by machine, machineIp, facility, level, application, appName, cmd, action, user, message, client
every 5m
//Entity Mapping Section
select machine as entity_sourceHostname
select str(machineIp) as entity_sourceIp
select user as entity_sourceAccount
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceIp) as entity_sourceIp_AssetRole
//<filtering_section>
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsLinuxInsertKernelInsmod") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsLinuxInsertKernelInsmod") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsLinuxInsertKernelInsmod") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsLinuxInsertKernelInsmod") as alertPriority
```

## SecOpsLinuxInstallKernelModprobe

**Summary:** Detects installation of a Linux kernel module using modprobe utility function.

**MITRE:** Tactics: Privilege Escalation (TA0004) | Techniques: Boot or Logon Autostart Execution (T1547)

**Tables:** box.unix

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.unix
where toktains(rawMessage, "argc=2 a0=\"modprobe\" a1=\"")
select peek(message, re("-")) as Argument
where isnull(Argument)
select peek(rawMessage, re("a1=\"(.+)"), 1) as ModuleInstalled
group every 5m by machine, machineIp, facility, level, application, message, ModuleInstalled, client
every 5m
//Entity Mapping Section
select machine as entity_sourceHostname
select str(machineIp) as entity_sourceIp
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceIp) as entity_sourceIp_AssetRole
//<filtering_section>
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsLinuxInstallKernelModprobe") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsLinuxInstallKernelModprobe") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsLinuxInstallKernelModprobe") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsLinuxInstallKernelModprobe") as alertPriority
```

## SecOpsLinuxIntNetworkviaTelnet

**Summary:** Detects connections to an internal network via Telnet.

**MITRE:** Tactics: Lateral Movement (TA0008) | Techniques: Remote Services (T1021)

**Tables:** box.unix

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.unix
where toktains(message,"Telnet")
select peek(message, re("SRC=(.+ )"), 1) as ip
select ip4(split(ip, " ", 0)) as srcIP,
isprivate(srcIP) as PrivateIP
where PrivateIP = true
group every 5m by machine, machineIp, facility, level, application, message, srcIP, PrivateIP, client
every 5m
//Entity Mapping Section
select machine as entity_sourceHostname
select str(srcIP) as entity_sourceIp
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceIp) as entity_sourceIp_AssetRole
//<filtering_section>
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsLinuxIntNetworkviaTelnet") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsLinuxIntNetworkviaTelnet") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsLinuxIntNetworkviaTelnet") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsLinuxIntNetworkviaTelnet") as alertPriority
```

## SecOpsLinuxIrregularLogin

**Summary:** Detects attempted login at a forbidden time.

**MITRE:** Tactics: Initial Access (TA0001) | Techniques: Valid Accounts (T1078)

**Tables:** box.unix

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.unix
where toktains (message, "pam_unix(gdm-password:session): session opened for")
select dayofweek(eventdate, "8") as Day
select hour(eventdate) as Hour
where Day = 0 or Day = 6 or Hour < 7 or Hour >= 18
select dayname(eventdate) as DayofTheWeek
group every 5m by machine, machineIp, facility, level, application, message, action, user, Hour, DayofTheWeek, client
every 5m
//Entity Mapping Section
select machine as entity_sourceHostname
select str(machineIp) as entity_sourceIp
select user as entity_sourceAccount
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceIp) as entity_sourceIp_AssetRole
//<filtering_section>
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsLinuxIrregularLogin") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsLinuxIrregularLogin") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsLinuxIrregularLogin") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsLinuxIrregularLogin") as alertPriority
```

## SecOpsLinuxIrregularLoginSsh

**Summary:** Detects attempted login at a forbidden time.

**MITRE:** Tactics: Initial Access (TA0001) | Techniques: Valid Accounts (T1078)

**Tables:** auth.unix

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from auth.unix
where application = "ssh",
action = "LOGIN"
select dayofweek(eventdate, "8") as Day
select hour(eventdate) as Hour
where Day = 0 or Day = 6 or Hour < 7 or Hour >= 18
select dayname(eventdate) as DayofTheWeek
group every 5m by machine, user, action, application, source_ip, message, Hour, DayofTheWeek, client
every 5m
//Entity Mapping Section
select machine as entity_sourceHostname
select source_ip as entity_sourceIp
select user as entity_sourceAccount
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceIp) as entity_sourceIp_AssetRole
//<filtering_section>
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsLinuxIrregularLoginSsh") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsLinuxIrregularLoginSsh") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsLinuxIrregularLoginSsh") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsLinuxIrregularLoginSsh") as alertPriority
```

## SecOpsLinuxMaxSessionsPerUser

**Summary:** Detects whenever a user reaches the maximum number of login sessions.

**MITRE:** Tactics: Initial Access (TA0001) | Techniques: Valid Accounts (T1078)

**Tables:** box.unix

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.unix
select user as username
where toktains(message, "Too many logins")
group every 5m by username, machine, machineIp, facility, level, application, processId, message, client
every 5m
//Entity Mapping Section
select machine as entity_sourceHostname
select str(machineIp) as entity_sourceIp
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceIp) as entity_sourceIp_AssetRole
//<filtering_section>
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsLinuxMaxSessionsPerUser") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsLinuxMaxSessionsPerUser") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsLinuxMaxSessionsPerUser") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsLinuxMaxSessionsPerUser") as alertPriority
```

## SecOpsLinuxNcUseDetected

**Summary:** Detects a potentially malicious Nc execution.

**Description:** Detected use of nc command on $entity_sourceHostname with ip $entity_sourceIp. Audit message: $message

**MITRE:** Tactics: Command and Control (TA0011), Exfiltration (TA0010), Execution (TA0002) | Techniques: Ingress Tool Transfer (T1105), Exfiltration Over Alternative Protocol (T1048), Command and Scripting Interpreter (T1059)

**Tables:** box.unix

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.unix
where toktains(message, "type=EXECVE")
where weaktoktains(message,"nc\"",true,true) or weaktoktains(message,"netcat\"",true,true) or weaktoktains(message,"ncat\"",true,true)
where (weaktoktains(message,"\"-e",true,true) and (weaktoktains(message,"sh",true,true) or weaktoktains(message,"bash",true,true) or weaktoktains(message,"zsh",true,true) or weaktoktains(message,"csh",true,true) or weaktoktains(message,"ksh",true,true))) or (weaktoktains(message,"<",true,true) or weaktoktains(message,">",true,true))
group every 5m by machine,machineIp,message, client
every 5m
//Entity Mapping Section
select machine as entity_sourceHostname
select str(machineIp) as entity_sourceIp
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceIp) as entity_sourceIp_AssetRole
//<filtering_section>
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsLinuxNcUseDetected") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsLinuxNcUseDetected") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsLinuxNcUseDetected") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsLinuxNcUseDetected") as alertPriority
```

## SecOpsLinuxNOPASSWDSudoers

**Summary:** Detects for suspicious command lines that may add an entry to /etc/sudoers with NOPASSWD attribute in Linux platform. This requires auditd installed and configured.

**MITRE:** Tactics: Defense Evasion (TA0005) | Techniques: Abuse Elevation Control Mechanism (T1548)

**Tables:** box.unix

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.unix
where toktains (raw, "NOPASSWD"), toktains (raw,"sudoers")
group every 5m by srcUser, action, user, machine, machineIp, facility, level, application, message, pwd, client
every 5m
//Entity Mapping Section
select machine as entity_sourceHostname
select str(machineIp) as entity_sourceIp
select srcUser as entity_sourceAccount
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_sourceAccount) as entity_sourceAccount_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceIp) as entity_sourceIp_AssetRole
//<filtering_section>
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsLinuxNOPASSWDSudoers") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsLinuxNOPASSWDSudoers") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsLinuxNOPASSWDSudoers") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsLinuxNOPASSWDSudoers") as alertPriority
```

## SecOpsLinuxPamdKeylogging

**Summary:** Detects audit enablement of TTY input leveraging Pam.d tool.

**Description:** Detected audit enablement of TTY input leveraging Pam.d tool on $srcHost with ip $machineIp. This activity should be reviewed to determine that this execution is not malicious. Audit message: $message

**MITRE:** Tactics: Collection (TA0009) | Techniques: Clipboard Data (T1115)

**Tables:** box.unix

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.unix
where (eq(auditType, "TTY") or eq(auditType, "USER_TTY")) or (eq(auditType, "PATH") and ( toktains(message,"/etc/pam.d/system-auth",true,true) or toktains(message,"/etc/pam.d/password-auth",true,true)))
group every 5m by machine,machineIp,message, client
every 5m
//Entity Mapping Section
select machine as entity_sourceHostname
select str(machineIp) as entity_sourceIp
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceIp) as entity_sourceIp_AssetRole
//<filtering_section>
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsLinuxPamdKeylogging") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsLinuxPamdKeylogging") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsLinuxPamdKeylogging") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsLinuxPamdKeylogging") as alertPriority
```

## SecOpsLinuxPhpServerStarted

**Summary:** Detects the initialization of a PHP Http server. This could indicate that an attacker could be trying to exfiltrate files from the target machine.

**Description:** Detected initialization of a PHP Http server on $entity_sourceHostname with ip $entity_sourceIp. Audit message: $message

**MITRE:** Tactics: Exfiltration (TA0010) | Techniques: Exfiltration Over Alternative Protocol (T1048)

**Tables:** box.unix

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.unix
where toktains(message, "type=EXECVE")
where weaktoktains(message,"php\"",true,true)
where toktains(message,"\"-S\"",true,true)
group every 5m by machine,machineIp,message, client
every 5m
//Entity Mapping Section
select machine as entity_sourceHostname
select str(machineIp) as entity_sourceIp
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceIp) as entity_sourceIp_AssetRole
//<filtering_section>
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsLinuxPhpServerStarted") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsLinuxPhpServerStarted") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsLinuxPhpServerStarted") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsLinuxPhpServerStarted") as alertPriority
```

## SecOpsLinuxPotentialDisableSELinux

**Summary:** Potential attempt to disable Security-Enhanced Linux (SELinux)

**MITRE:** Tactics: Defense Evasion (TA0005) | Techniques: Impair Defenses (T1562)

**Tables:** box.unix

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.unix
where toktains(message, "type=EXECVE"),
toktains(message, "a0=\"setenforce\" a1=\"0\"")
group every 5m by machine, machineIp, facility, level, application, message, client
every 5m
//Entity Mapping Section
select machine as entity_sourceHostname
select str(machineIp) as entity_sourceIp
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceIp) as entity_sourceIp_AssetRole
//<filtering_section>
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsLinuxPotentialDisableSELinux") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsLinuxPotentialDisableSELinux") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsLinuxPotentialDisableSELinux") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsLinuxPotentialDisableSELinux") as alertPriority
```

## SecOpsLinuxPythonServerStarted

**Summary:** Detects the initialization of a Python simple server. This could indicate that an attacker could be trying to exfiltrate files from to the target machine.

**Description:** Detected initialization of a python simple server on $entity_sourceHostname with ip $entity_sourceIp. Audit message: $message

**MITRE:** Tactics: Exfiltration (TA0010) | Techniques: Exfiltration Over Alternative Protocol (T1048)

**Tables:** box.unix

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.unix
where toktains(message, "type=EXECVE")
where weaktoktains(message,"python\"",true,true) or weaktoktains(message,"python3\"",true,true) or weaktoktains(message,"python2\"",true,true)
where toktains(message,"\"-m\"",true,true)
where toktains(message,"\"SimpleHTTPServer\"",true,true) or toktains(message,"\"http.server\"",true,true)
group every 5m by machine,machineIp,message, client
every 5m
//Entity Mapping Section
select machine as entity_sourceHostname
select str(machineIp) as entity_sourceIp
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceIp) as entity_sourceIp_AssetRole
//<filtering_section>
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsLinuxPythonServerStarted") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsLinuxPythonServerStarted") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsLinuxPythonServerStarted") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsLinuxPythonServerStarted") as alertPriority
```

## SecOpsLinuxRdpMountShare

**Summary:** Detects a command trying to mount an RDP share. This could indicate that an attacker could be trying to exfiltrate or download files to the target machine.

**Description:** Detected use of curl command on $entity_sourceHostname with ip $entity_sourceIp. Audit message: $message

**MITRE:** Tactics: Command and Control (TA0011), Exfiltration (TA0010) | Techniques: Ingress Tool Transfer (T1105), Exfiltration Over Alternative Protocol (T1048)

**Tables:** box.unix

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.unix
where toktains(message, "type=EXECVE")
where toktains(message,"rdesktop\"",true,true) or toktains(message,"xfreerdp\"",true,true)
where (toktains(message,"\"-r",true,true) and toktains(message,"\"disk:",true,true)) or toktains(message,"\"/drive:",true,true)
group every 5m by machine,machineIp,message, client
every 5m
//Entity Mapping Section
select machine as entity_sourceHostname
select str(machineIp) as entity_sourceIp
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceIp) as entity_sourceIp_AssetRole
//<filtering_section>
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsLinuxRdpMountShare") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsLinuxRdpMountShare") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsLinuxRdpMountShare") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsLinuxRdpMountShare") as alertPriority
```

## SecOpsLinuxRestrictedShellBreakoutSSH

**Summary:** Detects potential Linux binary SSH abuse to break out from restricted environments by spawning an interactive system shell.

**MITRE:** Tactics: Execution (TA0002) | Techniques: Command and Scripting Interpreter (T1059)

**Tables:** box.unix

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.unix
where toktains (message, "type=EXECVE") and
toktains(message, "a0=\"/bin/bash\" a1=\"-c\" a2=\"/bin/sh\"") or
toktains(message, "a0=\"/bin/bash\" a1=\"-c\" a2=\"/bin/bash\"") or
toktains(message, "a0=\"/bin/bash\" a1=\"-c\" a2=\"/bin/dash\"") or
toktains(message, "a0=\"/bin/bash\" a1=\"-c\" a2=\"bash") or
toktains(message, "a0=\"/bin/bash\" a1=\"-c\" a2=\"sh") or
toktains(message, "a0=\"/bin/bash\" a1=\"-c\" a2=\"dash")
group every 5m by machine, machineIp, application, message, appName, client
every 5m
//Entity Mapping Section
select machine as entity_sourceHostname
select str(machineIp) as entity_sourceIp
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceIp) as entity_sourceIp_AssetRole
//<filtering_section>
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsLinuxRestrictedShellBreakoutSSH") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsLinuxRestrictedShellBreakoutSSH") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsLinuxRestrictedShellBreakoutSSH") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsLinuxRestrictedShellBreakoutSSH") as alertPriority
```

## SecOpsLinuxRubyHttpServerStarted

**Summary:** Detects the initialization of a Ruby Http server. This could indicate that an attacker could be trying to exfiltrate files from to the target machine.

**Description:** Detected initialization of a Ruby Http server on $entity_sourceHostname with ip $entity_sourceIp. Audit message: $message

**MITRE:** Tactics: Exfiltration (TA0010) | Techniques: Exfiltration Over Alternative Protocol (T1048)

**Tables:** box.unix

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.unix
where toktains(message, "type=EXECVE")
where weaktoktains(message,"ruby\"",true,true)
where toktains(message,"\"-run\"",true,true) and toktains(message,"\"httpd\"",true,true)
group every 5m by machine,machineIp,message, client
every 5m
//Entity Mapping Section
select machine as entity_sourceHostname
select str(machineIp) as entity_sourceIp
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceIp) as entity_sourceIp_AssetRole
//<filtering_section>
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsLinuxRubyHttpServerStarted") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsLinuxRubyHttpServerStarted") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsLinuxRubyHttpServerStarted") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsLinuxRubyHttpServerStarted") as alertPriority
```

## SecOpsLinuxSCPDetect

**Summary:** Detects a potentially malicious Scp execution. This could indicate that an attacker could be trying to exfiltrate from or download a file to the target machine.

**Description:** Detected use of Scp command on $entity_sourceHostname with ip $entity_sourceIp. Audit message: $message

**MITRE:** Tactics: Command and Control (TA0011), Exfiltration (TA0010) | Techniques: Ingress Tool Transfer (T1105), Exfiltration Over Alternative Protocol (T1048)

**Tables:** box.unix

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.unix
where toktains(message,"type=EXECVE")
where weaktoktains(message,"scp\"",true,true)
where weaktoktains(message,"@",true,true) and toktains(message,":",true,true) and toktains(message,"/",true,true)
group every 5m by machine,machineIp,message, client
every 5m
//Entity Mapping Section
select machine as entity_sourceHostname
select str(machineIp) as entity_sourceIp
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceIp) as entity_sourceIp_AssetRole
//<filtering_section>
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsLinuxSCPDetect") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsLinuxSCPDetect") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsLinuxSCPDetect") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsLinuxSCPDetect") as alertPriority
```

## SecOpsLinuxSetuidUsingChmod

**Summary:** Detects chmod utility execution to enable setuid bit. This bit allows a user to run with the privileges of the owner of the file.

**MITRE:** Tactics: Privilege Escalation (TA0004) | Techniques: Abuse Elevation Control Mechanism (T1548)

**Tables:** box.unix

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.unix
where toktains(message, "a0=\"chmod\"")
where toktains(message, "g+s") or toktains(message, "\"u+s\" ") or toktains(message, "4777") or toktains(message, "\"4577\"")
group every 5m by machine, machineIp, facility, level, application, message, client
every 5m
//Entity Mapping Section
select machine as entity_sourceHostname
select str(machineIp) as entity_sourceIp
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceIp) as entity_sourceIp_AssetRole
//<filtering_section>
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsLinuxSetuidUsingChmod") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsLinuxSetuidUsingChmod") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsLinuxSetuidUsingChmod") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsLinuxSetuidUsingChmod") as alertPriority
```

## SecOpsLinuxSetuiSecapUtility

**Summary:** Detects for suspicious setcap utility execution to enable SUID bit.

**MITRE:** Tactics: Privilege Escalation (TA0004) | Techniques: Abuse Elevation Control Mechanism (T1548)

**Tables:** box.unix

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.unix
where toktains(message, "\"setcap\"")
where toktains(message, "\"cap_setuid+ep\" ") or toktains(message, "\"cap_setuid=ep\"") or toktains(message, "\"cap_net_bind_service+p\"") or toktains(message, "\"cap_net_raw+ep\"") or toktains(message, "\"cap_dac_read_search+ep\"")
group every 5m by machine, machineIp, facility, level, application, message, client
every 5m
//Entity Mapping Section
select machine as entity_sourceHostname
select str(machineIp) as entity_sourceIp
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceIp) as entity_sourceIp_AssetRole
//<filtering_section>
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsLinuxSetuiSecapUtility") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsLinuxSetuiSecapUtility") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsLinuxSetuiSecapUtility") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsLinuxSetuiSecapUtility") as alertPriority
```

## SecOpsLinuxSshAuthKeyModification

**Summary:** Detects modifications made to the Secure Shell authorized_keys file. This file contains a list of public keys that are authorized to log into a server.

**MITRE:** Tactics: Persistence (TA0003) | Techniques: Account Manipulation (T1098)

**Tables:** box.unix

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.unix
where toktains(message, "nametype=CREATE"),
toktains(message, "authorized_keys\"") or
toktains(message, "authorized_keys2")
select peek(message, re("uid=(.+ )"), 1) as name1
select split(name, " ", 0) as UID
select peek(message, re("name=(.+ )"), 1) as auth
select split(auth, " ", 0) as sshAuthorizedKeysModified

group every 5m by machine, machineIp, facility, level, application, message, sshAuthorizedKeysModified, UID, client
every 5m
//Entity Mapping Section
select machine as entity_sourceHostname
select str(machineIp) as entity_sourceIp
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceIp) as entity_sourceIp_AssetRole
//<filtering_section>
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsLinuxSshAuthKeyModification") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsLinuxSshAuthKeyModification") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsLinuxSshAuthKeyModification") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsLinuxSshAuthKeyModification") as alertPriority
```

## SecOpsLinuxStrangeProcessExec

**Summary:** Detects process execution in a temporary folder.

**MITRE:** Tactics: Execution (TA0002) | Techniques: User Execution (T1204)

**Tables:** box.unix

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.unix
where toktains(message, "type=PATH"),toktains(message, "nametype=NORMAL"), toktains(message, "mode=0100755"), toktains(message, "name=\"/tmp/")
select peek(message, re("name=(.+ )"), 1) as file
select split(file, " ", 0) as ExecutionFile
group every 5m by ExecutionFile, machine, machineIp, facility, level, application, message, client
every 5m
//Entity Mapping Section
select machine as entity_sourceHostname
select str(machineIp) as entity_sourceIp
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceIp) as entity_sourceIp_AssetRole
//<filtering_section>
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsLinuxStrangeProcessExec") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsLinuxStrangeProcessExec") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsLinuxStrangeProcessExec") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsLinuxStrangeProcessExec") as alertPriority
```

## SecOpsLinuxSudoFileModification

**Summary:** Detects modification to the sudoers file. The sudoers file determines which users have the ability to run with superuser permission.

**MITRE:** Tactics: Privilege Escalation (TA0004) | Techniques: Abuse Elevation Control Mechanism (T1548)

**Tables:** box.unix

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.unix
where toktains(message, "sudoers")
where message -> "item=3"
group every 5m by machine, machineIp, facility, level, application, message, client
every 5m
//Entity Mapping Section
select machine as entity_sourceHostname
select str(machineIp) as entity_sourceIp
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceIp) as entity_sourceIp_AssetRole
//<filtering_section>
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsLinuxSudoFileModification") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsLinuxSudoFileModification") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsLinuxSudoFileModification") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsLinuxSudoFileModification") as alertPriority
```

## SecOpsLinuxSuspciousExecutionCommand

**Summary:** Detects relevant commands often related to malware or hacking activity.

**Description:** Detected relevant command often related to malware or hacking activity on $entity_sourceHostname with ip $machineIp. This activity should be reviewed to determine that this execution is not malicious. Audit message: $message

**MITRE:** Tactics: Execution (TA0002) | Techniques: Command and Scripting Interpreter (T1059)

**Tables:** box.unix

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.unix
where eq(auditType, "EXECVE")
where ((a0 = "chmod" and a1 = "u+s") or (a0 = "cp" and a1 = "/bin/ksh")  or (a0 = "cp" and a1 = "/bin/sh"))
group every 5m by machine,machineIp,message,client
every 5m
//Entity Mapping Section
select machine as entity_sourceHostname
select str(machineIp) as entity_sourceIp
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceIp) as entity_sourceIp_AssetRole
//<filtering_section>
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsLinuxSuspciousExecutionCommand") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsLinuxSuspciousExecutionCommand") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsLinuxSuspciousExecutionCommand") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsLinuxSuspciousExecutionCommand") as alertPriority
```

## SecOpsLinuxSvcEnabled

**Summary:** Detects for services being enabled in Linux. It's important to look for who created the the service, and the service path. It is possible an administrator could create a legitimate service that may be detected.

**MITRE:** Tactics: Persistence (TA0003) | Techniques: Create or Modify System Process (T1543)

**Tables:** box.unix

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.unix
where
toktains(message, "type=EXECVE"),
toktains(message, "argc=3 a0=\"systemctl\" a1=\"start\"") or
toktains(message, "argc=3 a0=\"systemctl\" a1=\"enable\"")
select peek(message, re("a2=(.+)"), 1) as process
group every 5m by machine, machineIp, facility, level, application, message, process, client
every 5m
//Entity Mapping Section
select machine as entity_sourceHostname
select str(machineIp) as entity_sourceIp
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceIp) as entity_sourceIp_AssetRole
//<filtering_section>
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsLinuxSvcEnabled") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsLinuxSvcEnabled") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsLinuxSvcEnabled") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsLinuxSvcEnabled") as alertPriority
```

## SecOpsLinuxSvcFileCreated

**Summary:** Detects suspicious file creation in the systemd directory.

**MITRE:** Tactics: Persistence (TA0003) | Techniques: Create or Modify System Process (T1543)

**Tables:** box.unix

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.unix
where toktains(message, "nametype=CREATE"),
toktains(message, "/etc/systemd/system/") or toktains(message, "/lib/systemd/system/") or toktains(message, "/usr/lib/systemd/system/") or toktains(message, "/run/systemd/system/") or toktains(message, "/etc/systemd/user/") or toktains(message, "/lib/systemd/user/") or toktains(message, "/usr/lib/systemd/user/") or toktains(message, "/run/systemd/users/")
select peek(message, re("name=(.+ )"), 1) as File
select split(File, " ", 0) as FileCreated
group every 5m by machine, machineIp, facility, level, application, message, FileCreated, client
every 5m
//Entity Mapping Section
select machine as entity_sourceHostname
select str(machineIp) as entity_sourceIp
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceIp) as entity_sourceIp_AssetRole
//<filtering_section>
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsLinuxSvcFileCreated") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsLinuxSvcFileCreated") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsLinuxSvcFileCreated") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsLinuxSvcFileCreated") as alertPriority
```

## SecOpsLinuxSystemLogFileDeletion

**Summary:** Detects the deletion of sensitive Linux system logs.

**MITRE:** Tactics: Defense Evasion (TA0005) | Techniques: Indicator Removal (T1070)

**Tables:** box.unix

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.unix
where toktains(message, "nametype=DELETE")
where toktains(message, "/var/log/lastlog") or toktains(message, "lastlog") or
toktains(message, "/var/run/utmp") or toktains(message, "utmp") or
toktains(message, "/var/log/wtmp") or toktains(message, "wtmp") or
toktains(message, "/var/log/btmp") or toktains(message, "btmp") or
toktains(message, "/var/log/faillog") or toktains(message, "faillog") or
toktains(message, "/var/log/syslog") or toktains(message, "syslog") or
toktains(message, "/var/log/messages") or toktains(message, "messages") or
toktains(message, "/var/log/secure") or toktains(message, "secure") or
toktains(message, "/var/log/auth.log") or toktains(message, "auth.log")
group every 5m by machine, machineIp, facility, level, application, message, client
every 5m
//Entity Mapping Section
select machine as entity_sourceHostname
select str(machineIp) as entity_sourceIp
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceIp) as entity_sourceIp_AssetRole
//<filtering_section>
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsLinuxSystemLogFileDeletion") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsLinuxSystemLogFileDeletion") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsLinuxSystemLogFileDeletion") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsLinuxSystemLogFileDeletion") as alertPriority
```

## SecOpsLinuxWebserverAccessLogsDeleted

**Summary:** Detects the deletion of Web Server access logs.

**MITRE:** Tactics: Defense Evasion (TA0005) | Techniques: Indicator Removal (T1070)

**Tables:** box.unix

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.unix
where toktains(message, " nametype=DELETE")
where toktains(message, " name=\"/etc/httpd/logs/access_log\"") or
toktains(message, " name=\"/var/log/httpd/access.log\"") or
toktains(message, " name=\"/var/www/httpd/logs/access.log\"") or
toktains(message, " name=\"/var/log/apache2/access.log\"") or toktains(message, "access.log")
group every 5m by machine, machineIp, facility, level, application, message, client
every 5m
//Entity Mapping Section
select machine as entity_sourceHostname
select str(machineIp) as entity_sourceIp
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceIp) as entity_sourceIp_AssetRole
//<filtering_section>
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsLinuxWebserverAccessLogsDeleted") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsLinuxWebserverAccessLogsDeleted") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsLinuxWebserverAccessLogsDeleted") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsLinuxWebserverAccessLogsDeleted") as alertPriority
```

## SecOpsLinuxWgetUseDetected

**Summary:** Detects a potentially malicious Wget execution. This could indicate that an attacker could be trying to exfiltrate from or download a file to the target machine.

**Description:** Detected use of wget command on $entity_sourceHostname with ip $entity_sourceIp. Audit message: $message

**MITRE:** Tactics: Command and Control (TA0011), Exfiltration (TA0010) | Techniques: Ingress Tool Transfer (T1105), Exfiltration Over Alternative Protocol (T1048)

**Tables:** box.unix

**Lookups:** SecOpsAssetRole, SecOpsAlertDescription

```linq
from box.unix
where toktains(message, "type=EXECVE")
where weaktoktains(message,"wget\"",true,true)
where toktains(message,"\"--post-file=",true,true) or toktains(message,"\"--post-data=",true,true) or toktains(message,"\"-O",true,true) or toktains(message,"\"--output-document=",true,true)
group every 5m by machine,machineIp,message, client
every 5m
//Entity Mapping Section
select machine as entity_sourceHostname
select str(machineIp) as entity_sourceIp
// Get asset role from SecOpsRole Lookup Section
select lu("SecOpsAssetRole", "class", entity_sourceHostname) as entity_sourceHostname_AssetRole
select lu("SecOpsAssetRole", "class", entity_sourceIp) as entity_sourceIp_AssetRole
//<filtering_section>
//Alert Tuning Section
select lu("SecOpsAlertDescription", "alertType", "SecOpsLinuxWgetUseDetected") as alertType
select lu("SecOpsAlertDescription", "alertMitreTactics", "SecOpsLinuxWgetUseDetected") as alertMitreTactics
select lu("SecOpsAlertDescription", "alertMitreTechniques", "SecOpsLinuxWgetUseDetected") as alertMitreTechniques
select lu("SecOpsAlertDescription", "alertPriority", "SecOpsLinuxWgetUseDetected") as alertPriority
```
