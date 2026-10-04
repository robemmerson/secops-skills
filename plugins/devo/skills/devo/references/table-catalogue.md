# Devo table catalogue (for grep)

Every data table named on Devo's technology-category pages: 2,808 table names in 101 categories.
Do not read this file top to bottom. Grep it:

- by vendor or product: `grep -i 'crowdstrike' table-catalogue.md`
- by name prefix: `grep 'cloud.azure.ad' table-catalogue.md`
- by category: `grep -A40 '^## edr ' table-catalogue.md`

Format: `## <level-1 prefix> - <category>` headings, then one line per product:
`Product: table1, table2, ...`. Product names are as Devo gives them (they usually include the
vendor). `(union)` marks a union table; see `tables.md` section 8 for its fields. "Union tables" and
"Other (no product named)" lines are rows where the source page gives no product name.
The `sse` category page lists no tables. `cef0.*` tables (CEF-format feeds) are not on the category
pages; they appear only as union table sources in `tables.md`.
This is the set of tables Devo can parse, not what a domain receives. Check `devo.py tables --grep '<table>'` (the domain's cached live table list) or `siem.logtrust.collector.counter` for tables with data.

## adn - Application Delivery Network

A10 Thunder ADC: adn.a10networks.thunder_adc, adn.a10networks.thunder_adc.acos, adn.a10networks.thunder_adc.aflex, adn.a10networks.thunder_adc.analytics, adn.a10networks.thunder_adc.cli, adn.a10networks.thunder_adc.dns_cache, adn.a10networks.thunder_adc.gslb, adn.a10networks.thunder_adc.gslb_protocol, adn.a10networks.thunder_adc.hmon, adn.a10networks.thunder_adc.mgmt, adn.a10networks.thunder_adc.report, adn.a10networks.thunder_adc.system, adn.a10networks.thunder_adc.vcs
BIG-IP: adn.f5.bigip.afm, adn.f5.bigip.apm, adn.f5.bigip.asm, adn.f5.bigip.audit, adn.f5.bigip.dns, adn.f5.bigip.ltm, adn.f5.bigip.pktfilter

## ap - Access Point

Aruba Wireless Access Point: ap.aruba.wap
Cisco Wireless LAN Controller: ap.cisco.wlc

## api - API

IBM API Connect: api.ibm.connect.audit, api.ibm.connect.event
MuleSoft Anypoint Platform API: api.mulesoft.anypoint.audit

## app - Application

Anaplan: app.anaplan.audit.events
Asana: app.asana.audit.events
Confluence: app.atlassian.confluence.audit
Jira: app.atlassian.jira.audit
Cisco Unified Communications Manager: app.cisco.cucm.audit
Lark Suite: app.lark.audit.event
LastPass: app.lastpass.events
Slack: app.slack.audit
Workday: app.workday.activity, app.workday.audit, app.workday.user_activity.activity
Zoom: app.zoom.activity.events, app.zoom.meeting.events, app.zoom.operationlogs.events

## auth - Authentication

Union tables: auth.all (union)
Union tables: auth.unix (union)
1Password: auth.agilebits.onepassword.audit, auth.agilebits.onepassword.itemusage, auth.agilebits.onepassword.signinattempt
Auth0 platform: auth.auth0.events
Bitwarden: auth.bitwarden.api.event, auth.bitwarden.api.member
Cisco Identity Services Engine: auth.cisco.acs, auth.cisco.ise
Duo platform: auth.duo.administrator, auth.duo.administrator.events, auth.duo.administrator.login, auth.duo.authentication.events, auth.duo.authenticationProxy.events, auth.duo.telephony.events
IBM Security Access Manager: auth.ibm.isam.events
JumpCloud: auth.jumpcloud.all.events (union), auth.jumpcloud.directory.events, auth.jumpcloud.ldap.events, auth.jumpcloud.mdm.events, auth.jumpcloud.radius.events, auth.jumpcloud.software.events, auth.jumpcloud.sso.events, auth.jumpcloud.systems.events
Keeper Security Audit: auth.keepersecurity.audit.events
Keycloak: auth.keycloak.user.event
LoginRadius: auth.loginradius.audit
Okta Authentication Server: auth.okta, auth.okta.apps, auth.okta.asa_events, auth.okta.clients, auth.okta.events, auth.okta.groups, auth.okta.idps, auth.okta.policies, auth.okta.system, auth.okta.users, auth.okta.zones
One Identity Defender Security Server: auth.oneidentity.defender.securityserver
One Identity Safeguard: auth.oneidentity.safeguard.events
OneLogin: auth.onelogin.api_auth, auth.onelogin.apps, auth.onelogin.connectors, auth.onelogin.events, auth.onelogin.privileges, auth.onelogin.users, auth.onelogin.vigilance
PingFederate: auth.ping.federate.audit, auth.ping.federate.security_audit, auth.ping.federate.server
PingID: auth.ping.id.mfa
RSA Authentication Manager: auth.rsa.rsaam.manager
RSA SecurID: auth.rsa.secureid, auth.rsa.secureid.admin, auth.rsa.secureid.runtime, auth.rsa.secureid.system, auth.rsa.secureid.trace
SecureAuth identity platform: auth.secureauth.events, auth.secureauth.radius
SecurIdentity platform: auth.securenvoy, auth.securenvoy.admin, auth.securenvoy.batch, auth.securenvoy.enrol, auth.securenvoy.radius, auth.securenvoy.syslog, auth.securenvoy.websms
Delinea (formerly Thycotic) Secret Server: auth.thycotic.secretserver
Transmit Security FlexID: auth.transmit.flexid.events

## av - Antivirus

Union tables: av.all.threats (union)
Mobile Threat Prevention: av.checkpoint.mtp.audit, av.checkpoint.mtp.event
F-Secure Internet Gatekeeper: av.fsecure.igk.access
McAfee ePolicy Orchestrator (McAfee ePO): av.mcafee.epo.agent, av.mcafee.epo.dlp, av.mcafee.epo.endpointsecurity, av.mcafee.epo.events, av.mcafee.epo.threat, av.mcafee.epo.virusscan
SentinelOne Endpoint Protection Platform (EPP): av.sentinelone.events, av.sentinelone.rfc_5424
Sophos AntiVirus: av.sophos, av.sophos.applicationcontrol, av.sophos.devicecontrol, av.sophos.enterprise, av.sophos.events, av.sophos.tamperprotection, av.sophos.threatinstances, av.sophos.threats
Symantec Data Center Security - Server Advanced: av.symantec.dcs_sa.auditing, av.symantec.dcs_sa.events
Symantec Endpoint Protection: av.symantec.sep.mail
Symantec Endpoint Protection Cloud: av.symantec.sepc.events
Trend Micro Deep Security: av.trendmicro.deepsec.agent, av.trendmicro.deepsec.alerts, av.trendmicro.deepsec.antimalwareevents, av.trendmicro.deepsec.console, av.trendmicro.deepsec.firewallevents, av.trendmicro.deepsec.integrityevents, av.trendmicro.deepsec.manager
Trend Micro InterScan Web Security Virtual Appliance (IWSVA): av.trendmicro.iwsva.event

## backup - Backup

Veeam Backup & Replication: backup.veeam.backup_replication.backupserverdata

## bms - Bot Management System

Cloudflare Bot Management: bms.cloudflare.audit.events
HUMAN Bot Defender: bms.humansecurity.botdefender.events

## box - Operating Systems

Union tables: box.all.win (union)
IBM AS/400: box.as400.audit.type2, box.as400_townsend.logagent.audit
IBM z/OS: box.ibm.z_os.leef
IBM z/OS: box.zos
UNIX audit: box.audit.unix (union), box.audit.unix.audispd, box.audit.unix.auditd, box.audit.unix.goAudit
UNIX osquery: box.osquery.unix.info, box.osquery.unix.results
UNIX system logs: box.unix
UNIX 8 system logs: box.unix8
CloudWatch logs on UNIX: box.unix_cloudwatch
UNIX stat logs: box.stat.unix.diskstat, box.stat.unix.dstatLt1, box.stat.unix.tags
Docker container logs: box.docker.stats
Linux iptables: box.iptables
macOS: box.macos
macOS NXLog: box.osx_nxlog
VMware: box.vmware.esx, box.vmware.firewall, box.vmware.vcenter
Microsoft Azure: box.stat.azure.dstatLt1, box.stat.azure.tags
Windows events: box.win
Windows Classic: box.win_classic, box.win_classic.application, box.win_classic.other, box.win_classic.security, box.win_classic.system
Windows CloudWatch: box.win_cloudwatch
Windows InTrust: box.win_intrust, box.win_intrust.application, box.win_intrust.invalid, box.win_intrust.other, box.win_intrust.security, box.win_intrust.system
Windows Kinesis Agent: box.win_kinesis, box.win_kinesis.application, box.win_kinesis.invalid, box.win_kinesis.security, box.win_kinesis.system
Windows NXLog: box.win_nxlog, box.win_nxlog.adfs, box.win_nxlog.application, box.win_nxlog.dns, box.win_nxlog.group_policy, box.win_nxlog.invalid, box.win_nxlog.other, box.win_nxlog.powershell, box.win_nxlog.print, box.win_nxlog.remote_conn, box.win_nxlog.security, box.win_nxlog.smb, box.win_nxlog.sysmon, box.win_nxlog.system, box.win_nxlog.windows_powershell
WinQuest: box.win_quest.change_auditor.leef
Snare Windows Agent: box.win_snare, box.win_snare.application, box.win_snare.other, box.win_snare.powershell, box.win_snare.security, box.win_snare.setup, box.win_snare.system
SolarWinds: box.win_solarwinds, box.win_solarwinds.application, box.win_solarwinds.other, box.win_solarwinds.powershell, box.win_solarwinds.security, box.win_solarwinds.setup, box.win_solarwinds.system
Windows System Monitor (Sysmon): box.win_sysmon
Winlogbeat: box.win_winlogbeat, box.win_winlogbeat.adpwprotect, box.win_winlogbeat.application, box.win_winlogbeat.applocker, box.win_winlogbeat.authentication, box.win_winlogbeat.bitsClient, box.win_winlogbeat.codeintegrity, box.win_winlogbeat.deviceguard, box.win_winlogbeat.forwarding, box.win_winlogbeat.kernelPnp, box.win_winlogbeat.ntlm, box.win_winlogbeat.oalerts, box.win_winlogbeat.powershell, box.win_winlogbeat.security, box.win_winlogbeat.securityMitigations, box.win_winlogbeat.setup, box.win_winlogbeat.smb, box.win_winlogbeat.sysmon, box.win_winlogbeat.system, box.win_winlogbeat.taskscheduler, box.win_winlogbeat.terminalservices, box.win_winlogbeat.win32k, box.win_winlogbeat.windows_defender, box.win_winlogbeat.windows_firewall, box.win_winlogbeat.windowsupdateclient, box.win_winlogbeat.wmiActivity
Windows stat logs: box.stat.win.diskstat, box.stat.win.dstatLt1, box.stat.win.heartbeat, box.stat.win.tags

## casb - Cloud Access Security Broker

Bitglass: casb.bitglass.access, casb.bitglass.admin, casb.bitglass.cloud_audit, casb.bitglass.cloud_summary
Cisco Cloudlock: casb.cisco.cloudlock.activities, casb.cisco.cloudlock.apps, casb.cisco.cloudlock.incidents, casb.cisco.cloudlock.policies, casb.cisco.cloudlock.suspicious_ip, casb.cisco.cloudlock.threats
Illumio: casb.illumio.events
Microsoft Defender: casb.microsoft_defender.cloud_apps.activities, casb.microsoft_defender.cloud_apps.alerts, casb.microsoft_defender.cloud_apps.data_enrichment, casb.microsoft_defender.cloud_apps.entities, casb.microsoft_defender.cloud_apps.files
Netskope CASB (Cloud Access Security Broker): casb.netskope.alert, casb.netskope.application, casb.netskope.audit, casb.netskope.client, casb.netskope.compromisedcredential, casb.netskope.incident, casb.netskope.infrastructure, casb.netskope.malsite, casb.netskope.malware, casb.netskope.network, casb.netskope.page, casb.netskope.policy, casb.netskope.transaction_events, casb.netskope.uba
Paloalto Prisma Cloud: casb.paloalto.prisma, casb.paloalto.prisma.activity_monitoring, casb.paloalto.prisma.admin_audit, casb.paloalto.prisma.incident, casb.paloalto.prisma.invalid, casb.paloalto.prisma.other, casb.paloalto.prisma.policy_violation, casb.paloalto.prisma.remediation
Proofpoint: casb.proofpoint.alert, casb.proofpoint.event
Trend Micro: casb.trendmicro.security

## cdn - Content Delivery Network

Union tables: cdn.all.access (union)
Akamai CDN: cdn.akamai.access, cdn.akamai.audit, cdn.akamai.auditExtended, cdn.akamai.cloudmonitor, cdn.akamai.monitor, cdn.akamai.siem
Cloudflare: cdn.cloudflare.audit.events, cdn.cloudflare.firewall.samples, cdn.cloudflare.waf.events
Fastly: cdn.fastly.waf.event, cdn.fastly.web.event
Triton Digital: cdn.triton.access

## cloud - Cloud

Alibaba cloud: cloud.alibaba.actiontrail.events, cloud.alibaba.log_service.events
Cloudflare + AWS: cloud.aws.cloudflare.events
AWS CloudFront: cloud.aws.cloudfront.rmtp_1, cloud.aws.cloudfront.web_1
AWS CloudTrail: cloud.aws.cloudtrail, cloud.aws.cloudtrail.access_analyzer, cloud.aws.cloudtrail.acm, cloud.aws.cloudtrail.acm_pca, cloud.aws.cloudtrail.amazonmq, cloud.aws.cloudtrail.apigateway, cloud.aws.cloudtrail.appmesh, cloud.aws.cloudtrail.appstream, cloud.aws.cloudtrail.appsync, cloud.aws.cloudtrail.athena, cloud.aws.cloudtrail.audit, cloud.aws.cloudtrail.autoscaling, cloud.aws.cloudtrail.backup, cloud.aws.cloudtrail.batch, cloud.aws.cloudtrail.billingconsole, cloud.aws.cloudtrail.budgets, cloud.aws.cloudtrail.ce, cloud.aws.cloudtrail.cloudformation, cloud.aws.cloudtrail.cloudfront, cloud.aws.cloudtrail.cloudhsm, cloud.aws.cloudtrail.cloudsearch, cloud.aws.cloudtrail.cloudshell, cloud.aws.cloudtrail.cloudtrail, cloud.aws.cloudtrail.codeartifact, cloud.aws.cloudtrail.codebuild, cloud.aws.cloudtrail.codecommit, cloud.aws.cloudtrail.codedeploy, cloud.aws.cloudtrail.codepipeline, cloud.aws.cloudtrail.cognito_identify, cloud.aws.cloudtrail.cognito_idp, cloud.aws.cloudtrail.comprehend, cloud.aws.cloudtrail.config, cloud.aws.cloudtrail.datapipeline, cloud.aws.cloudtrail.dax, cloud.aws.cloudtrail.digest_logfile, cloud.aws.cloudtrail.digest_meta, cloud.aws.cloudtrail.directconnect, cloud.aws.cloudtrail.dms, cloud.aws.cloudtrail.ds, cloud.aws.cloudtrail.dynamodb, cloud.aws.cloudtrail.ec2, cloud.aws.cloudtrail.ecr, cloud.aws.cloudtrail.ecr_public, cloud.aws.cloudtrail.ecs, cloud.aws.cloudtrail.elasticache, cloud.aws.cloudtrail.elasticbeanstalk, cloud.aws.cloudtrail.elasticloadbalancing, cloud.aws.cloudtrail.elasticmapreduce, cloud.aws.cloudtrail.elastictranscoder, cloud.aws.cloudtrail.es, cloud.aws.cloudtrail.events, cloud.aws.cloudtrail.firehose, cloud.aws.cloudtrail.fsx, cloud.aws.cloudtrail.glacier, cloud.aws.cloudtrail.glue, cloud.aws.cloudtrail.guardduty, cloud.aws.cloudtrail.health, cloud.aws.cloudtrail.iam, cloud.aws.cloudtrail.identifystore, cloud.aws.cloudtrail.insights, cloud.aws.cloudtrail.inspector, cloud.aws.cloudtrail.kafka, cloud.aws.cloudtrail.kinesis, cloud.aws.cloudtrail.kinesisanalytics, cloud.aws.cloudtrail.kinesisvideo, cloud.aws.cloudtrail.kms, cloud.aws.cloudtrail.lakeformation, cloud.aws.cloudtrail.lambda, cloud.aws.cloudtrail.license_manager, cloud.aws.cloudtrail.lightsail, cloud.aws.cloudtrail.logs, cloud.aws.cloudtrail.mediaconnect, cloud.aws.cloudtrail.mediaconvert, cloud.aws.cloudtrail.mediapackage, cloud.aws.cloudtrail.mediastore, cloud.aws.cloudtrail.mediatailor, cloud.aws.cloudtrail.monitoring, cloud.aws.cloudtrail.network_firewall, cloud.aws.cloudtrail.opsworks, cloud.aws.cloudtrail.opsworks_cm, cloud.aws.cloudtrail.optimizer, cloud.aws.cloudtrail.organizations, cloud.aws.cloudtrail.pi, cloud.aws.cloudtrail.pricelist, cloud.aws.cloudtrail.ram, cloud.aws.cloudtrail.rds, cloud.aws.cloudtrail.redshift, cloud.aws.cloudtrail.rekognition, cloud.aws.cloudtrail.resource_groups, cloud.aws.cloudtrail.route53, cloud.aws.cloudtrail.route53domains, cloud.aws.cloudtrail.route53resolver, cloud.aws.cloudtrail.s3, cloud.aws.cloudtrail.sagemaker, cloud.aws.cloudtrail.savingsplans, cloud.aws.cloudtrail.schemas, cloud.aws.cloudtrail.secretsmanager, cloud.aws.cloudtrail.securityhub, cloud.aws.cloudtrail.servicecatalog, cloud.aws.cloudtrail.servicecatalog_appregistry, cloud.aws.cloudtrail.servicediscovery, cloud.aws.cloudtrail.servicesquotas, cloud.aws.cloudtrail.ses, cloud.aws.cloudtrail.shield, cloud.aws.cloudtrail.signin, cloud.aws.cloudtrail.sms, cloud.aws.cloudtrail.sns, cloud.aws.cloudtrail.soo_directory, cloud.aws.cloudtrail.sqs, cloud.aws.cloudtrail.ssm, cloud.aws.cloudtrail.states, cloud.aws.cloudtrail.storagegateway, cloud.aws.cloudtrail.sts, cloud.aws.cloudtrail.support, cloud.aws.cloudtrail.swf, cloud.aws.cloudtrail.tagging, cloud.aws.cloudtrail.translate, cloud.aws.cloudtrail.trustedadvisor, cloud.aws.cloudtrail.waf, cloud.aws.cloudtrail.waf_regional, cloud.aws.cloudtrail.wafv2, cloud.aws.cloudtrail.wellarchitected, cloud.aws.cloudtrail.workspaces, cloud.aws.cloudtrail.xray
AWS CloudWatch: cloud.aws.cloudwatch.alarm, cloud.aws.cloudwatch.events, cloud.aws.cloudwatch.logs, cloud.aws.cloudwatch.metrics
AWS Config: cloud.aws.configlogs.events
AWS Network Firewall: cloud.aws.firewall.alert, cloud.aws.firewall.netflow
AWS GuardDuty: cloud.aws.guardduty.events, cloud.aws.guardduty.findings
Amazon Security Lake: cloud.aws.security_lake.event
AWS Security Hub: cloud.aws.securityhub.findings
AWS Simple Queue Service (SQS): cloud.aws.sqs.audit
Amazon VPC: cloud.aws.vpc.flow
AWS Web Application Firewall (WAF): cloud.aws.waf.logs
Microsoft Azure: cloud.azure
Azure Activity log: cloud.azure.activity.events
Azure Active Directory: cloud.azure.ad.alerts, cloud.azure.ad.audit, cloud.azure.ad.identityprotection, cloud.azure.ad.managed_identity_signin, cloud.azure.ad.noninteractive_user_signin, cloud.azure.ad.provisioning, cloud.azure.ad.risky_service_principals, cloud.azure.ad.risky_users, cloud.azure.ad.service_principal_risk_events, cloud.azure.ad.service_principal_signin, cloud.azure.ad.signin, cloud.azure.ad.user_risk_events
Azure Kubernetes Service: cloud.azure.aks, cloud.azure.aks.cluster_autoscaler, cloud.azure.aks.containerlog, cloud.azure.aks.guard, cloud.azure.aks.kube_apiserver, cloud.azure.aks.kube_audit, cloud.azure.aks.kube_audit_admin, cloud.azure.aks.kube_controller_manager, cloud.azure.aks.kube_scheduler
Azure API Management: cloud.azure.apimanagement.gatewaylogs
Azure Application Gateway: cloud.azure.appgateway.access_log, cloud.azure.appgateway.administrative, cloud.azure.appgateway.firewall_log, cloud.azure.appgateway.policy
Azure App Service: cloud.azure.appservice.access_audit, cloud.azure.appservice.administrative, cloud.azure.appservice.app, cloud.azure.appservice.application, cloud.azure.appservice.console, cloud.azure.appservice.environment_platform, cloud.azure.appservice.http, cloud.azure.appservice.ipsecurity_audit, cloud.azure.appservice.platform, cloud.azure.appservice.policy
Azure Components: cloud.azure.components.process
Azure Container Registry: cloud.azure.contregistry.login
Azure Cosmos DB: cloud.azure.cosmosdb.control_plane_requests, cloud.azure.cosmosdb.date_plane_requests, cloud.azure.cosmosdb.metrics, cloud.azure.cosmosdb.mongo_requests, cloud.azure.cosmosdb.partition_key_ru_consumption, cloud.azure.cosmosdb.partition_key_statistics, cloud.azure.cosmosdb.query_runtime_statistics
Azure Data Factory: cloud.azure.datafactory.administrative
Azure Event Hub: cloud.azure.eh.events, cloud.azure.eh.metrics
Azure Data Factory: cloud.azure.factories.activity_runs, cloud.azure.factories.pipeline_runs, cloud.azure.factories.sandbox_activity_runs, cloud.azure.factories.sandbox_pipeline_runs, cloud.azure.factories.trigger_runs
Azure Firewall: cloud.azure.firewall.application_rule, cloud.azure.firewall.dns_proxy, cloud.azure.firewall.network_rule
Azure Front Door: cloud.azure.frontdoor.access, cloud.azure.frontdoor.waf
Azure Host Pool: cloud.azure.hostpools, cloud.azure.hostpools.agenthealthstatus, cloud.azure.hostpools.checkpoint, cloud.azure.hostpools.connection, cloud.azure.hostpools.error, cloud.azure.hostpools.management
Azure Key Vault: cloud.azure.keyvault.administrative, cloud.azure.keyvault.audit, cloud.azure.keyvault.azure_monitor, cloud.azure.keyvault.policy, cloud.azure.keyvault.policy_evaluation_details
Azure managed clusters: cloud.azure.managedclusters.cloud_controller_manager, cloud.azure.managedclusters.csi_azuredisk_controller, cloud.azure.managedclusters.csi_azurefile_controller, cloud.azure.managedclusters.csi_snapshot_controller
Azure Monitor Metrics: cloud.azure.metrics.metricsBlobLog, cloud.azure.metrics.metricsCapacityBlob, cloud.azure.metrics.metricsTableLog, cloud.azure.metrics.metricsTransactions, cloud.azure.metrics.metricsTransactionsBlob, cloud.azure.metrics.metricsTransactionsQueue, cloud.azure.metrics.metricsTransactionsTable
Azure x Microsoft Defender: cloud.azure.microsoft_defender.alerts, cloud.azure.microsoft_defender.scorecontrol, cloud.azure.microsoft_defender.scores
Azure Monitor: cloud.azure.monitor.alert, cloud.azure.monitor.audit
Azure network security groups: cloud.azure.nsg.flow
Azure Monitor Metrics - other metrics: cloud.azure.others.administrative, cloud.azure.others.autoscale, cloud.azure.others.events, cloud.azure.others.policy, cloud.azure.others.recommendation, cloud.azure.others.resourcehealth
Azure Database for PostgreSQL: cloud.azure.postgresql.events
Azure Network Security: cloud.azure.sec.nsg, cloud.azure.sec.rms
Azure Security Center: cloud.azure.securitycenter.alerts, cloud.azure.securitycenter.security
Azure x Sentinel: cloud.azure.sentinel.alerts
Azure Service Bus: cloud.azure.servicebus.metrics, cloud.azure.servicebus.operational
Azure Site Recovery: cloud.azure.siterecovery.addon_backup_jobs, cloud.azure.siterecovery.addon_backup_policy, cloud.azure.siterecovery.addon_backup_protected_inst, cloud.azure.siterecovery.addon_backup_storage, cloud.azure.siterecovery.backup_report, cloud.azure.siterecovery.core_backup, cloud.azure.siterecovery.site_rec_recovery_points, cloud.azure.siterecovery.site_rec_rep_stats, cloud.azure.siterecovery.site_rec_replicated_items
Azure SQL Database: cloud.azure.sql.audit, cloud.azure.sql.automatic_tuning, cloud.azure.sql.query_store_runtime, cloud.azure.sql.resourceusagestats, cloud.azure.sql.securityauditevents
Azure Storage Server: cloud.azure.storage.administrative, cloud.azure.storage.resourcehealth, cloud.azure.storage.storagedelete, cloud.azure.storage.storageread, cloud.azure.storage.storagewrite
Azure Traffic Manager: cloud.azure.traffic_manager.probe_health_status
Azure Virtual Network: cloud.azure.virtualnetwork.net_sec_group_event, cloud.azure.virtualnetwork.net_sec_group_rule_counter
Azure Virtual Machines: cloud.azure.vm.administrative, cloud.azure.vm.applicationevent, cloud.azure.vm.metrics_simple, cloud.azure.vm.policy, cloud.azure.vm.recommendation, cloud.azure.vm.resourcehealth, cloud.azure.vm.securityevent, cloud.azure.vm.systemevent, cloud.azure.vm.unix, cloud.azure.vm.unknown_events
Azure Virtual Machine Scale Sets: cloud.azure.vmscalesets.administrative, cloud.azure.vmscalesets.autoscale, cloud.azure.vmscalesets.policy, cloud.azure.vmscalesets.resourcehealth
Azure VPN Gateway: cloud.azure.vngateways.ikediagnos
Azure Diagnostics extension: cloud.azure.wad.waddirectories, cloud.azure.wad.wadperformancecounters, cloud.azure.wad.wadwindowseventlogs
Azure workflows: cloud.azure.workflows.workflow_runtime
Box cloud content management: cloud.box.collaborations, cloud.box.events, cloud.box.files, cloud.box.folders, cloud.box.groups, cloud.box.users
Cloud Foundry application: cloud.cloud_foundry.application, cloud.cloud_foundry.bosh, cloud.cloud_foundry.cloud_controller_ng, cloud.cloud_foundry.credhub, cloud.cloud_foundry.rep, cloud.cloud_foundry.route_emitter, cloud.cloud_foundry.route_registrar, cloud.cloud_foundry.service_metrics, cloud.cloud_foundry.uaa
Cloudflare: cloud.cloudflare.logpush, cloud.cloudflare.logpush.http
Google Cloud Platform: cloud.gcp
Google Cloud BigQuery: cloud.gcp.bigquery.gmail
Google Cloud Armor: cloud.gcp.cloud_armor.adaptive_protection, cloud.gcp.cloud_armor.events
Google Cloud Audit: cloud.gcp.cloudaudit, cloud.gcp.cloudaudit.activity, cloud.gcp.cloudaudit.bigquery, cloud.gcp.cloudaudit.data_access, cloud.gcp.cloudaudit.k8s, cloud.gcp.cloudaudit.login, cloud.gcp.cloudaudit.policy, cloud.gcp.cloudaudit.project, cloud.gcp.cloudaudit.system_event, cloud.gcp.scc.event_threat
Google Compute Engine: cloud.gcp.compute.firewall, cloud.gcp.compute.shielded_vm_integrity
Google Cloud DNS: cloud.gcp.dns.dns_queries
Google Cloud GCEGuestAgent: cloud.gcp.gceguestagent.none
Google Cloud IDS: cloud.gcp.ids.threat
Google Cloud OS Config agent: cloud.gcp.osconfigagent.none
Google Cloud Platform requests: cloud.gcp.requests
GCP Security Command Center: cloud.gcp.scc.event_threat, cloud.gcp.scc.findings
Google Cloud’s operations suite (formerly Stackdriver): cloud.gcp.stackdriver.log
GCP Standard Error Messages: cloud.gcp.stderr
GCP Standard Output: cloud.gcp.stdout
GCP Syslog: cloud.gcp.syslog.none
GCP Threat Detection: cloud.gcp.threatdetection.detection
GCP Threat Detection: cloud.gcp.unknown.none
Google logs: cloud.google.activity, cloud.google.audit
Google Workspace admin logs: cloud.gsuite.admin.alertcenter
Google Workspace alerts: cloud.gsuite.alerts, cloud.gsuite.alerts.activity_rule, cloud.gsuite.alerts.appmaker_default_cloud_sql_setup, cloud.gsuite.alerts.customer_takeout_initiated, cloud.gsuite.alerts.data_loss_prevention, cloud.gsuite.alerts.device_compromised, cloud.gsuite.alerts.google_operations, cloud.gsuite.alerts.government_attack_warning, cloud.gsuite.alerts.leaked_password, cloud.gsuite.alerts.malware_reclassification, cloud.gsuite.alerts.misconfigured_whitelist, cloud.gsuite.alerts.phising_reclassification, cloud.gsuite.alerts.super_admin_password_reset, cloud.gsuite.alerts.suspicious_activity, cloud.gsuite.alerts.suspicious_login, cloud.gsuite.alerts.suspicious_login_less_secure_app, cloud.gsuite.alerts.suspicious_message_reported, cloud.gsuite.alerts.suspicious_programmatic_login, cloud.gsuite.alerts.user_reported_phising, cloud.gsuite.alerts.user_reported_spam_spike, cloud.gsuite.alerts.user_suspended, cloud.gsuite.alerts.user_suspended_spam, cloud.gsuite.alerts.user_suspended_spam_through_relay, cloud.gsuite.alerts.user_suspended_suspicious_activity
Google Workspace audit logs: cloud.gsuite.audit.accesstransparency, cloud.gsuite.audit.admin, cloud.gsuite.audit.drive, cloud.gsuite.audit.login, cloud.gsuite.audit.mobile, cloud.gsuite.audit.token, cloud.gsuite.audit.useraccount
Google Workspace reports: cloud.gsuite.reports, cloud.gsuite.reports.access_transparency, cloud.gsuite.reports.admin, cloud.gsuite.reports.calendar, cloud.gsuite.reports.chat, cloud.gsuite.reports.data_studio, cloud.gsuite.reports.drive, cloud.gsuite.reports.gcp, cloud.gsuite.reports.gplus, cloud.gsuite.reports.groups, cloud.gsuite.reports.groups_enterprise, cloud.gsuite.reports.jamboard, cloud.gsuite.reports.login, cloud.gsuite.reports.meet, cloud.gsuite.reports.mobile, cloud.gsuite.reports.rules, cloud.gsuite.reports.saml, cloud.gsuite.reports.token, cloud.gsuite.reports.user_accounts
IBM Cloud Activity Tracker: cloud.ibm.activity_tracker.audit
IBM SoftLayer: cloud.ibm.softlayer.event_log
IBM Cloud Virtual Private Cloud (VPC): cloud.ibm.vpc.flow_log
Cisco Meraki: cloud.meraki.api.changelog
Microsoft Graph: cloud.msgraph, cloud.msgraph.security.alerts, cloud.msgraph.security.alerts_v2, cloud.msgraph.security.scorecontrol, cloud.msgraph.security.scores
Netskope cloud: cloud.netskope.events
Microsoft 365: cloud.office365
Microsoft 365 Azure Active Directory: cloud.office365.aad
Microsoft Defender for Cloud Apps alerts: cloud.office365.cloud_apps.alerts
Microsoft 365 Data Loss Prevention: cloud.office365.dlp
Microsoft Defender for Endpoint alerts: cloud.office365.endpoint.alerts
Microsoft 365 Exchange: cloud.office365.exchange
Microsoft 365 Identity Alerts: cloud.office365.identity.alerts
Microsoft 365 management: cloud.office365.management (union), cloud.office365.management_all, cloud.office365.oldmanagement, cloud.office365.management.aip, cloud.office365.management.airinvestigation, cloud.office365.management.azureactivedirectory, cloud.office365.management.cca, cloud.office365.management.compliance, cloud.office365.management.compliancemanager, cloud.office365.management.complianceposturemanager, cloud.office365.management.corereporting, cloud.office365.management.crm, cloud.office365.management.dlpsensitiveinformationtype, cloud.office365.management.endpoint, cloud.office365.management.exchange, cloud.office365.management.mcas, cloud.office365.management.microsoftflow, cloud.office365.management.microsoftforms, cloud.office365.management.microsoftstream, cloud.office365.management.microsoftteams, cloud.office365.management.mip, cloud.office365.management.myanalytics, cloud.office365.management.officeapps, cloud.office365.management.onedrive, cloud.office365.management.onedriveforbusiness, cloud.office365.management.powerapps, cloud.office365.management.powerbi, cloud.office365.management.powerplatformadmin, cloud.office365.management.project, cloud.office365.management.publicendpoint, cloud.office365.management.quarantine, cloud.office365.management.rdl, cloud.office365.management.se, cloud.office365.management.securitycompliancecenter, cloud.office365.management.sharepoint, cloud.office365.management.skypeforbusiness, cloud.office365.management.threatintelligence, cloud.office365.management.workplaceanalytics, cloud.office365.management.yammer
Microsoft 365 message tracing: cloud.office365.messagetracing
Microsoft 365 OneDrive: cloud.office365.onedrive
Microsoft 365 OneDrive: cloud.office365.other
Microsoft 365 reports: cloud.office365.reporting.atptraffic, cloud.office365.reporting.dlp, cloud.office365.reporting.dlpdetail, cloud.office365.reporting.maildetailatp, cloud.office365.reporting.mailtraffic, cloud.office365.reporting.messagetrace, cloud.office365.reporting.safelinksdetail, cloud.office365.reporting.spoofmail
Microsoft 365 security events: cloud.office365.security.alerts, cloud.office365.security.scorecontrol, cloud.office365.security.scores
Microsoft 365 Security & Compliance Center: cloud.office365.securitycompliancecenter
Microsoft 365 SharePoint: cloud.office365.sharepoint
Microsoft 365 SIEM agent: cloud.office365.siem_agent_alert, cloud.office365.siem_agent_event
Microsoft 365 Teams: cloud.office365.teams
Prisma Cloud: cloud.paloalto.prisma.alert, cloud.paloalto.prisma.audit, cloud.paloalto.prisma.inventory_trend, cloud.paloalto.prisma.inventory_view
Rubrik cloud data management: cloud.rubrik.events
Snowflake: cloud.snowflake.logins
Sophos Central: cloud.sophos.central.alerts, cloud.sophos.central.events
Twistlock: cloud.twistlock.events
VMware Tanzu Operations Manager: cloud.vmware_tanmzu.opsmanager.audit

## cls - Cloud Log Service

Tencent Cloud: cls.tencent.log.event

## cms - Content Management Systems

WordPress software: cms.wordpress.stdout

## cnapp - Cloud Native Application Protection Platforms

Orca Security: cnapp.orca.security.alerts

## codeanalysis - Code Analysis

SonarQube: codeanalysis.sonarqube.access, codeanalysis.sonarqube.ce, codeanalysis.sonarqube.es, codeanalysis.sonarqube.sonar, codeanalysis.sonarqube.web

## crm - Customer Relationship Management

Microsoft Dynamics 365: crm.microsoft.dynamics365.audit
Salesforce: crm.salesforce, crm.salesforce.apexcallout, crm.salesforce.apexexecution, crm.salesforce.apexrestapi, crm.salesforce.apexsoap, crm.salesforce.apextrigger, crm.salesforce.apexunexpectedexception, crm.salesforce.api, crm.salesforce.asyncreportrun, crm.salesforce.audit, crm.salesforce.bulkapi, crm.salesforce.concurrentlongrunningapexlimit, crm.salesforce.console, crm.salesforce.contentdocumentlink, crm.salesforce.contenttransfer, crm.salesforce.dashboard, crm.salesforce.documentattachmentdownloads, crm.salesforce.knowledgearticleview, crm.salesforce.lightningerror, crm.salesforce.lightninginteraction, crm.salesforce.lightningpageview, crm.salesforce.lightningperformance, crm.salesforce.login, crm.salesforce.logout, crm.salesforce.metadataapioperation, crm.salesforce.multiblockreport, crm.salesforce.packageinstall, crm.salesforce.queuedexecution, crm.salesforce.report, crm.salesforce.reportexport, crm.salesforce.restapi, crm.salesforce.sandbox, crm.salesforce.search, crm.salesforce.searchclick, crm.salesforce.sites, crm.salesforce.timebasedworkflow, crm.salesforce.uri, crm.salesforce.visualforcerequest, crm.salesforce.wavechange, crm.salesforce.waveinteraction, crm.salesforce.waveperformance
Salesforce Objects: crm.salesforceobjects, crm.salesforceobjects.account, crm.salesforceobjects.case, crm.salesforceobjects.contentversion, crm.salesforceobjects.dashboard, crm.salesforceobjects.eventlogfile, crm.salesforceobjects.loginevent, crm.salesforceobjects.loginhistory, crm.salesforceobjects.logoutevent, crm.salesforceobjects.opportunity, crm.salesforceobjects.report, crm.salesforceobjects.setupaudittrail, crm.salesforceobjects.users

## cspm - Cloud Security Posture Management

Horangi Cyber Security: cspm.horangi.warden.alerts
Sysdig: cspm.sysdig.monitor.alerts
Wiz: cspm.wiz.audit.default, cspm.wiz.cloud_configuration.default, cspm.wiz.cloud_event.default, cspm.wiz.issues.default, cspm.wiz.system_activity.default, cspm.wiz.vulnerabilities.default

## cwpp - Cloud Workload Protection Platform

ColorTokens Xshield: cwpp.colortokens.xshield.alert, cwpp.colortokens.xshield.audit

## daas - Desktop as a Service

Citrix: daas.citrix.config.event, daas.citrix.system.event

## dataset - Data Set

New York City Taxi: dataset.nyctaxi.green, dataset.nyctaxi.yellow

## db - Database

IBM Db2 Database: db.db2.audit
EDB BigAnimal: db.edb.biganimal.prometheus_metric
InfluxDB: db.influxdb.audit
MongoDB: db.mongodb.audit, db.mongodb.events, db.mongodb.malformed, db.mongodb.out
Microsoft SQL Server: db.mssql.audit, db.mssql.error, db.mssql.events
MySQL Server: db.mysql.error, db.mysql.out, db.mysql.slow
Netezza Performance Server: db.netezza.out
Oracle database: db.oracle.alert, db.oracle.audit, db.oracle.audit_trail, db.oracle.error, db.oracle.unifiedaudit
OrientDB: db.orientdb.error, db.orientdb.out
PostgreSQL: db.postgresql.audit, db.postgresql.out
Redis: db.redis.out
Snowflake: db.snowflake.history.access, db.snowflake.history.login, db.snowflake.history.session
Solr: db.solr.out
Teradata: db.teradata.out

## dbsec - Database Security

Imperva SecureSphere: dbsec.imperva.securesphere.alerts, dbsec.imperva.securesphere.events, dbsec.imperva.securesphere.system

## ddi - DNS, DHCP, and IP Address Management

Infoblox solutions: ddi.infoblox, ddi.infoblox.audit, ddi.infoblox.audit.httpd, ddi.infoblox.audit.serial_console, ddi.infoblox.audit.sshd, ddi.infoblox.dhcp, ddi.infoblox.dhcp.dhcpd, ddi.infoblox.dhcp.validate_dhcpd, ddi.infoblox.dns, ddi.infoblox.dns.client, ddi.infoblox.dns.config, ddi.infoblox.dns.database, ddi.infoblox.dns.dtc, ddi.infoblox.dns.general, ddi.infoblox.dns.infobloxResponses, ddi.infoblox.dns.lameServers, ddi.infoblox.dns.network, ddi.infoblox.dns.notify, ddi.infoblox.dns.queries, ddi.infoblox.dns.queries_responses (union), ddi.infoblox.dns.queryErrors, ddi.infoblox.dns.rateLimit, ddi.infoblox.dns.resolver, ddi.infoblox.dns.rpz, ddi.infoblox.dns.security, ddi.infoblox.dns.unknown, ddi.infoblox.dns.update, ddi.infoblox.dns.updateSecurity, ddi.infoblox.dns.xferIn, ddi.infoblox.dns.xferOut, ddi.infoblox.nios, ddi.infoblox.nios.monitor, ddi.infoblox.nios.ntpd, ddi.infoblox.nios.ntpdate, ddi.infoblox.nios.rabbitmq_control, ddi.infoblox.nios.syslogNg, ddi.infoblox.unknown.unknown

## ddos - Distributed-Denial-of-Service

Arbor Networks Peakflow: ddos.arbor.peakflow.dos, ddos.arbor.peakflow.sp
Arbor Networks Pravail: ddos.arbor.pravail.aps
Huawei DDoS Protection Systems: ddos.huawei.antiddos, ddos.huawei.antiddos.sec

## devo - Devo platform

Devo collectors: devo.collector.metric, devo.collector.metric.input_stat, devo.collector.metric.message_sent, devo.collector.metric.output_stat
Devo Endpoint Agent: devo.ea (union), devo.ea.agent, devo.ea.agent.events_pubsub, devo.ea.agent.extensions, devo.ea.agent.flags, devo.ea.agent.info, devo.ea.agent.packs, devo.ea.agent.registry, devo.ea.agent.schedule, devo.ea.agent.status, devo.ea.extensions, devo.ea.extensions.fetchfiles_config, devo.ea.extensions.fetchfiles_info, devo.ea.unknown

## dhcp - Dynamic Host Configuration Protocol

Union tables: dhcp.all (union)
BlueCat DHCP server: dhcp.bluecat.dhcpd
Infoblox DHCP: dhcp.infoblox.stdout
ISC DHCP: dhcp.isc.stdout
Microsoft DHCP server: dhcp.microsoft.ip4, dhcp.microsoft.ip6
Unix DHCP server: dhcp.unix.stdout

## directory - Directory

Microsoft Active Directory: directory.msad.health, directory.msad.netlogon, directory.msad.siteinfo, directory.msad.snapshot, directory.msad.update
OpenLDAP: directory.openldap.access.event
Oracle Unified Directory: directory.oracle.sun_one.ldap_access
Red Hat: directory.redhat.389directory.access, directory.redhat.389directory.error

## dlp - Data Loss Prevention

Code 42 Incydr: dlp.code42.incydr.alerts, dlp.code42.incydr.audit, dlp.code42.incydr.file_expose
Endpoint Protector by CoSoSys (now part of Netwrix): dlp.cososys.endpoint_protector, dlp.cososys.endpoint_protector.system_logs, dlp.cososys.endpoint_protector.device_control, dlp.cososys.endpoint_protector.content_aware_protection, dlp.cososys.endpoint_protector.other
Digital Guardian Endpoint DLP: dlp.digitalguardian.endpointdlp.alerts, dlp.digitalguardian.endpointdlp.audit, dlp.digitalguardian.endpointdlp.events, dlp.digitalguardian.endpointdlp, dlp.digitalguardian.endpointdlp.classification
Digital Guardian Network DLP: dlp.digitalguardian.networkdlp, dlp.digitalguardian.networkdlp.events, dlp.digitalguardian.networkdlp.system
Digital Guardian Analytics & Reporting Cloud: dlp.digitalguardian.arc.events
Forcepoint One: dlp.forcepoint.events
Trellix Endpoint Security: dlp.trellix.epo.incident, dlp.trellix.dpim.incident

## dmarc - Domain-based Message Authentication, Reporting, and Conformance

Sendmarc DMARC: dmarc.sendmarc.bimi.domain, dmarc.sendmarc.bimi.selector, dmarc.sendmarc.dkim.domain, dmarc.sendmarc.dkim.public_key, dmarc.sendmarc.ip_address.aggregate_records_report, dmarc.sendmarc.ip_address.domain, dmarc.sendmarc.ip_address.sender, dmarc.sendmarc.ip_address.source, dmarc.sendmarc.sender.domain, dmarc.sendmarc.sender.domain_detail, dmarc.sendmarc.setting.dmarc, dmarc.sendmarc.setting.spf, dmarc.sendmarc.setting.sts, dmarc.sendmarc.volume.group_total, dmarc.sendmarc.volume.timeline, dmarc.sendmarc.volume.total

## dmp - Data Management Platform

Cohesity Helios: dmp.cohesity.helios.audit, dmp.cohesity.helios.alerts
Commvault: dmp.commvault.audit.event, dmp.commvault.alert.event
Egnity: dmp.egnyte.object_storage.comment, dmp.egnyte.object_storage.file_system, dmp.egnyte.object_storage.link, dmp.egnyte.object_storage.permission
Kiteworks data management platform: dmp.kiteworks.admin.event
Pure Storage: dmp.pure_storage.purity.audit, dmp.pure_storage.purity.event

## dns - Domain Name Systems

AWS Route 53: dns.aws.route53
BIND Name Server: dns.bind.info, dns.bind.query
BlueCat DNS: dns.bluecat.named, dns.bluecat.stats, dns.bluecat.stats.authquery, dns.bluecat.stats.authresponse, dns.bluecat.stats.clientquery, dns.bluecat.stats.clientresponse, dns.bluecat.stats.resolverquery, dns.bluecat.stats.resolverresponse, dns.bluecat.stats.updatequery, dns.bluecat.stats.updateresponse
Infoblox DNS: dns.infoblox.bloxonethreatdefense.threats, dns.infoblox.response
Neustar UltraDNS: dns.neustar.ultradns.config_audit, dns.neustar.ultradns.volume_report, dns.neustar.ultradns.zone_volume_report
Windows DNS: dns.windows

## drm - Digital Rights Management

Vera DRM: drm.vera.events

## drp - Digital Risk Protection

CloudSEK XVigil: drp.cloudsek.xvigil.alerts
Digital Shadows SearchLight: drp.digitalshadows.searchlight.alerts, drp.digitalshadows.searchlight.assets, drp.digitalshadows.searchlight.incidents, drp.digitalshadows.searchlight.triage_items

## dsp - Data Security Platform

Kiteworks (formerly known as Accellion) Secure File Transfer: dsp.accellion.sft.events
SafeNet Trusted Access: dsp.safenet.encryption.events
Vormetric Data Security Platform: dsp.vormetric.dsm.events

## dspm - Data Security Posture Management

Big ID Audit logs: dspm.bigid.audit.event

## edr - Endpoint Detection and Response

Union tables: edr.all.threats (union), edr.all.processes (union), edr.all.netconns (union)
BlackBerry Cylance: edr.blackberry.cylance.devices, edr.blackberry.cylance.optics_detections, edr.blackberry.cylance.optics_detections_rules, edr.blackberry.cylance.optics_detections_exceptions, edr.blackberry.cylance.policies, edr.blackberry.cylance.threats, edr.blackberry.cylance.users
Carbon Black: edr.carbonblack, edr.carbonblack.all (union), edr.carbonblack.alert, edr.carbonblack.binary, edr.carbonblack.feed, edr.carbonblack.ingress, edr.carbonblack.protect, edr.carbonblack.watchlist
Carbon Black Event Forwarder: edr.cbef, edr.cbef.alert, edr.cbef.alert.cb_analytics, edr.cbef.alert.watchlist, edr.cbef.endpoint_event, edr.cbef.endpoint_event.apicall, edr.cbef.endpoint_event.crossproc, edr.cbef.endpoint_event.filemod, edr.cbef.endpoint_event.moduleload, edr.cbef.endpoint_event.netconn, edr.cbef.endpoint_event.procend, edr.cbef.endpoint_event.procstart, edr.cbef.endpoint_event.regmod
Cisco Secure Endpoint (Formerly AMP for Endpoints): edr.cisco.amp.computers, edr.cisco.amp.events, edr.cisco.amp.vulnerabilities
Cortex XDR: edr.cortex_xdr.alerts, edr.cortex_xdr.alerts_multi, edr.cortex_xdr.alerts_multi_event, edr.cortex_xdr.incidents
CrowdStrike: edr.crowdstrike.cannon, edr.crowdstrike.cannon.additionalhostinfo, edr.crowdstrike.cannon.agentconnect, edr.crowdstrike.cannon.agentonline, edr.crowdstrike.cannon.arcfilewrtitten, edr.crowdstrike.cannon.asepkeyupdate, edr.crowdstrike.cannon.asepvalueupdate, edr.crowdstrike.cannon.associateindicator, edr.crowdstrike.cannon.associatetreeidwithroot, edr.crowdstrike.cannon.billinginfo, edr.crowdstrike.cannon.bitsjobcreated, edr.crowdstrike.cannon.bmpfilewritten, edr.crowdstrike.cannon.cabfilewritten, edr.crowdstrike.cannon.channeldatadownloadcomplete, edr.crowdstrike.cannon.channelversionrequired, edr.crowdstrike.cannon.commandhistory, edr.crowdstrike.cannon.configstateupdate, edr.crowdstrike.cannon.createservice, edr.crowdstrike.cannon.criticalenvironmentvariablechanged, edr.crowdstrike.cannon.criticalfileaccessed, edr.crowdstrike.cannon.currentsystemtags, edr.crowdstrike.cannon.dconline, edr.crowdstrike.cannon.dcstatus, edr.crowdstrike.cannon.dcsyncattempted, edr.crowdstrike.cannon.dcusbconfigurationdescriptor, edr.crowdstrike.cannon.dcusbdeviceblocked, edr.crowdstrike.cannon.dcusbdeviceconnected, edr.crowdstrike.cannon.dcusbdevicedisconnected, edr.crowdstrike.cannon.dcusbendpointdescriptor, edr.crowdstrike.cannon.dcusbhiddescriptor, edr.crowdstrike.cannon.dcusbinterfacedescriptor, edr.crowdstrike.cannon.deliverlocalfxtocloud, edr.crowdstrike.cannon.detectionexcluded, edr.crowdstrike.cannon.directorycreate, edr.crowdstrike.cannon.directorytraversaloversmb, edr.crowdstrike.cannon.diskcapacity, edr.crowdstrike.cannon.dllinjection, edr.crowdstrike.cannon.dmpfilewritten, edr.crowdstrike.cannon.dnsrequest, edr.crowdstrike.cannon.documentproograminjectedthread, edr.crowdstrike.cannon.driverload, edr.crowdstrike.cannon.dwgfilewritten, edr.crowdstrike.cannon.elffilewritten, edr.crowdstrike.cannon.endofprocess, edr.crowdstrike.cannon.errorevent, edr.crowdstrike.cannon.etwcomponentresponse, edr.crowdstrike.cannon.etwerrorevent, edr.crowdstrike.cannon.executabledeleted, edr.crowdstrike.cannon.falconservicestatus, edr.crowdstrike.cannon.filedeleted, edr.crowdstrike.cannon.filedeleteinfo, edr.crowdstrike.cannon.fileopeninfo, edr.crowdstrike.cannon.filerenameinfo, edr.crowdstrike.cannon.firewallchangeoption, edr.crowdstrike.cannon.firewalldeleterule, edr.crowdstrike.cannon.firewallsetrule, edr.crowdstrike.cannon.firmwareanalysishardwaredata, edr.crowdstrike.cannon.firmwareanalysisstatus, edr.crowdstrike.cannon.fspostopensnapshotfile, edr.crowdstrike.cannon.fsvolumemounted, edr.crowdstrike.cannon.fsvolumeunmounted, edr.crowdstrike.cannon.genericfilewritten, edr.crowdstrike.cannon.giffilewritten, edr.crowdstrike.cannon.gzipfilewritten, edr.crowdstrike.cannon.hostedservicestarted, edr.crowdstrike.cannon.hostedservicesttoped, edr.crowdstrike.cannon.hostinfo, edr.crowdstrike.cannon.hostnamechanged, edr.crowdstrike.cannon.imagehash, edr.crowdstrike.cannon.injectedthread, edr.crowdstrike.cannon.installedapplication, edr.crowdstrike.cannon.installedupdates, edr.crowdstrike.cannon.invalid, edr.crowdstrike.cannon.iosessionconnected, edr.crowdstrike.cannon.iosessionloggedon, edr.crowdstrike.cannon.jarfilewritten, edr.crowdstrike.cannon.javaclassfilewritten, edr.crowdstrike.cannon.jpegfilewritten, edr.crowdstrike.cannon.kernelmodeloadimage, edr.crowdstrike.cannon.lfodownloadconfirmation, edr.crowdstrike.cannon.localipaddressip4, edr.crowdstrike.cannon.localipaddressip6, edr.crowdstrike.cannon.localipaddressremovedip4, edr.crowdstrike.cannon.localipaddressremovedip6, edr.crowdstrike.cannon.lsasshandlefromunisgnedmodule, edr.crowdstrike.cannon.manifestdownloadcomplete, edr.crowdstrike.cannon.modifyservicebinary, edr.crowdstrike.cannon.neighborlistip4, edr.crowdstrike.cannon.neighborlistip6, edr.crowdstrike.cannon.netshareadd, edr.crowdstrike.cannon.netsharesecuritymodify, edr.crowdstrike.cannon.networkcapableasepwrite, edr.crowdstrike.cannon.networkcloseip4, edr.crowdstrike.cannon.networkcloseip6, edr.crowdstrike.cannon.networkconnectip4, edr.crowdstrike.cannon.networkconnectip6, edr.crowdstrike.cannon.networklistenip4, edr.crowdstrike.cannon.networklistenip6, edr.crowdstrike.cannon.networkreceiveacceptip4, edr.crowdstrike.cannon.networkreceiveacceptip6, edr.crowdstrike.cannon.newexecutablerenamed, edr.crowdstrike.cannon.newexecutablewritten, edr.crowdstrike.cannon.newscriptwritten, edr.crowdstrike.cannon.olefilewritten, edr.crowdstrike.cannon.ooxmlfilewritten, edr.crowdstrike.cannon.osversioninfo, edr.crowdstrike.cannon.other, edr.crowdstrike.cannon.packedexecutablewritten, edr.crowdstrike.cannon.pdffilewritten, edr.crowdstrike.cannon.pefilewritten, edr.crowdstrike.cannon.peversioninfo, edr.crowdstrike.cannon.pngfilewritten, edr.crowdstrike.cannon.privilegedprocesshandledfromunisgnedmodule, edr.crowdstrike.cannon.processinjection, edr.crowdstrike.cannon.processrollup2, edr.crowdstrike.cannon.processrollup2stats, edr.crowdstrike.cannon.processelfdeleted, edr.crowdstrike.cannon.promiscuousbindip4, edr.crowdstrike.cannon.queueapcetw, edr.crowdstrike.cannon.ransomwareopenfile, edr.crowdstrike.cannon.rarfilewritten, edr.crowdstrike.cannon.rawbindip4, edr.crowdstrike.cannon.rawbindip6, edr.crowdstrike.cannon.reflectivedotnetmoduleload, edr.crowdstrike.cannon.reggenericvalueupdate, edr.crowdstrike.cannon.registerrawinputdevicesetw, edr.crowdstrike.cannon.regsystemconfigvalueupdate, edr.crowdstrike.cannon.removablemediavolumemounted, edr.crowdstrike.cannon.resourceutilization, edr.crowdstrike.cannon.rtffilewritten, edr.crowdstrike.cannon.samhashdumpfromunsignedmodule, edr.crowdstrike.cannon.scheduledtaskdeleted, edr.crowdstrike.cannon.scheduledtaskmodified, edr.crowdstrike.cannon.scheduledtaskregistered, edr.crowdstrike.cannon.screenshottakenetw, edr.crowdstrike.cannon.scriptcontroldetectinfo, edr.crowdstrike.cannon.scriptcontrolerrorevent, edr.crowdstrike.cannon.scriptcontrolscantelemetry, edr.crowdstrike.cannon.sensitivewmiquery, edr.crowdstrike.cannon.sensorheartbeat, edr.crowdstrike.cannon.servicestarted, edr.crowdstrike.cannon.setwineventhooketw, edr.crowdstrike.cannon.sevenzipfilewritten, edr.crowdstrike.cannon.signinfoerror, edr.crowdstrike.cannon.signinfowithcertandcontext, edr.crowdstrike.cannon.signinfowithcontext, edr.crowdstrike.cannon.smbclientshareclosedetw, edr.crowdstrike.cannon.smbclientshareopenedetw, edr.crowdstrike.cannon.smbservershareopenedetw, edr.crowdstrike.cannon.snapshotvolumemounted, edr.crowdstrike.cannon.suspectcreatethreadstack, edr.crowdstrike.cannon.suspiciouscreatesymboliclink, edr.crowdstrike.cannon.suspiciousslackofprocessrollupevents, edr.crowdstrike.cannon.suspiciousprivilegedprocesshandle, edr.crowdstrike.cannon.suspiciousregasepupdate, edr.crowdstrike.cannon.syntheticprocessrollup2, edr.crowdstrike.cannon.systemcapacity, edr.crowdstrike.cannon.tarfilewritten, edr.crowdstrike.cannon.tcgpcrinfo, edr.crowdstrike.cannon.terminateprocess, edr.crowdstrike.cannon.tifffilewritten, edr.crowdstrike.cannon.tokenimpersonated, edr.crowdstrike.cannon.umppaerrorevent, edr.crowdstrike.cannon.umppcbypasssuspected, edr.crowdstrike.cannon.updatemanifestdownloadcomplete, edr.crowdstrike.cannon.useraccountaddedtogroup, edr.crowdstrike.cannon.userexceptiondep, edr.crowdstrike.cannon.userfontload, edr.crowdstrike.cannon.useridentity, edr.crowdstrike.cannon.userinformationetw, edr.crowdstrike.cannon.userlogoff, edr.crowdstrike.cannon.userlogon, edr.crowdstrike.cannon.userlogonfailed, edr.crowdstrike.cannon.userlogonfailed2, edr.crowdstrike.cannon.volumesnapshotcreated, edr.crowdstrike.cannon.volumesnapshotdeleted, edr.crowdstrike.cannon.wfpfiltertamperingfilteradded, edr.crowdstrike.cannon.wfpfiltertamperingfilterdeleted, edr.crowdstrike.cannon.wmicreateprocess, edr.crowdstrike.cannon.wmifilterconsumerbindingetw, edr.crowdstrike.cannon.wmiproviderregistrationetw, edr.crowdstrike.cannon.wroteexeandgeneratedserviceevent, edr.crowdstrike.cannon.zipfilewriten
CrowdStrike Falcon Discover: edr.crowdstrike.discover, edr.crowdstrike.discover.appinfo, edr.crowdstrike.discover.userinfo
CrowdStrike Falcon: edr.crowdstrike.falcon
CrowdStrike Falcon FileVantage: edr.crowdstrike.falcon_filevantage.change
CrowdStrike Falcon Event Streams: edr.crowdstrike.falconstreaming, edr.crowdstrike.falconstreaming.agents, edr.crowdstrike.falconstreaming.auth_activity, edr.crowdstrike.falconstreaming.behaviors, edr.crowdstrike.falconstreaming.cspm_ioa_streaming, edr.crowdstrike.falconstreaming.cspm_search_streaming, edr.crowdstrike.falconstreaming.customer_ioc, edr.crowdstrike.falconstreaming.detection_summary, edr.crowdstrike.falconstreaming.external_api, edr.crowdstrike.falconstreaming.firewall_match, edr.crowdstrike.falconstreaming.identity_protection, edr.crowdstrike.falconstreaming.idp_detection_summary, edr.crowdstrike.falconstreaming.incident_summary, edr.crowdstrike.falconstreaming.incidents, edr.crowdstrike.falconstreaming.mobile_detection_summary, edr.crowdstrike.falconstreaming.other, edr.crowdstrike.falconstreaming.recon_notification_summary, edr.crowdstrike.falconstreaming.remote_response_session, edr.crowdstrike.falconstreaming.scheduled_report_notification, edr.crowdstrike.falconstreaming.user_activity_all (union), edr.crowdstrike.falconstreaming.user_activity_detections, edr.crowdstrike.falconstreaming.user_activity_device_control_policy, edr.crowdstrike.falconstreaming.user_activity_devices, edr.crowdstrike.falconstreaming.user_activity_groups, edr.crowdstrike.falconstreaming.user_activity_ip_whitelist, edr.crowdstrike.falconstreaming.user_activity_other, edr.crowdstrike.falconstreaming.user_activity_prevention_policy, edr.crowdstrike.falconstreaming.user_quarantined_files, edr.crowdstrike.falconstreaming.user_activity_sensor_update_policy, edr.crowdstrike.falconstreaming.vulnerabilities, edr.crowdstrike.falconstreaming.indicators
CrowdStrike Falcon Insight: edr.crowdstrike.insight, edr.crowdstrike.insight.aidmaster, edr.crowdstrike.insight.managedassets, edr.crowdstrike.insight.notmanaged
Cybereason: edr.cybereason, edr.cybereason.api_malop, edr.cybereason.api_malware, edr.cybereason.malop, edr.cybereason.malware, edr.cybereason.useractions
Cylance PROTECT: edr.cylance, edr.cylance.app, edr.cylance.audit, edr.cylance.device, edr.cylance.devicecontrol, edr.cylance.memory, edr.cylance.optics, edr.cylance.optics.dns, edr.cylance.optics.file, edr.cylance.optics.log, edr.cylance.optics.memory, edr.cylance.optics.network, edr.cylance.optics.powershell, edr.cylance.optics.process, edr.cylance.optics.registry, edr.cylance.optics.wmi, edr.cylance.protect, edr.cylance.protect.app, edr.cylance.protect.audit, edr.cylance.protect.device, edr.cylance.protect.devicecontrol, edr.cylance.protect.memory, edr.cylance.protect.script, edr.cylance.protect.threats, edr.cylance.script, edr.cylance.threats
Darktrace RESPOND: edr.darktrace.respond.antigena, edr.darktrace.respond.incident_event, edr.darktrace.respond.model_breach, edr.darktrace.respond.status, edr.darktrace.respond.summary
FireEye Endpoint Detection & Response: edr.fireeye.alerts
Jamf Protect: edr.jamf.protect.alerts
Malwarebytes Nebula: edr.malwarebytes.nebula.detection, edr.malwarebytes.nebula.dns_logdata, edr.malwarebytes.nebula.event, edr.malwarebytes.nebula.notification, edr.malwarebytes.nebula.suspicious_activity, edr.malwarebytes.nebula.vulnerability
McAfee MVISION Endpoint: edr.mcafee.mvision.threat
Microsoft Defender Endpoint: edr.microsoft_defender.advanced_hunting.device_process_events, edr.microsoft_defender.alerts.events, edr.microsoft_defender.endpoint.alerts, edr.microsoft_defender.endpoint.assesment_secure_configuration, edr.microsoft_defender.endpoint.assesment_software_inventory, edr.microsoft_defender.endpoint.assesment_software_vulnerabilities, edr.microsoft_defender.endpoint.investigations, edr.microsoft_defender.endpoint.machines, edr.microsoft_defender.endpoint.recommendations, edr.microsoft_defender.endpoint.software, edr.microsoft_defender.endpoint.vulnerabilities, edr.microsoft_defender.iot_security.alert
Minerva Labs: edr.minervalabs
ObserveIT Insider Threat Detection: edr.observeit.events
Palo Alto Cortex XDR: edr.paloalto.cortex_xdr, edr.paloalto.cortex_xdr_agent
Palo Alto Networks Traps: edr.paloalto.traps
SentinelOne: edr.sentinelone.agent.agents, edr.sentinelone.agent.threats, edr.sentinelone.cloud_detection.alerts, edr.sentinelone.dv, edr.sentinelone.dv.cross_process, edr.sentinelone.dv.dns, edr.sentinelone.dv.driver, edr.sentinelone.dv.events, edr.sentinelone.dv.file, edr.sentinelone.dv.group, edr.sentinelone.dv.indicators, edr.sentinelone.dv.ip, edr.sentinelone.dv.logins, edr.sentinelone.dv.module, edr.sentinelone.dv.process, edr.sentinelone.dv.registry, edr.sentinelone.dv.scheduled_task, edr.sentinelone.management.activities
Superna Eyeglass Ransomware Defender: edr.superna.ransomware_defender.alarms, edr.superna.ransomware_defender.events
Symantec Endpoint Detection & Response: edr.symantec.events
Tanium: edr.tanium.action_history, edr.tanium.all_assets, edr.tanium.applicable_patches, edr.tanium.asset_report, edr.tanium.audit, edr.tanium.basic_asset, edr.tanium.client_status, edr.tanium.crowdstrike, edr.tanium.detect, edr.tanium.discover, edr.tanium.discover_lost, edr.tanium.events, edr.tanium.installedapps, edr.tanium.patch_list, edr.tanium.question, edr.tanium.threat_response, edr.tanium.threats
Trellix Endpoint Security: edr.trellix.epo.threat

## endpoint - Endpoint

Airlock Digital: endpoint.airlock.allowlist.audit
Bitdefender: endpoint.bitdefender.agent, endpoint.bitdefender.agent.active_host, endpoint.bitdefender.agent.active_host_ping, endpoint.bitdefender.agent.alert, endpoint.bitdefender.agent.connection_connect, endpoint.bitdefender.agent.ctc_raw_process_create, endpoint.bitdefender.agent.detection, endpoint.bitdefender.agent.external_notification_on_process, endpoint.bitdefender.agent.file_create, endpoint.bitdefender.agent.file_delete, endpoint.bitdefender.agent.file_modify, endpoint.bitdefender.agent.file_move, endpoint.bitdefender.agent.file_read, endpoint.bitdefender.agent.filescan_detection, endpoint.bitdefender.agent.generic_logging, endpoint.bitdefender.agent.interface_added, endpoint.bitdefender.agent.interface_change, endpoint.bitdefender.agent.log_on, endpoint.bitdefender.agent.log_out, endpoint.bitdefender.agent.logon_failed, endpoint.bitdefender.agent.network_connection, endpoint.bitdefender.agent.network_interfaces, endpoint.bitdefender.agent.process_create, endpoint.bitdefender.agent.process_create_execve, endpoint.bitdefender.agent.process_create_fork, endpoint.bitdefender.agent.process_signal, endpoint.bitdefender.agent.rca_insight, endpoint.bitdefender.agent.rca_insight_event, endpoint.bitdefender.agent.reg_delete_key, endpoint.bitdefender.agent.reg_delete_value, endpoint.bitdefender.agent.reg_modify_value, endpoint.bitdefender.agent.scheduled_task_create, endpoint.bitdefender.agent.service_added, endpoint.bitdefender.agent.terminate_process, endpoint.bitdefender.agent.user_account_settings_change, endpoint.bitdefender.agent.user_logout, endpoint.bitdefender.agent.user_session_list, endpoint.bitdefender.agent.user_specific_logging, endpoint.bitdefender.agent.xrca, endpoint.bitdefender.agent.xrca_event, endpoint.bitdefender.agent.modify_value, endpoint.bitdefender.gravityzone.product_modules_status
Carbon Black Protection: endpoint.carbonblack.protection
SentinelOne Singularity Mobile: endpoint.sentinelone.mobile.audit, endpoint.sentinelone.mobile.threat
Symantec Endpoint Protection Manager: endpoint.symantec.sepm.agent_activity, endpoint.symantec.sepm.agent_behavior, endpoint.symantec.sepm.agent_risk, endpoint.symantec.sepm.agent_scan, endpoint.symantec.sepm.agent_security, endpoint.symantec.sepm.agent_system, endpoint.symantec.sepm.agent_traffic, endpoint.symantec.sepm.others
VMware Carbon Black: endpoint.vmware.cbc_api.alerts, endpoint.vmware.cbc_defender.audit_logs, endpoint.vmware.cbc_event_forwarder, endpoint.vmware.cbc_event_forwarder.cb_analytics, endpoint.vmware.cbc_event_forwarder.endpoint_event_apicall, endpoint.vmware.cbc_event_forwarder.endpoint_event_crossproc, endpoint.vmware.cbc_event_forwarder.endpoint_event_fileless_scriptload, endpoint.vmware.cbc_event_forwarder.endpoint_event_filemod, endpoint.vmware.cbc_event_forwarder.endpoint_event_moduleload, endpoint.vmware.cbc_event_forwarder.endpoint_event_netconn, endpoint.vmware.cbc_event_forwarder.endpoint_event_procend, endpoint.vmware.cbc_event_forwarder.endpoint_event_procstart, endpoint.vmware.cbc_event_forwarder.endpoint_event_regmod, endpoint.vmware.cbc_event_forwarder.endpoint_event_scriptload, endpoint.vmware.cbc_event_forwarder.kognos_alerts, endpoint.vmware.cbc_event_forwarder.kognos_events, endpoint.vmware.cbc_event_forwarder.unknown, endpoint.vmware.cbc_liveops.live_query

## entity - Entity

Security Operations: entity.behavior.list.groups, entity.behavior.list.members, entity.behavior.list.notables, entity.behavior.risk.events, entity.behavior.signals.events

## epm - Endpoint Privilege Management

Endpoint Privilege Management: epm.beyondtrust.pmfw.event
CyberArk EPM: epm.cyberark.epm.admin_audit, epm.cyberark.epm.event, epm.cyberark.epm.policy_audit, epm.cyberark.epm.event_aggregated, epm.cyberark.epm.policy_audit_aggregated

## erp - Enterprise Resource Planning

PeopleSoft software: erp.peoplesoft.info

## firewall - Firewall

Union tables: firewall.all.cpu (union), firewall.all.ips (union), firewall.all.mem (union), firewall.all.traffic (union), firewall.all.virus (union), firewall.all.vpn.auth (union), firewall.all.vpn.traffic (union), firewall.all.webfilter (union)
Arista NG Firewall: firewall.arista.ng_firewall, firewall.arista.ng_firewall.applicationcontrollog, firewall.arista.ng_firewall.captiveportaluser, firewall.arista.ng_firewall.devicetable, firewall.arista.ng_firewall.firewall, firewall.arista.ng_firewall.hosttable, firewall.arista.ng_firewall.httprequest, firewall.arista.ng_firewall.httpresponse, firewall.arista.ng_firewall.interfacestat, firewall.arista.ng_firewall.intrusionpreventionlog, firewall.arista.ng_firewall.session, firewall.arista.ng_firewall.sessionminute, firewall.arista.ng_firewall.sessionnat, firewall.arista.ng_firewall.sessionstats, firewall.arista.ng_firewall.systemstat, firewall.arista.ng_firewall.threatprevention, firewall.arista.ng_firewall.threatpreventionhttp, firewall.arista.ng_firewall.tunnelstatus, firewall.arista.ng_firewall.virushttp, firewall.arista.ng_firewall.wanfailovertest, firewall.arista.ng_firewall.webfilter
Barracuda Firewall: firewall.barracuda.audit
Check Point Firewall: firewall.checkpoint.fw, firewall.checkpoint.gaia, firewall.checkpoint.gaia_system, firewall.checkpoint.lea, firewall.checkpoint.log_exporter
Cisco Adaptive Security Appliance (ASA) Software: firewall.cisco.asa
Cisco Secure Firewall Management Center (FMC): firewall.cisco.fmc, firewall.cisco.fmc_audit, firewall.cisco.fmc_other, firewall.cisco.fmc_system
Cisco FMC eStreamer: firewall.cisco.fmc_estreamer, firewall.cisco.fmc_estreamer.connection, firewall.cisco.fmc_estreamer.correlation, firewall.cisco.fmc_estreamer.event, firewall.cisco.fmc_estreamer.file_malware, firewall.cisco.fmc_estreamer.intrusion, firewall.cisco.fmc_estreamer.metadata, firewall.cisco.fmc_estreamer.packet, firewall.cisco.fmc_estreamer.rna, firewall.cisco.fmc_estreamer.rua
Cisco Firepower Threat Defense (FTD): firewall.cisco.ftd
Cisco Firewall Services Module (FWSM): firewall.cisco.fwsm
Cisco PIX (Private Internet eXchange): firewall.cisco.pix
Cisco SFIMS: firewall.cisco.sfims
F5 Web Application Firewall: firewall.f5.asm
Fortinet Firewall: firewall.fortinet, firewall.fortinet.anomaly.anomaly, firewall.fortinet.event, firewall.fortinet.event.admin, firewall.fortinet.event.config, firewall.fortinet.event.dhcp, firewall.fortinet.event.dns, firewall.fortinet.event.fgd, firewall.fortinet.event.ha, firewall.fortinet.event.hisPerformance, firewall.fortinet.event.ipsec, firewall.fortinet.event.pattern, firewall.fortinet.event.perf-historical, firewall.fortinet.event.router, firewall.fortinet.event.securityRating, firewall.fortinet.event.sslvpnSession, firewall.fortinet.event.sslvpnUser, firewall.fortinet.event.system, firewall.fortinet.event.user, firewall.fortinet.event.vpn, firewall.fortinet.event.wireless, firewall.fortinet.fortianalyzer.analyzer, firewall.fortinet.fortiedr.endpoint, firewall.fortinet.ips, firewall.fortinet.ips.anomaly, firewall.fortinet.securityevent, firewall.fortinet.securityevent.antiexploit, firewall.fortinet.securityevent.av, firewall.fortinet.securityevent.removablemediaaccess, firewall.fortinet.securityevent.sandboxing, firewall.fortinet.securityevent.sslvpn, firewall.fortinet.securityevent.vulnerabilityscan, firewall.fortinet.securityevent.webfilter, firewall.fortinet.systemevent, firewall.fortinet.systemevent.endpoint, firewall.fortinet.systemevent.system, firewall.fortinet.systemevent.update, firewall.fortinet.traffic, firewall.fortinet.traffic.allowed, firewall.fortinet.traffic.forward, firewall.fortinet.traffic.local, firewall.fortinet.traffic.multicast, firewall.fortinet.traffic.other, firewall.fortinet.traffic.violation, firewall.fortinet.utm.anomaly, firewall.fortinet.utm.appCtrl, firewall.fortinet.utm.dns, firewall.fortinet.utm.emailfilter, firewall.fortinet.utm.ips, firewall.fortinet.utm.ssh, firewall.fortinet.utm.ssl, firewall.fortinet.utm.virus, firewall.fortinet.utm.voip, firewall.fortinet.utm.webfilter
Huawei Next-Gen Firewall: firewall.huawei.ngfw, firewall.huawei.ngfw.aaa, firewall.huawei.ngfw.cm, firewall.huawei.ngfw.fw-log, firewall.huawei.ngfw.ifnet, firewall.huawei.ngfw.ifpdt, firewall.huawei.ngfw.info, firewall.huawei.ngfw.module, firewall.huawei.ngfw.mstp, firewall.huawei.ngfw.ntp, firewall.huawei.ngfw.sec, firewall.huawei.ngfw.shell, firewall.huawei.ngfw.spr, firewall.huawei.ngfw.ssh
Linux kernel firewall - iptables: firewall.iptables.std
Juniper Networks ISG Series: firewall.juniper.isg.system, firewall.juniper.isg.traffic
Juniper Network and Security Manager (NSM): firewall.juniper.nsm.traffic
Juniper SRX: firewall.juniper.srx.idp, firewall.juniper.srx.other, firewall.juniper.srx.probe, firewall.juniper.srx.system, firewall.juniper.srx.traffic, firewall.juniper.srx.utm
Juniper Networks SSG Series: firewall.juniper.ssg.system, firewall.juniper.ssg.traffic
Juniper Networks SSG Series: firewall.juniper.system, firewall.juniper.traffic
Firewall Meraki: firewall.meraki.events, firewall.meraki.flows, firewall.meraki.idsAlerts, firewall.meraki.urls
Firewall Palo Alto: firewall.paloalto.all (union), firewall.paloalto.auth, firewall.paloalto.config, firewall.paloalto.correlation, firewall.paloalto.decryption, firewall.paloalto.globalprotect, firewall.paloalto.hipmatch, firewall.paloalto.system, firewall.paloalto.threat, firewall.paloalto.traffic, firewall.paloalto.url, firewall.paloalto.userid
pfSense firewall: firewall.pfsense.everything, firewall.pfsense.filterlog, firewall.pfsense.firewall, firewall.pfsense.system
Sangfor Technologies: firewall.sangfor.app_control.event
SonicWall general: firewall.sonicwall.general, firewall.sonicwall.genv58
Sophos Firewall: firewall.sophos.general.system, firewall.sophos.securemail.smtp, firewall.sophos.securenet.ips, firewall.sophos.securenet.packetfilter, firewall.sophos.securenet.vpn, firewall.sophos.secureweb.eplog, firewall.sophos.secureweb.http, firewall.sophos.system.auth, firewall.sophos.system.confd, firewall.sophos.system.eplog, firewall.sophos.system.epsecd, firewall.sophos.system.ha, firewall.sophos.system.loadbalancing, firewall.sophos.system.misc, firewall.sophos.system.red, firewall.sophos.system.up2date, firewall.sophos.system.wifi, firewall.sophos.tagged, firewall.sophos.xgfirewall, firewall.sophos.xgfirewall.contentfiltering, firewall.sophos.xgfirewall.event, firewall.sophos.xgfirewall.firewall, firewall.sophos.xgfirewall.idp, firewall.sophos.xgfirewall.systemhealth, firewall.sophos.xgfirewall.wirelessprotection
StoneGate Firewall: firewall.stonegate.ips, firewall.stonegate.leef, firewall.stonegate.xml
Stormshield Network Security: firewall.stormshield.alarm, firewall.stormshield.auth, firewall.stormshield.connection, firewall.stormshield.filterstat, firewall.stormshield.monitor, firewall.stormshield.plugin, firewall.stormshield.pop3, firewall.stormshield.pvm, firewall.stormshield.sandboxing, firewall.stormshield.server, firewall.stormshield.smtp, firewall.stormshield.ssl, firewall.stormshield.system, firewall.stormshield.vpn, firewall.stormshield.web, firewall.stormshield.xvpn
VeloCloud Firewall: firewall.velocloud.traffic
Vyatta Firewall: firewall.vyatta.session_table, firewall.vyatta.traffic
WatchGuard Firewall: firewall.watchguard.traffic
Windows Firewall: firewall.windows.stdout

## ftp - File Transfer Protocol

Union tables: ftp.all.access (union)
CrushFTP: ftp.crushftp.event
Microsoft Internet Information Services (IIS) FTP Services: ftp.iis.access-w3c-all

## gateway - Gateway

Okta Access Gateway: gateway.okta.oag.access, gateway.okta.oag.audit, gateway.okta.oag.monitor
API Security Gateway: gateway.forum.system

## grc - Governance, Risk and Compliance

OneTrust: grc.onetrust.audit.profile_activity, grc.onetrust.audit.login_history

## helpdesk - Helpdesk

Zendesk: helpdesk.zendesk.audit.logs, helpdesk.zendesk.automations.all, helpdesk.zendesk.brands.all, helpdesk.zendesk.extended.fields, helpdesk.zendesk.groups.all, helpdesk.zendesk.groups.memberships, helpdesk.zendesk.macros.all, helpdesk.zendesk.organizations.all, helpdesk.zendesk.organizations.fields, helpdesk.zendesk.organizations.memberships, helpdesk.zendesk.recipients.addresses, helpdesk.zendesk.requests.all, helpdesk.zendesk.targets.all, helpdesk.zendesk.tickets.all, helpdesk.zendesk.tickets.fields, helpdesk.zendesk.tickets.forms, helpdesk.zendesk.triggers.all, helpdesk.zendesk.users.all, helpdesk.zendesk.views.all

## iam - Identity and Access Management

Broadcom SiteMinder: iam.broadcom.siteminder.audit, iam.broadcom.siteminder.auth
CyberArk: iam.cyberark.audit, iam.cyberark.identity.cloud_saas_application_applaunch, iam.cyberark.vault, iam.cyberark.vault_leef
Fortinet FortiAuthenticator: iam.fortinet.fortiauthenticator.events
Hitachi ID Password Manager: iam.hitachi.password.events
IBM WebSEAL: iam.ibm.webseal.audit
Imprivata: iam.imprivata.events
SailPoint IdentityNow: iam.sailpoint.events, iam.sailpoint.identitynow.account_activities, iam.sailpoint.identitynow.account_activity, iam.sailpoint.identitynow.event, iam.sailpoint.identitynow.events

## ids - Intrusion Detection Systems

Attivo BOTsink: ids.attivo.botsink
Bricata IDS: ids.bricata.alerts.all (union), ids.bricata.bro_broker, ids.bricata.bro_cluster, ids.bricata.bro_conn, ids.bricata.bro_dce_rpc, ids.bricata.bro_dhcp, ids.bricata.bro_dns, ids.bricata.bro_dns_hunt, ids.bricata.bro_dpd, ids.bricata.bro_files, ids.bricata.bro_ftp, ids.bricata.bro_http, ids.bricata.bro_irc, ids.bricata.bro_kerberos, ids.bricata.bro_notice, ids.bricata.bro_ntlm, ids.bricata.bro_ntp, ids.bricata.bro_observed_users, ids.bricata.bro_pe, ids.bricata.bro_rdp, ids.bricata.bro_reporter, ids.bricata.bro_smb_files, ids.bricata.bro_smb_mapping, ids.bricata.bro_smtp, ids.bricata.bro_snmp, ids.bricata.bro_software, ids.bricata.bro_ssl, ids.bricata.bro_tunnel, ids.bricata.bro_weird, ids.bricata.bro_x509, ids.bricata.broall, ids.bricata.brocata, ids.bricata.broconn, ids.bricata.burocata, ids.bricata.suricata
Bro IDS (now Zeek Network Security Monitor): ids.bro.captureloss, ids.bro.communication, ids.bro.conn, ids.bro.dce_rpc, ids.bro.dhcp, ids.bro.dns, ids.bro.dpd, ids.bro.files, ids.bro.ftp, ids.bro.http, ids.bro.kerberos, ids.bro.knownhosts, ids.bro.knownservices, ids.bro.notice, ids.bro.ntlm, ids.bro.ntp, ids.bro.packet_filter, ids.bro.pe, ids.bro.rdp, ids.bro.reporter, ids.bro.smb_files, ids.bro.smb_mapping, ids.bro.snmp, ids.bro.software, ids.bro.ssh, ids.bro.ssl, ids.bro.stats, ids.bro.weird, ids.bro.x509
Corelight: ids.corelight, ids.corelight.broker, ids.corelight.capture_loss, ids.corelight.cluster, ids.corelight.config, ids.corelight.conn, ids.corelight.conn_long, ids.corelight.conn_red, ds.corelight.connlong, ids.corelight.connmod, ids.corelight.connred, ids.corelight.corelight_metrics_suricata, ids.corelight.corelight_metrics_zeek_doctor, ids.corelight.corelight_service_status, ids.corelight.data_red, ids.corelight.datared, ids.corelight.dce_rpc, ids.corelight.dcerpc, ids.corelight.dhcp, ids.corelight.dnp3, ids.corelight.dns, ids.corelight.dns_red, ids.corelight.dnsred, ids.corelight.dpd, ids.corelight.encrypted_dns, ids.corelight.etc_viz, ids.corelight.files, ids.corelight.files_red, ids.corelight.filesred, ids.corelight.ftp, ids.corelight.generic_dns_tunnels, ids.corelight.generic_icmp_tunnels, ids.corelight.http, ids.corelight.http2, ids.corelight.http_red, ids.corelight.httpred, ids.corelight.intel, ids.corelight.ipsec, ids.corelight.irc, ids.corelight.kerberos, ids.corelight.known_certs, ids.corelight.known_devices, ids.corelight.known_domains, ids.corelight.known_hosts, ids.corelight.known_names, ids.corelight.known_remotes, ids.corelight.known_services, ids.corelight.known_users, ids.corelight.ldap, ids.corelight.ldap_search, ids.corelight.log4shell, ids.corelight.metrics_bro, ids.corelight.metrics_cpu, ids.corelight.metrics_disk, ids.corelight.metrics_docker, ids.corelight.metrics_iface, ids.corelight.metrics_memory, ids.corelight.metrics_s3, ids.corelight.metrics_sftp, ids.corelight.metrics_system, ids.corelight.metrics_utilization, ids.corelight.modbus, ids.corelight.mqtt_connect, ids.corelight.mqtt_subscribe, ids.corelight.mysql, ids.corelight.notice, ids.corelight.ntlm, ids.corelight.ntp, ids.corelight.overall_capture_loss, ids.corelight.pcr, ids.corelight.pe, ids.corelight.radius, ids.corelight.rdp, ids.corelight.reporter, ids.corelight.rfb, ids.corelight.sip, ids.corelight.smb_files, ids.corelight.smb_mapping, ids.corelight.smtp, ids.corelight.smtplinks, ids.corelight.snmp, ids.corelight.socks, ids.corelight.software, ids.corelight.ssh, ids.corelight.ssl, ids.corelight.ssl_red, ids.corelight.sslred, ids.corelight.stats, ids.corelight.stepping, ids.corelight.stun, ids.corelight.stun_nat, ids.corelight.suricata_corelight, ids.corelight.suricata_enhanced, ids.corelight.suricata_stats, ids.corelight.syslog, ids.corelight.traceroute, ids.corelight.tunnel, ids.corelight.weird, ids.corelight.weird_red, ids.corelight.weird_stats, ids.corelight.weirdmod, ids.corelight.x509, ids.corelight.x509_red, ids.corelight.x509red, ids.corelight.zeek_doctor
Darktrace platform: ids.darktrace.threats
ExtraHop solution: ids.extrahop.audit, ids.extrahop.cifs, ids.extrahop.crwd, ids.extrahop.detections, ids.extrahop.dhcp, ids.extrahop.dns, ids.extrahop.flow, ids.extrahop.ftp, ids.extrahop.http, ids.extrahop.kerberos, ids.extrahop.ldap, ids.extrahop.llmnr, ids.extrahop.mongodb, ids.extrahop.nfs, ids.extrahop.ntlm, ids.extrahop.rdp, ids.extrahop.rfb, ids.extrahop.rpc, ids.extrahop.ssh, ids.extrahop.ssl, ids.extrahop.telnet
Huawei NIP intrusion detection system (IDS): ids.huawei.nip, ids.huawei.nip.assoc, ids.huawei.nip.atk, ids.huawei.nip.iprpu
Juniper SRX Firewall: ids.juniper.srx
Reservoir R-Scope Advanced Threat Detection: ids.rscope (union), ids.rscope.communication, ids.rscope.conn, ids.rscope.dce_rpc, ids.rscope.dhcp, ids.rscope.dns, ids.rscope.dpd, ids.rscope.files, ids.rscope.ftp, ids.rscope.http, ids.rscope.intel, ids.rscope.irc, ids.rscope.kerberos, ids.rscope.known_hosts, ids.rscope.known_services, ids.rscope.modbus, ids.rscope.mysql, ids.rscope.notice, ids.rscope.ntlm, ids.rscope.pe, ids.rscope.protocolstats_orig, ids.rscope.protocolstats_resp, ids.rscope.radius, ids.rscope.rdp, ids.rscope.removed_files, ids.rscope.reporter, ids.rscope.rfb, ids.rscope.rscopestats_byte, ids.rscope.rscopestats_core, ids.rscope.rscopestats_misc, ids.rscope.rscopestats_pckt, ids.rscope.rscopestats_port, ids.rscope.rscopestats_sys, ids.rscope.sip, ids.rscope.smb_files, ids.rscope.smb_mapping, ids.rscope.smtp, ids.rscope.snmp, ids.rscope.socks, ids.rscope.software, ids.rscope.ssh, ids.rscope.ssl, ids.rscope.stats, ids.rscope.stderr, ids.rscope.stdout, ids.rscope.syslog, ids.rscope.tunnel, ids.rscope.weird, ids.rscope.x509
Snort Intrusion Detection (Open source): ids.snort.unified2
Suricata threat detection engine: ids.suricata.alert, ids.suricata.dns, ids.suricata.events, ids.suricata.fast, ids.suricata.fileinfo, ids.suricata.files, ids.suricata.ftp, ids.suricata.ftp_data, ids.suricata.http, ids.suricata.ikev2, ids.suricata.smb, ids.suricata.smtp, ids.suricata.ssh, ids.suricata.stats, ids.suricata.stdout, ids.suricata.tftp
Thinkst Canary: ids.thinkst_canary.canary.audit, ids.thinkst_canary.canary.bird, ids.thinkst_canary.canary.incident, ids.thinkst_canary.canary.token
Tripwire: ids.tripwire.audit
Wazuh: ids.wazuh.alerts
Zeek: ids.zeek.ssl

## infra - Infrastructure

Terraform: infra.terraform.app.archivist, infra.terraform.app.atlas, infra.terraform.app.build_manager, infra.terraform.app.build_worker, infra.terraform.app.other, infra.terraform.app.sidekiq, infra.terraform.app.slug_ingress, infra.terraform.audit.atlas, infra.terraform.audit.sidekiq

## ipaas - Integration Platform as a Service

Workato: ipaas.workato.audit, ipaas.workato.audit.account_property_created, ipaas.workato.audit.connection_updated, ipaas.workato.audit.connector_deleted, ipaas.workato.audit.folder_moved, ipaas.workato.audit.folder_renamed, ipaas.workato.audit.kms_policy_enabled, ipaas.workato.audit.message_template_created, ipaas.workato.audit.recipe_copied, ipaas.workato.audit.recipe_moved, ipaas.workato.audit.recipe_renamed, ipaas.workato.audit.recipe_started, ipaas.workato.audit.recipe_stopped, ipaas.workato.audit.recipe_updated, ipaas.workato.audit.switch_team

## ips - Intrusion Prevention Systems

Union tables: ips.all.alerts (union)
Cisco Security Device Event Exchange: ips.cisco.sdee.alerts, ips.cisco.sdee.sdee.collector
Cisco Sourcefire: ips.cisco.sourcefire.network
Cisco Sourcefire 3D: ips.cisco.sourcefire3d.snort
Corero: ips.corero.common
F5 BIG-IP Intrusion Prevention System: ips.f5.bigip
IBM SNP: ips.ibm.snp.audit
IBM Top Layer IPS: ips.toplayer.common
McAfee Network Security Manager: ips.mcafee.nsm, ips.mcafee.nsm.audit, ips.mcafee.nsm.events, ips.mcafee.nsm.fault
Proventia G Series: ips.proventia.gseries.audit, ips.proventia.gseries.event
IBM Proventia Management SiteProtector: ips.proventia.siteprotector.leef
Trend Micro TippingPoint Security Management System: ips.tippingpoint.sms

## itdr - Identity Threat Detection and Response

Oort AI: itdr.oort.ai.events

## itops - IT Operations

Automox API: itops.automox.api.package

## itrm - IT Risk Management

RSA: itrm.rsa.archer.events

## itsm - IT Service Management

ServiceNow: itsm.servicenow.cmdb.cmdbci, itsm.servicenow.cmdb.cmdbciappserver, itsm.servicenow.cmdb.cmdbcidbinstance, itsm.servicenow.cmdb.cmdbciinfraservice, itsm.servicenow.cmdb.cmdbciserver, itsm.servicenow.cmdb.cmdbciservice, itsm.servicenow.cmdb.cmdbcivm, itsm.servicenow.cmdb.cmdbrelci, itsm.servicenow.cmdb.cmnlocation, itsm.servicenow.login, itsm.servicenow.sysevent, itsm.servicenow.tables.change, itsm.servicenow.tables.event, itsm.servicenow.tables.incident, itsm.servicenow.tables.location, itsm.servicenow.tables.user, itsm.servicenow.transaction

## kms - Key Management Systems

Hashicorp Vault Audit: kms.hashicorp.vault.operational_logs, kms.hashicorp.vault.audit_logs
Venafi Certificate Management: kms.venafi.events

## mail - Email

Abnormal Security: mail.abnormalsecurity.cases, mail.abnormalsecurity.threats
Cisco Email Security Appliance: mail.cisco.esa.amp, mail.cisco.esa.antispam, mail.cisco.esa.antivirus, mail.cisco.esa.authentication, mail.cisco.esa.delivery, mail.cisco.esa.encryption, mail.cisco.esa.euq, mail.cisco.esa.graymail, mail.cisco.esa.scanning, mail.cisco.esa.sdr, mail.cisco.esa.status, mail.cisco.esa.stdout, mail.cisco.esa.system, mail.cisco.esa.text_mail, mail.cisco.esa.threatfeeds
Darktrace Email: mail.darktrace.detect_respond.event
Dovecot email server: mail.dovecot.audit
Egress Secure Mail: mail.egress.defend.phising_events
Microsoft Exchange Server: mail.exchange.messagetracking, mail.exchange.ncsa, mail.exchange.w3c
FortiMail - Secure Email Gateway: mail.fortinet.event.admin, mail.fortinet.event.config, mail.fortinet.event.ha, mail.fortinet.event.smtp, mail.fortinet.event.update, mail.fortinet.spam, mail.fortinet.statistics, mail.fortinet.virus.infected
Fortra’s Agari Phishing Defense: mail.agari.phishing_defense.policy_events, mail.agari.phishing_defense.messages
Gmail: mail.google.gmail.metadata
Google Apps: mail.googleapps.gat.audit, mail.googleapps.gat.auditDetached, mail.googleapps.gat.login
KnowBe4: mail.knowbe4.phisher.webhooks
McAfee Email Gateway: mail.mcafee.emailgateway
Mimecast Secure Email Gateway Mimecast Targeted Threat Protection: mail.mimecast.account.dashboard, mail.mimecast.archive, mail.mimecast.archive.messageview, mail.mimecast.archive.search, mail.mimecast.audit.events, mail.mimecast.message.list, mail.mimecast.message.summary, mail.mimecast.siem, mail.mimecast.siem.av, mail.mimecast.siem.delivery, mail.mimecast.siem.iep, mail.mimecast.siem.impersonation, mail.mimecast.siem.jrnl, mail.mimecast.siem.process, mail.mimecast.siem.receipt, mail.mimecast.siem.spameventthread, mail.mimecast.siem.ttp, mail.mimecast.thread.feed, mail.mimecast.ttp, mail.mimecast.ttp.attachment, mail.mimecast.ttp.attachment_protect, mail.mimecast.ttp.impersonation, mail.mimecast.ttp.url
Postfix mail server: mail.postfix
Proofpoint Email Protection: mail.proofpoint.pod (union), mail.proofpoint.pod.events, mail.proofpoint.pod.isolation, mail.proofpoint.pod.maillog, mail.proofpoint.pod.message, mail.proofpoint.sendmail, mail.proofpoint.stdout, mail.proofpoint.tapsiem, mail.proofpoint.tapsiem_syslog, mail.proofpoint.tapsiem_v2, mail.proofpoint.trap, mail.proofpoint.trap_incident
Simple Mail Transfer Protocol (SMTP): mail.smtp.as400alerts, mail.smtp.dlp, mail.smtp.general, mail.smtp.imssPolevt, mail.smtp.spamEti, mail.smtp.spamSpain, mail.smtp.spamTis, mail.smtp.spamTrap
Symantec Email Security Cloud: mail.symantec.email_security_cloud.all_email, mail.symantec.email_security_cloud.anti_spam, mail.symantec.email_security_cloud.clicktime, mail.symantec.email_security_cloud.ec_report, mail.symantec.email_security_cloud.email_delivery, mail.symantec.email_security_cloud.isolation, mail.symantec.email_security_cloud.malware
Trellix FireEye ETP: mail.trellix.etp.alert_summary, mail.trellix.etp.email_trace, mail.trellix.etp.user_activity_search, mail.trellix.etp.statistic
Trend Micro InterScan Messaging Security Suite (IMSS): mail.trend_micro.email_security.directory_user, mail.trend_micro.email_security.mail_tracking, mail.trend_micro.email_security.policy_event

## mainframe - Mainframes

IBM mainframe: mainframe.ibm.type80

## mdm - Mobile Device Management

Automox: mdm.automox.security.data_extracts, mdm.automox.security.devices, mdm.automox.security.events, mdm.automox.security.needs_attention, mdm.automox.security.policies, mdm.automox.security.policy_stats, mdm.automox.security.prepatch, mdm.automox.security.software_packages, mdm.automox.security.task_batches, mdm.automox.security.users, mdm.automox.security.users_api_keys, mdm.automox.security.worklet_catalog
Jamf Pro Mobile Device Management (MDM): mdm.jamf.events, mdm.jamf.pro, mdm.jamf.pro.computer_added, mdm.jamf.pro.computer_checkin, mdm.jamf.pro.computer_inventory_completed, mdm.jamf.pro.computer_patch_policy_completed, mdm.jamf.pro.computer_policy_finished, mdm.jamf.pro.computer_push_capability_changed, mdm.jamf.pro.device_added_to_dep, mdm.jamf.pro.jss_shutdown, mdm.jamf.pro.jss_startup, mdm.jamf.pro.mobile_device_checkin, mdm.jamf.pro.mobile_device_command_completed, mdm.jamf.pro.mobile_device_enrolled, mdm.jamf.pro.mobile_device_push_sent, mdm.jamf.pro.mobile_device_unenrolled, mdm.jamf.pro.patch_software_title_updated, mdm.jamf.pro.push_sent, mdm.jamf.pro.rest_api_operation, mdm.jamf.pro.scep_challenge

## mdr - Managed Detection and Response

Infocyte platform: mdr.infocyte.alertdetails

## metrics - Metrics

Other (no product named): metrics.esquilo, metrics.esquilo.kubernetes.core
Prometheus: metrics.prometheus

## monitor - Monitoring

Datadog Unified Observability and Security: monitor.datadog.archival, monitor.datadog.event, monitor.datadog.monitor
Dynatrace API: monitor.dynatrace.api.audit_log
Elastic Security: monitor.elastic.auditbeat.fileintegrity
Lacework: monitor.lacework.agent.applications, monitor.lacework.agent.connnections, monitor.lacework.agent.dns_query, monitor.lacework.agent.interfaces, monitor.lacework.agent.machine_summary, monitor.lacework.agent.new_hashes, monitor.lacework.agent.package, monitor.lacework.agent.process_summary, monitor.lacework.alerts.events, monitor.lacework.alerts, monitor.lacework.awscloudtrail.alert_details
MainView Monitoring (now BMC AMI Ops Monitoring): monitor.mainview.out
Nagios Network Monitoring : monitor.nagios
PagerDuty: monitor.pagerduty.alerts.events, monitor.pagerduty.audit.events, monitor.pagerduty.changes.events, monitor.pagerduty.incidents.events, monitor.pagerduty.log_entries.events, monitor.pagerduty.notifications.events
BMC PATROL Performance Management: monitor.patrol
Qualys FIM (File Integrity Monitoring): monitor.qualys.fim.incident, monitor.qualys.fim.event
Threat Stack, now called F5 Distributed Cloud App Infrastructure Protection (AIP): monitor.threatstack.alerts, monitor.threatstack.audit, monitor.threatstack.cve, monitor.threatstack.ec2, monitor.threatstack.events

## mq - Message Queueing

IBM WebSphere MQ (MQSeries) messaging middleware: mq.mqseries.error, mq.mqseries.errorfmt
RabbitMQ: mq.rabbitmq.out
Solace PubSub+ Connector for IBM MQ: mq.solace.pubsub365, mq.solace.pubsub365.client, mq.solace.pubsub365.system, mq.solace.pubsub365.vpn
Tibco Connector for IBM MQ: mq.tibco.ems.events

## nac - Network Access Control

Aruba ClearPass: nac.aruba.audit.all, nac.aruba.clearpass.audit, nac.aruba.clearpass.audit_records, nac.aruba.clearpass.configuration_audit, nac.aruba.clearpass.insight, nac.aruba.clearpass.session, nac.aruba.clearpass.system, nac.aruba.cppm, nac.aruba.cppm.endpoint, nac.aruba.cppm.policy, nac.aruba.cppm.system, nac.aruba.cppm.system_stat, nac.aruba.os.events, nac.aruba.other.events, nac.aruba.sessions.common, nac.aruba.sessions.failed_authentications, nac.aruba.sessions.radius, nac.aruba.sessions (union), nac.aruba.wifi.event
Extreme: nac.extreme.other.events, nac.extreme.switching.network_login
Forescout CounterACT : nac.forescout.counteract.actions, nac.forescout.counteract.common, nac.forescout.counteract.log, nac.forescout.counteract.policy, nac.forescout.counteract.system

## ndr - Network Detection and Response

ExtraHop Reveal(x): ndr.extrahop.revealx, ndr.extrahop.revealx360.alerts
Vectra Cognito Stream: ndr.vectra.cognito_stream, ndr.vectra.cognito_stream.dcerpc, ndr.vectra.cognito_stream.dhcp, ndr.vectra.cognito_stream.dns, ndr.vectra.cognito_stream.httpsessioninfo, ndr.vectra.cognito_stream.isession, ndr.vectra.cognito_stream.kerberos_txn, ndr.vectra.cognito_stream.ldap, ndr.vectra.cognito_stream.ntlm, ndr.vectra.cognito_stream.rdp, ndr.vectra.cognito_stream.smbfiles, ndr.vectra.cognito_stream.smbmapping, ndr.vectra.cognito_stream.smtp, ndr.vectra.cognito_stream.ssl, ndr.vectra.cognito_stream.x509
Vectra platform: ndr.vectra.platform.detection
Darktrace NDR: ndr.darktrace.action.event, ndr.darktrace.model_breach.event, ndr.darktrace.other.event, ndr.darktrace.system.event, ndr.darktrace.threat.event

## netstat - Network Statistics

Allot ClearSee Network Analytics: netstat.allot.clearsee.conv, netstat.allot.clearsee.flood, netstat.allot.clearsee.http_cdra, netstat.allot.clearsee.mou, netstat.allot.clearsee.sdr, netstat.allot.clearsee.udr, netstat.allot.clearsee.vc, netstat.allot.clearsee.vdr
GFI Exinda NetworkOrchestrator: netstat.exinda.orchestrator.stdout
NetFlow traffic: netstat.netflow.all (union), netstat.netflow.ipfix, netstat.netflow.lt, netstat.netflow.v9
Netmetrio: netstat.netmetrio.tcprtt.badIp4, netstat.netmetrio.tcprtt.ether, netstat.netmetrio.tcprtt.ip4, netstat.netmetrio.tcprtt.libpcap, netstat.netmetrio.tcprtt.pcap, netstat.netmetrio.tcprtt.tcp, netstat.netmetrio.tcprtt.tcprtt, netstat.netmetrio.tcprtt.tcprttError, netstat.netmetrio.tcprtt.tcprttInfo, netstat.netmetrio.tcprtt.udp
PCAP (Packet Capture): netstat.pcap.b16, netstat.pcap.b16simple
Ping: netstat.ping.collector, netstat.ping.stats
SNMP (Simple Network Management Protocol): netstat.snmp.collector, netstat.snmp.ifaces, netstat.snmp.ifacesAll, netstat.snmp.qosCisco, netstat.snmp.qosPortCisco, netstat.snmp.traps
Zscaler Analyzer: netstat.zscaler.analyzer, netstat.zscaler.analyzer_zpa

## network - Network

A10's Thunder Application Delivery Controller: network.a10.thunderAdc, network.a10.thunderAdc.acos, network.a10.thunderAdc.mgmt, network.a10.thunderAdc.system
Cisco network devices: network.cisco, network.cisco.router, network.cisco.switch, network.cisco.wireless, network.cisco.wcl
Citrix ADC: network.citrix.adc, network.citrix.adc.aaa, network.citrix.adc.aaatm, network.citrix.adc.api, network.citrix.adc.appfw, network.citrix.adc.cli, network.citrix.adc.console, network.citrix.adc.event, network.citrix.adc.gui, network.citrix.adc.ica, network.citrix.adc.nswl, network.citrix.adc.other, network.citrix.adc.routing, network.citrix.adc.snmp, network.citrix.adc.ssllog, network.citrix.adc.sslvpn, network.citrix.adc.tcp
Citrix NetScaler: network.citrix.netscaler.event, network.citrix.netscaler.misc, network.citrix.netscaler.snmp, network.citrix.netscaler.tcp
Dell SmartFabric OS10: network.dell.switch.smartfabric_os10
Union tables: network.dns (union)
F5 BIG-IP: network.f5.bigip, network.f5.bigip.audit, network.f5.bigip.gtm, network.f5.bigip.hslog, network.f5.bigip.ltm, network.f5.bigip.pktfilter, network.f5.bigip.system
HP printers: network.hp.printer.events
HP networking switches: network.hp.switch, network.hp.switch.addrmgr, network.hp.switch.auth, network.hp.switch.cdp, network.hp.switch.chassis, network.hp.switch.dhcp, network.hp.switch.ffi, network.hp.switch.ip, network.hp.switch.lldp, network.hp.switch.loopProtect, network.hp.switch.mgr, network.hp.switch.notice, network.hp.switch.ports, network.hp.switch.radius, network.hp.switch.sntp, network.hp.switch.ssh, network.hp.switch.stack, network.hp.switch.system, network.hp.switch.tftp, network.hp.switch.udpf, network.hp.switch.vlan
Juniper Wireless Access Point: network.juniper.wlc
Cisco Meraki: network.meraki, network.meraki.airmarshal_events, network.meraki.api_events, network.meraki.api_security_events, network.meraki.events, network.meraki.firewall, network.meraki.flows, network.meraki.idsAlerts, network.meraki.ip_flow_end, network.meraki.ip_flow_start, network.meraki.l7_firewall, network.meraki.security-event, network.meraki.switch, network.meraki.urls, network.meraki.vpn_firewall
Riverbed SteelHead: network.riverbed.steelhead.event
Riverbed SteelCentral: network.riverbed.steelcentral.audit
VeloCloud: network.velocloud.applianceevents, network.velocloud.events, network.velocloud.orchestratorevents
Versa networks: network.versa.av.events, network.versa.cgnat.events, network.versa.idp.events, network.versa.ngfw.access, network.versa.ngfw.identification, network.versa.ngfw.urlfiltering, network.versa.sdwan.b2bslam, network.versa.sdwan.slaviolation, network.versa.sdwan.traffic
VMware AirWatch: network.vmware.airwatch.events
VMware Unified Access Gateway: network.vmware.uag.events
Vyatta switches: network.vyatta.switch.arp, network.vyatta.switch.others

## ofd - Online Fraud Detection

SpyCloud ATO Prevention: ofd.spycloud.ato_prevention.watchlist

## pds - Plagiarism Detection Systems

Viper plagiarism detection: pds.pviper.stdout

## proxy - Proxy

Union tables: proxy.all.access (union)
Symantec ProxySG (formerly Proxy Blue Coat): proxy.bluecoat.proxysg.bcreportermain_v1, proxy.bluecoat.proxysg.leef, proxy.bluecoat.proxysg.main
Forcepoint ONE: proxy.forcepoint.access
Union tables: proxy.haproxy.all (union)
HAProxy Enterprise: proxy.haproxy.clf, proxy.haproxy.http, proxy.haproxy.tcp
Cisco Web Security (formerly IronPort Proxy Server): proxy.ironport.access.squid
Microsoft Forefront Threat Management Gateway (formerly Microsoft ISA Server): proxy.isaserver.accessW3cAb
McAfee Web Gateway: proxy.mcafee.webgw.accessAb, proxy.mcafee.webgw.default
Netskope Secure Web Gateway: proxy.netskope.events.transaction_events
OCLC EZproxy: proxy.oclc.ezproxy.accessClf
Squid caching proxy: proxy.squid.accessClf, proxy.squid.accessCombined, proxy.squid.accessLt, proxy.squid.accessSquid, proxy.squid.accessSquidMime, proxy.squid.cache
Stunnel TLS Proxy: proxy.stunnel.stdout
Varnish HTTP Cache: proxy.varnish.accessCombined, proxy.varnish.accessCombinedXff
Zscaler Secure Web Gateway: proxy.zscaler.access, proxy.zscaler.nss, proxy.zscaler.nss_firewall, proxy.zscaler.nss_web
Zscaler Internet Access (ZIA): proxy.zscaler.zia.alert, proxy.zscaler.zia.dns, proxy.zscaler.zia.firewall, proxy.zscaler.zia.saas_collaboration, proxy.zscaler.zia.saas_crm, proxy.zscaler.zia.saas_email, proxy.zscaler.zia.saas_file, proxy.zscaler.zia.saas_itsm, proxy.zscaler.zia.saas_repository, proxy.zscaler.zia.tunnel, proxy.zscaler.zia.web

## ras - Remote Access Servers

BeyondTrust: ras.beyondtrust.events
SecureLink remote support: ras.securelink.admin, ras.securelink.audit

## rbi - Remote Browser Isolation

Silo Web Isolation Platform: rbi.authentic8.silo, rbi.authentic8.silo.a8ss, rbi.authentic8.silo.admin_audit, rbi.authentic8.silo.auth, rbi.authentic8.silo.blocked_url, rbi.authentic8.silo.cookies, rbi.authentic8.silo.download, rbi.authentic8.silo.enc, rbi.authentic8.silo.exploit, rbi.authentic8.silo.location_change, rbi.authentic8.silo.post_data, rbi.authentic8.silo.print, rbi.authentic8.silo.session, rbi.authentic8.silo.translation, rbi.authentic8.silo.upload, rbi.authentic8.silo.url
Menlo Security Browser Isolation (inside the Menlo Security Cloud Platform): rbi.menlo.attachment, rbi.menlo.audit, rbi.menlo.email, rbi.menlo.smtp, rbi.menlo.web

## runtime - Runtime

Oracle Java Virtual Machine: runtime.jvm.advancedActivity, runtime.jvm.advancedError, runtime.jvm.advancedOutput, runtime.jvm.advancedTrace, runtime.jvm.basicActivity, runtime.jvm.basicError, runtime.jvm.basicOutput, runtime.jvm.basicTrace, runtime.jvm.nativememorysummary
Linux Perf performance analyzing tool: runtime.linuxperf.fct

## sase - Secure Access Service Edge

Appgate SDP: sase.appgate.sdp.events
Cato Networks: sase.cato.security, sase.cato.connectivity
Prisma SASE: sase.paloalto.prisma_access, sase.paloalto.prisma_access.globalprotect, sase.paloalto.prisma_access.threat, sase.paloalto.prisma_access.traffic, sase.paloalto.prisma_cloud.audit, sase.paloalto.prisma_cloud.cwp, sase.paloalto.prisma_saas.activity_monitoring, sase.paloalto.prisma_saas.admin_audit, sase.paloalto.prisma_saas.incident, sase.paloalto.prisma_saas.invalid, sase.paloalto.prisma_saas.other, sase.paloalto.prisma_saas.policy_violation, sase.paloalto.prisma_saas.remediation

## sast - Static Application Security Testing

Snyk SAST tools: sast.snyk.organization.audit

## sdn - Software-defined Networking

Aviatrix: sdn.aviatrix.controller, sdn.aviatrix.controller.auth, sdn.aviatrix.controller.cmd, sdn.aviatrix.controller.gateway, sdn.aviatrix.controller.gwnetstats, sdn.aviatrix.controller.gwsysstats, sdn.aviatrix.controller.syslog, sdn.aviatrix.controller.tunnel, sdn.aviatrix.controller.unknown

## seg - Secure Email Gateway

Check Point Harmony: seg.checkpoint.harmony.event

## sgsn - Serving GPRS Support Nodes

Ericsson SGSN-MME: sgsn.mme.ericsson

## siem - Security Information And Event Management

CrowdStrike Falcon LogScale: siem.crowdstrike.falcon_logscale.search
Trellix Helix: siem.trellix.helix.alerts

## sig - Secure Internet Gateways

Cisco Umbrella Secure Internet Gateway (SIG): sig.cisco.umbrella, sig.cisco.umbrella.audit, sig.cisco.umbrella.dlp, sig.cisco.umbrella.dns, sig.cisco.umbrella.firewall, sig.cisco.umbrella.intrusion, sig.cisco.umbrella.ip, sig.cisco.umbrella.proxy

## smp - SaaS Management Platform

BetterCloud Action Engine: smp.bettercloud.actionengine, smp.bettercloud.alerts, smp.bettercloud.audit, smp.bettercloud.workflow

## sms - Service Management Systems

Adaxes service management system: sms.adaxes.events

## soar - Security Orchestration, Automation, and Response

Devo SOAR: soar.devo.audit.casemanagement, soar.devo.audit.events, soar.devo.audit.flowexecutions, soar.devo.audit.integration, soar.devo.audit.mitreattackdetection, soar.devo.gc.events, soar.devo.raservice.events, soar.devo.service.events

## social - Social Networks

Salesforce: social.salesforce.opportunity
X (formerly known as Twitter): social.twitter.tweets.common, social.twitter.tweets.complete, social.twitter.tweets.trace

## ssm - System Software Management

APT (Advanced Packaging Tool) library: ssm.apt.history, ssm.apt.term
YUM (Yellowdog Updater Modified) library: ssm.yum.history, ssm.yum.term

## storage - Data Storage and Management

Huawei OceanStor: storage.huawei.oceanstor.alarm, storage.huawei.oceanstor.secure_log
NetApp ONTAP: storage.netapp.ontap.audit
DSM (DiskStation Manager): storage.synology.dsm.connection, storage.synology.dsm.events, storage.synology.dsm.system

## stream - Data Streaming

Confluent Platform: stream.confluent.kafka.controller, stream.confluent.kafka.server, stream.confluent.zookeeper
Apache Kafka: stream.kafka.kastle, stream.kafka.relay

## swg - Secure Web Gateway

Broadcom: swg.broadcom.wss.access

## tap - Targeted Attack Protection

Proofpoint TAP Isolation: tap.proofpoint.isolation.browser, tap.proofpoint.isolation.browser_and_email, tap.proofpoint.isolation.url

## threatintel - Threat Intelligence

Other (no product named): threatintel.anomaly.threatstream
AlienVault OTX (Open Threat eXchange): threatintel.alienvault_otx.pulses.indicators
ThreatBlockr (formerly Bandura ThreatBlockr): threatintel.bandura.threatblockr.dnslog, threatintel.bandura.threatblockr.dnsresplog, threatintel.bandura.threatblockr.packetlog
Cyble Vision: threatintel.cyble.vision.alert
Arachni Web Application Security Scanner Framework: threatintel.discovery.arachni.scan
Nmap Network Scanner: threatintel.discovery.nmap.scan
DomainTools Iris platform: threatintel.domaintools.whois
Threat Compass (formerly Blueliv Threat Compass): threatintel.external.blueliv.attackingips, threatintel.external.blueliv.credentials, threatintel.external.blueliv.credentialsettings, threatintel.external.blueliv.crimeservers, threatintel.external.blueliv.malware
DNS Changes channel: threatintel.farsight.dns.ch212, threatintel.farsight.dns.ch213
Flashpoint Platform: threatintel.flashpoint.intelligence.alerts
MISP Threat Sharing: threatintel.misp.attributenotifications, threatintel.misp.attributes, threatintel.misp.sighting.attributes, threatintel.misp.sighting.logs
SOCRadar's Extended Threat Intelligence: threatintel.socradar.xti.audit_logs, threatintel.socradar.xti.incidents, threatintel.socradar.xti.threat_feed
ThreatQ Platform: threatintel.threatquotient.platform, threatintel.threatquotient.platform.anonymization, threatintel.threatquotient.platform.commandandcontrol, threatintel.threatquotient.platform.compromisedpkicertificate, threatintel.threatquotient.platform.dosattack, threatintel.threatquotient.platform.exfiltration, threatintel.threatquotient.platform.hostcharacteristics, threatintel.threatquotient.platform.incident, threatintel.threatquotient.platform.logincompromise, threatintel.threatquotient.platform.malware, threatintel.threatquotient.platform.sighting, threatintel.threatquotient.platform.spearphish, threatintel.threatquotient.platform.sqlinjectionattack, threatintel.threatquotient.platform.userdefined, threatintel.threatquotient.platform.watchlist, threatintel.threatquotient.platform.wateringhole
Anomali ThreatStream Threat Intelligence Management: threatintel.threatstream, threatintel.threatstream.domain, threatintel.threatstream.email, threatintel.threatstream.ioccountbyhour, threatintel.threatstream.ip, threatintel.threatstream.itypes, threatintel.threatstream.md5, threatintel.threatstream.severities, threatintel.threatstream.string, threatintel.threatstream.url

## uba - User Behavior Analytics

Exabeam Security Analytics: uba.exabeam.notables, uba.exabeam.skyformation
Varonis Data Security Platform: uba.varonis.alerts, uba.varonis.audit, uba.varonis.dataalert

## ups - Uninterruptible Power Supply

SNMP Monitoring for APC Smart-UPS: ups.apc.snmp

## utm - Unified Threat Management

Cisco Web Secure Appliance: utm.cisco.wsa.accessStd, utm.cisco.wsa.trafficStd
Juniper Networks Advanced Threat Prevention (formerly of Cyphort): utm.hawkeye.cyphort
Sophos UTM system.log: utm.sophos.system

## vcs - Version Control Systems

GitHub: vcs.github.organization.audit, vcs.github.organization.dependabot, vcs.github.organization.sso_authorizations, vcs.github.organization.webhooks, vcs.github.repository.actions, vcs.github.repository.codescan, vcs.github.repository.collaborators, vcs.github.repository.commits, vcs.github.repository.dependabot_alerts, vcs.github.repository.events, vcs.github.repository.forks, vcs.github.repository.issue_comments, vcs.github.repository.pull_request_commits, vcs.github.repository.pull_requests, vcs.github.repository.releases, vcs.github.repository.stargazers, vcs.github.repository.subscribers, vcs.github.repository.subscriptions
GitLab: vcs.gitlab.audit, vcs.gitlab.organization.audit, vcs.gitlab.production, vcs.gitlab.repository, vcs.gitlab.repository.confidential_issue, vcs.gitlab.repository.confidential_note, vcs.gitlab.repository.deployment, vcs.gitlab.repository.feature_flag, vcs.gitlab.repository.groups, vcs.gitlab.repository.group_member, vcs.gitlab.repository.issue, vcs.gitlab.repository.job, vcs.gtlab.repository.key, vcs.gitlab.repository.merge_request, vcs.gitlab.repository.note, vcs.gitlab.repository.pipeline, vcs.gitlab.repository.project, vcs.gitlab.repository.push, vcs.gitlab.repository.release, vcs.gitlab.repository.repository_update, vcs.gitlab.repository.subgroup, vcs.gitlab.repository.tag_push, vcs.gitlab.repository.wiki_page, vcs.gitlab.shell

## vdi - Virtual Desktop Infrastructure

VMware Horizon: vdi.vmware.horizon, vdi.vmware.horizon.agent, vdi.vmware.horizon.connection_server, vdi.vmware.horizon.console

## vpc - Virtual Private Cloud

AWS Virtual Private Cloud: vpc.aws.flow

## vpn - Virtual Private Network

Absolute Software (formerly Netmotion): vpn.netmotion.mobility.event
Array Networks: vpn.arraynetworks.audit.events
Amazon Web Services (AWS): vpn.aws.client
Cisco AnyConnect: vpn.cisco.asa.anyconnect
Juniper VPN: vpn.juniper.sa, vpn.juniper.srx
Open VPN: vpn.openvpn.audit.events, vpn.openvpn.auth.failed, vpn.openvpn.auth.success, vpn.openvpn.system.events, vpn.openvpn.web.events
Pulse Secure: vpn.pulsesecure.audit, vpn.pulsesecure.sa
SoftEther VPN: vpn.soft_ether.packet_log.event, vpn.soft_ether.security_log.event, vpn.soft_ether.server_log.event
Zscaler: vpn.zscaler.access, vpn.zscaler.activity, vpn.zscaler.audit, vpn.zscaler.status_connector, vpn.zscaler.status_user

## vuln - Vulnerability Detection

BeyondTrust vulnerability management: vuln.beyondtrust.appaudit, vuln.beyondtrust.pbps, vuln.beyondtrust.retina
HackerOne: vuln.hackerone.audit.logs
Kenna: vuln.kenna.vm.assets_vulnerabilities
Nist: vuln.nist.cve.db
Onapsis: vuln.onapsis.osp.assessment, vuln.onapsis.osp.event, vuln.onapsis.osp.heartbeat
Qualys: vuln.qualys.hosts, vuln.qualys.hostdetections, vuln.qualys.useractivitylog, vuln.qualys.vulnerabilities
Rapid7 InsightVM: vuln.rapid7.insightvm.assets, vuln.rapid7.insightvm.audit, vuln.rapid7.insightvm.auth, vuln.rapid7.insightvm.scans, vuln.rapid7.insightvm.sites, vuln.rapid7.insightvm.vulnerabilities
Rapid7 Nexpose: vuln.rapid7.nexpose.asset, vuln.rapid7.nexpose.vuln
Risk Sense: vuln.risksense.host, vuln.risksense.hostfindings
Tenable: vuln.tenable.io.agents, vuln.tenable.io.assets, vuln.tenable.io.audit_log, vuln.tenable.io.plugins, vuln.tenable.io.scanners, vuln.tenable.io.scans, vuln.tenable.io.vulnerabilities, vuln.tenable.sc.organization

## waf - Web Application Firewalls

Cequence Unified API Protection Platform: waf.cequence.botdefense
F5 Distributed Cloud WAF: waf.f5.events
Fastly Next-Gen WAF: waf.fastly.nextgen_waf.corp_activity, waf.fastly.nextgen_waf.corp_event, waf.fastly.nextgen_waf.request_feed, waf.fastly.nextgen_waf.site_activity
FortiWeb web application firewall: waf.fortiweb, waf.fortiweb.attack, waf.fortiweb.event, waf.fortiweb.traffic
Kemp LoadMaster: waf.kemp.loadmaster, waf.kemp.loadmaster.alert, waf.kemp.loadmaster.audit
SecureSphere Web Application Firewall: waf.imperva.securesphere
Imperva Web Application Firewall (formerly Incapsula Web Application Firewall): waf.incapsula.audit, waf.incapsula.events, waf.incapsula.siemintegration
Radware API: waf.radware.api.user_activity, waf.radware.api.security_event
Salt Security API Protection Platform: waf.saltsecurity.attackers
Signal Sciences Web Application Firewall: waf.signalsciences.request

## web - Web

Union tables: web.all.access (union)
Other (no product named): web.ams.accessW3c
Apache HTTP Server Project: web.apache.accessClf, web.apache.accessCombined, web.apache.accessLt, web.apache.accessLtXff, web.apache.accessVhc, web.apache.error, web.apache.modJk, web.apache.modSecurity
Apache Tomcat web application server: web.tomcat.accessClf, web.tomcat.accessCombined, web.tomcat.accessLt, web.tomcat.app, web.tomcat.appLt, web.tomcat.catalina, web.tomcat.catalinaLt, web.tomcat.tomcat_gc, web.tomcat.out
Arbor Solutions (now part of NETSCOUT): web.arbor.access
Amazon Web Services: web.aws.alb.access, web.aws.cloudfront.accessW3c, web.aws.elb.access, web.aws.s3.access
Edgio solutions (formerly Edgecast): web.edgecast.accessW3c
GlassFish Application Server: web.glassfish.server
IBM InfoSphere Information Server: web.iis.accessNcsa, web.iis.accessW3c, web.iis.accessW3cAll
IBM WebSphere Application Server: web.websphere.error, web.websphere.gc, web.websphere.gcStdout, web.websphere.gcSummary, web.websphere.out
WebSEAL: web.webseal.accessCombined
Oracle iPlanet Web Server: web.iplanet.accessClf2, web.iplanet.error
WildFly Web Server (formerly JBoss Web Server): web.jboss.accessClf, web.jboss.accessCombined, web.jboss.accessLt, web.jboss.boot, web.jboss.server
Level3 web server: web.level3.accessW3c
NGINX webserver: web.nginx.accessCombined, web.nginx.accessLt, web.nginx.accessLtXff, web.nginx.accessMain, web.nginx.error

## xdr - Extended Detection and Response

Cynet XDR: xdr.cynet, xdr.cynet.alerts.events, xdr.cynet.audit.events, xdr.cynet.va, xdr.cynet.va.agents, xdr.cynet.va.installed_softwares, xdr.cynet.va.patch_validation, xdr.cynet.va.patches, xdr.cynet.va.risky_apps
Mandiant: xdr.mandiant.threatintel.dtm_alert
Trend Micro: xdr.trend_micro.vision_one.alerts, xdr.trend_micro.vision_one.audit, xdr.trend_micro.vision_one.observed_attack_techniques
