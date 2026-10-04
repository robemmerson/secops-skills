from cloud.azure.others.events
where weakhas(category, "CloudAuditEvents")
select str(jqeval(jqcompile(".DataSource"), properties)) as data_source
group by data_source
select count() as n
