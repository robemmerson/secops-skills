from cloud.office365.management.sharepoint
where weakhas(SourceFileName, "{file}") or weakhas(ObjectId, "{file}")
select parsedate(str(jsonparse(message)["CreationTime"]), "YYYY-MM-DD[T]HH:mm:ss", "UTC") as event_time
group by Operation, UserId, ClientIP, SourceFileName, SiteUrl
select count() as n, min(event_time) as first_event, max(event_time) as last_event
