from cloud.office365.management.threatintelligence
where weakhas(FileData_FileName, "{file}") or weakhas(message, "{file}")
select parsedate(str(jsonparse(message)["CreationTime"]), "YYYY-MM-DD[T]HH:mm:ss", "UTC") as event_time
group by Operation, UserId, FileData_FileName, FileData_SHA256
select count() as n, min(event_time) as first_event, max(event_time) as last_event
