from cloud.office365.management.exchange
where weakhas(message, "{file}")
select parsedate(str(jsonparse(message)["CreationTime"]), "YYYY-MM-DD[T]HH:mm:ss", "UTC") as event_time
group by Operation, UserId
select count() as n, min(event_time) as first_event, max(event_time) as last_event
