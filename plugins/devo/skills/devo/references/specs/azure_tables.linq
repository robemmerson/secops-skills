from siem.logtrust.collector.counter
where kind = "table", weakhas(object, "azure")
group by object
select sum(events) as events
