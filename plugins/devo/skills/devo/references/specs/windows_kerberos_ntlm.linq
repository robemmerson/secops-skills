from box.win_nxlog.security
where EventID in {4771, 4776}
group by host, EventID, Status
select count() as n, min(eventdate) as first, max(eventdate) as last
