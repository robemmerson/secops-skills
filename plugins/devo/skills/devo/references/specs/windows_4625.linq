from box.win_nxlog.security
where EventID = 4625
select peek(Message, re("Source Network Address:\\s*([^\\r\\n\\t]+)"), 1) as src
group by host, src, TargetUserName, WorkstationName, Status, SubStatus, LogonType, AuthenticationPackageName
select count() as n, min(eventdate) as first, max(eventdate) as last
