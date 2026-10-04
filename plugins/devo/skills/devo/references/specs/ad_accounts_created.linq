from box.win_nxlog.security
where EventID = 4720
group by host, SubjectUserName, SubjectUserSid, SubjectDomainName, TargetUserName, TargetSid
select count() as n, min(eventdate) as first, max(eventdate) as last
