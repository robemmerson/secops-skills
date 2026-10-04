from box.win_nxlog.security
where EventID in {4728, 4729, 4732, 4733, 4756, 4757}
group by host, EventID, TargetUserName, SubjectUserName, SubjectUserSid, SubjectDomainName, MemberName, MemberSid
select count() as n, min(eventdate) as first, max(eventdate) as last
