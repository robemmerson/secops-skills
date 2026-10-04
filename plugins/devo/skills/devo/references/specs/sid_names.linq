from box.win_nxlog.security
where EventID = 4624, TargetUserSid -> "S-1-5-21-"
group by TargetUserSid, TargetDomainName, TargetUserName
select count() as n
