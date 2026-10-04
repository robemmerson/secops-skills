from box.unix
where appName in {"sshd", "sshd-session"}, has(message, "Failed password", "Invalid user", "authentication failure", "Failed publickey", "maximum authentication attempts")
select peek(message, re("(Failed \\S+|Invalid user|authentication failure|maximum authentication attempts)"), 1) as what,
  peek(message, re("(?:for invalid user |for |Invalid user |user=)(\\S+)"), 1) as account,
  peek(message, re("(?:from |rhost=)([0-9a-fA-F:.]+)"), 1) as src
group by machine, what, account, src
select count() as n, min(eventdate) as first, max(eventdate) as last
