from cloud.azure.ad.noninteractive_user_signin
where properties_status_errorCode = 0
group by properties_ipAddress, properties_userPrincipalName
select count() as n
