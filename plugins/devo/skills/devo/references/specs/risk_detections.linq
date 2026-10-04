from cloud.azure.ad.user_risk_events
group by properties__riskEventType, properties__riskLevel, properties__riskState, properties__userPrincipalName, properties__ipAddress
select count() as n, min(eventdate) as first, max(eventdate) as last
