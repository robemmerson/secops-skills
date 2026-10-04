from cloud.azure.ad.signin
where properties_status_errorCode in {50126, 50053, 50057, 50055, 50034}
group by properties_ipAddress, properties_userPrincipalName, properties_status_errorCode, properties_appDisplayName, properties_clientAppUsed, properties_location_countryOrRegion
select count() as n, min(eventdate) as first, max(eventdate) as last
