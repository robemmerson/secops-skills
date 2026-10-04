from edr.sentinelone.agent.threats
where weakhas(threatInfo__filePath, "{file}") or threatInfo__sha256 = "{sha256}"
group by agentRealtimeInfo__agentComputerName, threatInfo__threatName, threatInfo__filePath, threatInfo__sha256, threatInfo__mitigationStatus, threatInfo__analystVerdict
select count() as n, min(eventdate) as first, max(eventdate) as last
