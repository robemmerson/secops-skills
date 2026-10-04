from cloud.azure.ah.device_process_event
where weakhas(process_command_line, "{file}")
group by device_name, account_name, file_name, init_process_file_name
select count() as n, min(timestamp) as first_event, max(timestamp) as last_event
