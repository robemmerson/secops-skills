from cloud.azure.ah.device_file_event
where weakhas(file_name, "{file}") or sh_a256 = "{sha256}"
group by device_name, action_type, folder_path, file_name, sh_a256, init_process_file_name, init_process_account_upn, file_origin_url
select count() as n, min(timestamp) as first_event, max(timestamp) as last_event
