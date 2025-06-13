import os
import tldextract

log_file_path = "./log.txt"

sources_folder_path = "./sources"
fqdn_folder_path = os.path.join(sources_folder_path, 'fqdn')

whitelist_allowed_file_path = os.path.join(fqdn_folder_path, 'allowed_domains.txt')
whitelist_allowed_except_subdomains_file_path = os.path.join(fqdn_folder_path, 'allowed_domains_except_listed_subdomains.txt')

blocklist_registered_file_paths = [
    os.path.join(fqdn_folder_path, 'explicit_registered_domains.txt'), 
    os.path.join(fqdn_folder_path, 'proxy_registered_domains.txt')
]
blocklist_subdomain_file_paths = [
    os.path.join(fqdn_folder_path, 'explicit_subdomains.txt')
]

curation_folder_path = "./curation"
unbound_folder_path = os.path.join(curation_folder_path, 'unbound')
all_domains_file_path = os.path.join(unbound_folder_path, 'all_domains.txt')
wildcard_domains_file_path = os.path.join(unbound_folder_path, 'wildcard_domains.txt')
subdomains_file_path = os.path.join(unbound_folder_path, 'subdomains.txt')

try:
    with open(log_file_path, 'w') as output:
        
        full_and_registered_domain_pairs = set()

        for file_path in (blocklist_registered_file_paths + blocklist_subdomain_file_paths):
            try:
                with open(file_path, 'r') as file:
                    lines = file.readlines()
    
                    for line_number, line in enumerate(lines, start=1): 
                        domain = line.strip()
                        if not domain:
                            log_message = f"Error: Blank on line {line_number} in file {file_path}\n"
                            output.write(log_message)
                            continue
    
                        extracted = tldextract.extract(domain)
                        registered_domain = extracted.registered_domain
    
                        if registered_domain:
                            registered_domains.add((registered_domain, domain))
                        else:
                            log_message = f"Error: Invalid domain '{domain}' on line {line_number} in file {file_path}\n"
                            output.write(log_message)
            except FileNotFoundError:
                log_message = f"Error: File not found: {file_path}"
                output.write(log_message)

        whitelisted_allowed_domains = set()
        if os.path.exists(whitelist_allowed_file_path):
            with open(whitelist_allowed_file_path, 'r') as file:
                whitelist_lines = file.readlines()
    
            for line_number, line in enumerate(whitelist_lines, start=1):
                domain = line.strip() 
                if not domain:
                    log_message = f"Error: Blank in whitelist file on line {line_number}\n"
                    output.write(log_message)
                    continue
    
                extracted = tldextract.extract(domain)
                registered_domain = extracted.registered_domain
    
                if registered_domain:
                    whitelisted_allowed_domains.add(registered_domain)
                else:
                    log_message = f"Error: Invalid domain in whitelist file on line {line_number}: '{domain}'\n"
                    output.write(log_message)
        else:
            log_message = f"Warning: Whitelist file '{whitelist_allowed_file_path}' not found. No domains were whitelisted from it.\n"
            output.write(log_message)

        whitelisted_allowed_except_subdomains_domains = set()
        if os.path.exists(whitelist_allowed_except_subdomains_file_path):
            with open(whitelist_allowed_except_subdomains_file_path, 'r') as file:
                whitelist_lines = file.readlines()
    
            for line_number, line in enumerate(whitelist_lines, start=1):
                domain = line.strip() 
                if not domain:
                    log_message = f"Error: Blank in whitelist file on line {line_number}\n"
                    output.write(log_message)
                    continue
    
                extracted = tldextract.extract(domain)
                registered_domain = extracted.registered_domain
    
                if registered_domain:
                    whitelisted_allowed_except_subdomains_domains.add(registered_domain)
                else:
                    log_message = f"Error: Invalid domain in whitelist file on line {line_number}: '{domain}'\n"
                    output.write(log_message)
        else:
            log_message = f"Warning: Whitelist file '{whitelist_allowed_except_subdomains_file_path}' not found. No domains were whitelisted from it.\n"
            output.write(log_message)

        final_wildcard_domains = set()
        final_subdomains = set()
        for registered_domain, full_domain in full_and_registered_domain_pairs:
            if registered_domain in whitelisted_allowed_domains:
                continue
            elif registered_domain in whitelisted_allowed_except_subdomains_domains:
                final_subdomains.add(f"{full_domain}\n")
            else:
                final_wildcard_domains.add(f"*.{registered_domain}\n")
    
        sorted_wildcard_domains = sorted(final_wildcard_domains)
        sorted_subdomains = sorted(subdomains)

        with open(all_domains_file_path, 'w') as file:
            file.writelines(sorted_subdomains)
            file.writelines(sorted_wildcard_domains)
        
        with open(wildcard_domains_file_path, 'w') as file:
            file.writelines(sorted_wildcard_domains)

        with open(subdomains_file_path, 'w') as file:
            file.writelines(sorted_subdomains)

        log_message = "Processing complete\n"
        output.write(log_message)
        
except FileNotFoundError:
    sys.exit()
