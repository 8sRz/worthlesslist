import os
import tldextract

log_file_path = "./log.txt"

sources_folder_path = "./sources"
fqdn_folder_path = os.path.join(sources_folder_path, 'fqdn')

whitelist_allow_file_path = os.path.join(fqdn_folder_path, 'allow_always.txt')
whitelist_allow_if_unspecified_file_path = os.path.join(fqdn_folder_path, 'allow_if_unspecified.txt')

blocklist_file_paths = [
    os.path.join(fqdn_folder_path, 'explicit.txt'), 
    os.path.join(fqdn_folder_path, 'proxy.txt')
]

curation_folder_path = "./curation"
unbound_folder_path = os.path.join(curation_folder_path, 'unbound')
all_file_path = os.path.join(unbound_folder_path, 'all.txt')
wildcard_file_path = os.path.join(unbound_folder_path, 'wildcard.txt')
subdomain_file_path = os.path.join(unbound_folder_path, 'subdomain.txt')

try:
    with open(log_file_path, 'w') as output:
        
        whitelist_allow_domains = set()
        if os.path.exists(whitelist_allow_file_path):
            with open(whitelist_allow_file_path, 'r') as file:
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
                    whitelist_allow_domains.add(registered_domain)
                else:
                    log_message = f"Error: Invalid domain in whitelist file on line {line_number}: '{domain}'\n"
                    output.write(log_message)
        else:
            log_message = f"Warning: Whitelist file '{whitelist_allow_file_path}' not found. No domains were whitelisted from it.\n"
            output.write(log_message)
        

        whitelist_allow_if_unspecified_domains = set()
        if os.path.exists(whitelist_allow_if_unspecified_file_path):
            with open(whitelist_allow_if_unspecified_file_path, 'r') as file:
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
                    whitelist_allow_if_unspecified_domains.add(registered_domain)
                else:
                    log_message = f"Error: Invalid domain in whitelist file on line {line_number}: '{domain}'\n"
                    output.write(log_message)
        else:
            log_message = f"Warning: Whitelist file '{whitelist_allow_if_unspecified_file_path}' not found. No domains were whitelisted from it.\n"
            output.write(log_message)


        registered_domains = set()
        subdomains = set()

        for file_path in blocklist_file_paths:
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
                        fqdn = extracted.fqdn
                        registered_domain = extracted.registered_domain
    
                        if fqdn and registered_domain:
                            if registered_domain in whitelist_allow_domains:
                                continue
                            elif fqdn != registered_domain and registered_domain in whitelist_allow_if_unspecified_domains:
                                subdomains.add(fqdn)
                            else:
                                registered_domains.add(registered_domain)
                        else:
                            log_message = f"Error: Invalid domain '{domain}' on line {line_number} in file {file_path}\n"
                            output.write(log_message)
            except FileNotFoundError:
                log_message = f"Error: File not found: {file_path}"
                output.write(log_message)

        final_wildcard_domains = set()
        final_subdomains = set()

        for domain in registered_domains:
            final_wildcard_domains.add(f"*.{domain}\n")

        for domain in subdomains:
            final_subdomains.add(f"{domain}\n")
                
        sorted_wildcard_domains = sorted(final_wildcard_domains)
        sorted_subdomains = sorted(final_subdomains)

        with open(all_file_path, 'w') as file:
            file.writelines(sorted_subdomains)
            file.writelines(sorted_wildcard_domains)
        
        with open(wildcard_file_path, 'w') as file:
            file.writelines(sorted_wildcard_domains)

        with open(subdomain_file_path, 'w') as file:
            file.writelines(sorted_subdomains)

        log_message = "Processing complete\n"
        output.write(log_message)
        
except FileNotFoundError:
    sys.exit()
