import os
import tldextract

# Path to the folder containing the input and output files
in_folder_path = "./sources"
out_folder_path = "./output"

# File paths
blocklist_file_paths = [os.path.join(in_folder_path, 'explicit_video.txt'), os.path.join(in_folder_path, 'proxy.txt')]
whitelist_file_path = os.path.join(in_folder_path, 'essential.txt')

apex_unbound_file_path = os.path.join(out_folder_path, 'apex_unbound.txt')
subdomain_file_path = os.path.join(out_folder_path, 'essential.txt')
log_file_path = os.path.join(out_folder_path, 'log.txt')  # Output log file

# Open output file for writing logs
with open(log_file_path, 'w') as output:

    # Initialize sets for registered domains and subdomains
    registered_domains = set()
    subdomains = set()

    for file_path in blocklist_file_paths:
        try:
            with open(file_path, 'r') as file:
                lines = file.readlines()

                # Process each line in source.txt
                for line_number, line in enumerate(lines, start=1):  # Keep track of line numbers
                    domain = line.strip()  # Remove any leading/trailing whitespace
                    if not domain:  # Skip empty lines
                        log_message = f"Error: Blank on line {line_number}\n"
                        output.write(log_message)
                        continue

                    # Extract the registered domain using tldextract
                    extracted = tldextract.extract(domain)
                    registered_domain = extracted.registered_domain

                    if registered_domain:
                        registered_domains.add((registered_domain, domain))  # Store both registrable and full domain
                    else:
                        # Log an error if the domain is invalid
                        log_message = f"Error: Invalid domain on line {line_number}: '{domain}'\n"
                        output.write(log_message)
        except FileNotFoundError:
            log_message = f"Error: File not found: {file_path}"
            output.write(log_message)

    # Read domains from whitelists.txt
    whitelisted_domains = set()
    if os.path.exists(whitelist_file_path ):
        with open(whitelist_file_path , 'r') as file:
            whitelist_lines = file.readlines()

        # Process the whitelist domains
        for line_number, line in enumerate(whitelist_lines, start=1):
            domain = line.strip()  # Remove any leading/trailing whitespace
            if not domain:  # Skip empty lines
                log_message = f"Error: Blank in whitelist file on line {line_number}\n"
                output.write(log_message)
                continue

            # Extract the registered domain using tldextract
            extracted = tldextract.extract(domain)
            registered_domain = extracted.registered_domain

            if registered_domain:
                whitelisted_domains.add(registered_domain)
            else:
                # Log an error if the domain is invalid
                log_message = f"Error: Invalid domain in whitelist file on line {line_number}: '{domain}'\n"
                output.write(log_message)
    else:
        log_message = f"Warning: Whitelist file '{whitelist_file_path }' not found. No domains were whitelisted.\n"
        output.write(log_message)

    # Process registered domains and filter out subdomains
    final_registered_domains = set()
    for registered_domain, full_domain in registered_domains:
        if registered_domain in whitelisted_domains:
            subdomains.add(full_domain)  # Add full domain to subdomains if its registrable part is whitelisted
        else:
            final_registered_domains.add(registered_domain)

    # Sort the final registered domains and subdomains
    sorted_domains = sorted(final_registered_domains)
    sorted_subdomains = sorted(subdomains)

    unbound_entries = [f"*.{domain}\n" for domain in sorted_domains]

    # Write to apex_unbound.txt
    with open(apex_unbound_file_path, 'w') as file:
        file.writelines(unbound_entries)

    # Write to subdomains.txt
    with open(subdomain_file_path, 'w') as file:
        file.writelines([f"{domain}\n" for domain in sorted_subdomains])

    log_message = "Processing complete\n"
    output.write(log_message)
