import os
import tldextract

# Path to the folder containing the input and output files
folder_path = "./explicit"

# File paths
source_file = os.path.join(folder_path, 'source.txt')
master_file = os.path.join(folder_path, 'apex_plain.txt')
abp_file = os.path.join(folder_path, 'apex_abp.txt')
unbound_file = os.path.join(folder_path, 'apex_unbound.txt')
subdomains_file = os.path.join(folder_path, 'subdomain_plain.txt')
whitelist_file = "./program/whitelist.txt"  # Root directory whitelist file
output_file = "./program/output.txt"  # Output log file

# Open output file for writing logs
with open(output_file, 'w') as output:

    # Read domains from source.txt
    with open(source_file, 'r') as file:
        lines = file.readlines()

    # Initialize sets for registered domains and subdomains
    registered_domains = set()
    subdomains = set()

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

    # Read domains from whitelists.txt
    whitelisted_domains = set()
    if os.path.exists(whitelist_file):
        with open(whitelist_file, 'r') as file:
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
        log_message = f"Warning: Whitelist file '{whitelist_file}' not found. No domains were whitelisted.\n"
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

    # Generate entries for master.txt and ABP.txt
    master_entries = [f"{domain}\n" for domain in sorted_domains]
    abp_entries = [f"||{domain}^\n" for domain in sorted_domains]
    unbound_entries = [f"{domain}\n*.{domain}\n" for domain in sorted_domains]

    # Write to master.txt
    with open(master_file, 'w') as file:
        file.writelines(master_entries)

    # Write to ABP.txt
    with open(abp_file, 'w') as file:
        file.writelines(abp_entries)

    # Write to apex_unbound.txt
    with open(unbound_file, 'w') as file:
        file.writelines(unbound_entries)

    # Write to subdomains.txt
    with open(subdomains_file, 'w') as file:
        file.writelines([f"{domain}\n" for domain in sorted_subdomains])

    log_message = "Processing complete\n"
    output.write(log_message)
