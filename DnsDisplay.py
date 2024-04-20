import subprocess
import re

def export_ipconfig_displaydns(output_file):
    # Run ipconfig /displaydns command and capture the output
    result = subprocess.run(['ipconfig', '/displaydns'], capture_output=True, text=True)

    # Write the output to a text file
    with open(output_file, 'w') as file:
        file.write(result.stdout)

def check_for_legitimate_domains(output_file, legitimate_domains_file):
    # Read legitimate domains from the text file
    with open(legitimate_domains_file, 'r') as file:
        legitimate_domains = [line.strip() for line in file]

    # Read the output of ipconfig /displaydns
    with open(output_file, 'r') as file:
        output = file.read()

    # Search for matches between the output and legitimate domains
    matches = []
    for domain in legitimate_domains:
        if re.search(domain, output):
            matches.append(domain)

    return matches

if __name__ == "__main__":
    export_ipconfig_displaydns('dns_output.txt')
    legitimate_domains_file = 'Domains_List.txt'
    matches = check_for_legitimate_domains('dns_output.txt', legitimate_domains_file)
    if matches:
        print("Found matches to suspicious domains:")
        for match in matches:
            print(match)
    else:
        print("No matches found.")
