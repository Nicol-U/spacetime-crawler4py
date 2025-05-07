#fixed values that were incorrectly parsed due to jupyterhub internal server crash (unique url count was cut off and so were the subdomains - used worker logs to generate this data)

#to run type:
# 1: python "(insert file path to this report fixer file here)"
# 2: python (insert file path to the worker log file here)

import re
from urllib.parse import urlparse
import os

def defrag(url):
    # fragment remover to count unique ursl
    fragment_pos = url.find('#')
    if fragment_pos != -1:
        return url[:fragment_pos]
    return url

def generate_report(log_file_path):
    # matches url patterns in log file to correctly parse them
    url_pattern = r"Downloaded (https?://[^,]+), status <(\d+)>"
    
    # tracks unique urls and subdomain paths
    unique_urls = set()
    subdomains = {}
    
    # log file processing
    with open(log_file_path, 'r', encoding='utf-8', errors='ignore') as file:
        for line in file:
            if "Downloaded " in line and "status <200>" in line: # checks its a 200 type and downloaded (works with log format)
                match = re.search(url_pattern, line)
                if match:
                    url = match.group(1)
                    
                    # adds to unique url after defrag
                    clean_url = defrag(url)
                    unique_urls.add(clean_url)
                    
                    # gets domain and path
                    parsed = urlparse(clean_url)
                    domain = parsed.netloc.lower()
                    path = parsed.path.lower()
                    
                    # tracks path according to subdomain
                    if domain not in subdomains:
                        subdomains[domain] = set()
                    subdomains[domain].add(path)
    
    # gets report values that were inaccurate due to crash of main scraper
    print(f"subdomain & unique pages counts: ")
    for subdomain, paths in sorted(subdomains.items()):
        if '.uci.edu' in subdomain:
            print(f"{subdomain} ---> {len(paths)}")
    
    print("-" * 20)
    print(f"Total unique pages count:")
    print(len(unique_urls))

if __name__ == "__main__":
    log_file = input("Enter the path to Worker.log: ")
    if not log_file:
        log_file = "Logs/Worker.log"
    
    if not os.path.exists(log_file):
        print(f"Error: File not found at {log_file}")
    else:
        generate_report(log_file)