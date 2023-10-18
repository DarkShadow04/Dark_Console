import importlib
import subprocess
import sys
import os
import requests
import argparse
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

VIRUSTOTAL_API_KEY = "18ad48320f7be2b7a9297fd3e39e5ae3bde85bf9f29abc0f74a11de1cb9aa74f"

def install(package):
    subprocess.check_call([sys.executable, "-m", "pip", "install", package], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def check_dependencies():
    required_libraries = ['requests', 'reportlab', 'matplotlib', 'argparse']
    for lib in required_libraries:
        try:
            importlib.import_module(lib)
        except ImportError:
            print(f"{lib} is not installed. Installing {lib}...")
            install(lib)
    print("All dependencies are installed.")
        
# Import the necessary module for generating random colors
import random

# List of ANSI color codes
ansi_colors = ['\033[0;31m', '\033[0;32m', '\033[0;33m', '\033[0;34m', '\033[0;35m', '\033[0;36m']

# Select a random color from the list
random_color = random.choice(ansi_colors)    
    
# Define the ANSI color codes
cyan = '\033[0;36m'
green = '\033[0;32m'
NC = '\033[0m'  # No Color

# Print the banner with colors
print(cyan + """
_
""" + green + """██████╗  █████╗ ██████╗ ██╗  ██╗         ██████╗ ██████╗ ███╗   ██╗███████╗ ██████╗ ██╗     ███████╗
██╔══██╗██╔══██╗██╔══██╗██║ ██╔╝        ██╔════╝██╔═══██╗████╗  ██║██╔════╝██╔═══██╗██║     ██╔════╝
██║  ██║███████║██████╔╝█████╔╝         ██║     ██║   ██║██╔██╗ ██║███████╗██║   ██║██║     █████╗  
██║  ██║██╔══██║██╔══██╗██╔═██╗         ██║     ██║   ██║██║╚██╗██║╚════██║██║   ██║██║     ██╔══╝  
██████╔╝██║  ██║██║  ██║██║  ██╗███████╗╚██████╗╚██████╔╝██║ ╚████║███████║╚██████╔╝███████╗███████╗
╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝ ╚═════╝ ╚══════╝╚══════╝
""" + NC)

# Define the ANSI color codes
reset = '\033[0m'  # Reset

# Assuming you have defined the variable random_color somewhere in your script, you can use it as follows:
print(f"{random_color} Dark_Console script by: Dark_Shadow04 {reset}\n")
print(f"{random_color} https://github.com/DarkShadow04  {reset}\n")
print(f"{random_color} Copyright 2023 Dark_Shadow04 {reset}\n")

def create_pdf_report(results, input_type):
    pdf_path = "VirusTotal_Report.pdf"
    banner = "Report"
    os.system(f'echo "{banner}" | lolcat')
    c = canvas.Canvas(pdf_path, pagesize=letter)
    c.setFont("Helvetica-Bold", 16)
    c.drawString(220, 750, "Report")
    c.setFont("Helvetica-Bold", 12)
    c.drawString(30, 700, "Targets List:")

    y_position = 680
    for target, details in results.items():
        c.drawString(30, y_position, f"Target: {target}")
        y_position -= 20
        for category, count in details.items():
            c.drawString(50, y_position, f"{category}: {str(count)}")
            y_position -= 20
        y_position -= 20  # Add extra space between results

    c.save()
    print(f"Report generated successfully at {pdf_path}")

def analyze_item(item):
    try:
        url = f"https://www.virustotal.com/vtapi/v2/url/report?apikey={VIRUSTOTAL_API_KEY}&resource={item}"
        response = requests.get(url)
        json_response = response.json()
        if json_response['response_code'] == 0:
            return "Unrated"
        scans = json_response.get('scans', {})
        categories = {
            'malicious': 0,
            'phishing': 0,
            'suspicious': 0,
            'clean site': 0,
            'not recommended': 0,
            'unrated': 0
        }
        for scan in scans.values():
            result = scan.get('result', '').lower()
            if 'malicious' in result or 'malware' in result:
                categories['malicious'] += 1
            elif 'phish' in result:
                categories['phishing'] += 1
            elif 'suspicious' in result:
                categories['suspicious'] += 1
            elif 'clean' in result:
                categories['clean site'] += 1
            elif 'not recommended' in result:
                categories['not recommended'] += 1
            else:
                categories['unrated'] += 1
        return categories
    except Exception as e:
        print(f"An error occurred: {e}")
        return {
            'malicious': 0,
            'phishing': 0,
            'suspicious': 0,
            'clean site': 0,
            'not recommended': 0,
            'unrated': 0
        }

def main():
    try:
        check_dependencies()

        banner = "Warning: Request rate: 4 lookups/minute. Daily quota: 500 lookups/day. Monthly quota: 15.5K lookups/month."
        os.system(f'echo "{banner}" | lolcat')

        parser = argparse.ArgumentParser(description='VirusTotal Analysis Script')
        parser.add_argument('input_type', type=str, help='Specify the input type: URL, IP address, or file')
        args = parser.parse_args()

        items = []
        if args.input_type.lower() == 'file':
            file_path = input("Enter the location of the file containing URLs or IP addresses: ")
            with open(file_path, 'r') as f:
                items = f.read().splitlines()
        else:
            item = input(f"Enter the {args.input_type}: ")
            items.append(item)

        results = {}
        for item in items:
            if item not in results:
                results[item] = {'Malicious': 0, 'Phishing': 0, 'Suspicious': 0, 'Clean': 0, 'Unrated': 0}
            result = analyze_item(item)
            results[item] = result

        create_pdf_report(results, args.input_type)

        print("")
        banner = "Exiting from 'Dark_Shadow04' private database console."
        os.system(f'echo "{banner}" | lolcat')
    except KeyboardInterrupt:
        banner = "Exiting from 'Dark_Shadow04' Private Database Console"
        os.system(f'echo "{banner}" | lolcat')

print(f"{random_color} Script executed successfully with blessing of Dark_Shadow04. {reset}\n")       

if __name__ == "__main__":
    main()
