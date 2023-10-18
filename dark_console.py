import importlib
import subprocess
import sys
import os
import requests
import argparse
import time
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

VIRUSTOTAL_API_KEY = "18ad48320f7be2b7a9297fd3e39e5ae3bde85bf9f29abc0f74a11de1cb9aa74f"  # Replace with your VirusTotal API key

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
    c = canvas.Canvas(pdf_path, pagesize=letter)

    page_height = 750
    c.setFont("Helvetica-Bold", 16)
    c.drawString(220, page_height, "Report")

    y_position = page_height - 50
    counter = 1
    for target, details in results.items():
        c.setFont("Helvetica-Bold", 12)
        c.drawString(30, y_position, f"{counter}. Target: {target}")
        y_position -= 20
        if isinstance(details, str):
            c.drawString(50, y_position, f"Result: {details}")
        else:
            for category, count in details.items():
                c.drawString(50, y_position, f"{category}: {str(count)}")
                y_position -= 20
                if y_position < 50:
                    c.showPage()
                    page_height = 750
                    y_position = page_height

        counter += 1
        y_position -= 40  # Add extra space between results

    c.save()
    print(f"Report generated successfully at {pdf_path}")

def analyze_item(item, index, total_items):
    try:
        print(f"Scanning item {index}/{total_items}: {item} - Next scan in 15 seconds. Estimated time remaining for all items: {15 * (total_items - index)} seconds.")
        time.sleep(15)  # Adding an extra 15-second delay for every 4 scans
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
        print(f"An error occurred for item {item}: {e}")
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
            
            results = {}
            for idx, item in enumerate(items, start=1):
                results[item] = analyze_item(item, idx, len(items))
                
            print("\nScan results:")
            for item, result in results.items():
                print(f"Item: {item} - Result: {result}")
            
            save_pdf = input("Do you want to save the results to a PDF file? (yes/no): ").lower()
            if save_pdf == 'yes':
                create_pdf_report(results, args.input_type)
            else:
                print("Results not saved as PDF.")

        else:
            item = input(f"Enter the {args.input_type}: ")
            results = analyze_item(item, 1, 1)
            print(f"\nScan result for {item}: {results}")
            save_pdf = input("Do you want to save the result to a PDF file? (yes/no): ").lower()
            if save_pdf == 'yes':
                create_pdf_report({item: results}, args.input_type)
            else:
                print("Result not saved as PDF.")

        banner = "Exiting from 'Dark_Shadow04' private database console."
        os.system(f'echo "{banner}" | lolcat')
    except KeyboardInterrupt:
        banner = "Exiting from 'Dark_Shadow04' Private Database Console"
        os.system(f'echo "{banner}" | lolcat')

# Rest of the script remains the same

if __name__ == "__main__":
    main()
