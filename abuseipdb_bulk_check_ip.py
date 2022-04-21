#==============================================
# Extracts IP addresses from .csv and .txt files
# IPs will be checked with AbuseIPDB API and get exported to an Excel file
# Author: https://github.com/dev-lu
#==============================================
from getpass import getpass
from datetime import datetime
from decouple import config
import requests
import json
import xlsxwriter
import re
import os


abuseipdb_apikey = config('ABUSEIPDB_APIKEY')
file = input("Pleaser enter path to input file: \n").encode('unicode-escape').decode()
path = os.path.dirname(os.path.abspath(file))
print(path)
# IPs in "ips" are to be checked and results are added to "result_list"
ips = []
result_list = []


# Add results from API response to lists
def update_result_list(response_json):
    result_list.append([
        str(response_json["data"]["ipAddress"]),
        str(response_json["data"]["domain"]),
        str(response_json["data"]["hostnames"]),
        str(response_json["data"]["abuseConfidenceScore"]),
        str(response_json["data"]["totalReports"]),
        str(response_json["data"]["countryCode"]),
        str(response_json["data"]["isp"]),
        str(response_json["data"]["usageType"]),
        str(response_json["data"]["lastReportedAt"])
    ])


# Print result on console
def print_results(response_json):
    print("IP: " + str(response_json["data"]["ipAddress"]))
    print("Domain: " + str(response_json["data"]["domain"]))
    print("Hostnames: " + str(response_json["data"]["hostnames"]))
    print("Malicious: " + str(response_json["data"]["abuseConfidenceScore"]) + "%")
    print("Number of reports: " + str(response_json["data"]["totalReports"]))
    print("Country: " + str(response_json["data"]["countryCode"]))
    print("ISP: " + str(response_json["data"]["isp"]))
    print("Type: " + str(response_json["data"]["usageType"]))
    print("Last reported: " + str(response_json["data"]["lastReportedAt"]))


# Import result to Excel
def write_to_excel():
    now = datetime.now()
    dt_string = now.strftime("%d%m%Y-%H%M%S")
    filename = 'abuseipdb_export-' + dt_string + '.xlsx'
    # Create an new Excel file and add a worksheet.
    workbook = xlsxwriter.Workbook(os.path.join(path, filename))  # Location for file export
    worksheet = workbook.add_worksheet()  # Insert sheet
    bold = workbook.add_format({'bold': True})  # Activate bold font
    # Set column width
    worksheet.set_column('A:A', 15)
    worksheet.set_column('B:B', 20)
    worksheet.set_column('C:C', 20)
    worksheet.set_column('D:D', 25)
    worksheet.set_column('E:E', 20)
    worksheet.set_column('F:F', 10)
    worksheet.set_column('G:G', 35)
    worksheet.set_column('H:H', 30)
    worksheet.set_column('I:I', 30)

    # Create titel row
    worksheet.write('A1', 'IP', bold)
    worksheet.write('B1', 'Domain', bold)
    worksheet.write('C1', 'Hostnames', bold)
    worksheet.write('D1', 'Abuse confidence in %', bold)
    worksheet.write('E1', 'Number of reports', bold)
    worksheet.write('F1', 'Country', bold)
    worksheet.write('G1', 'ISP', bold)
    worksheet.write('H1', 'Type', bold)
    worksheet.write('I1', 'Last reported', bold)

    # write results into Excel
    for ip in range(len(result_list)):
        worksheet.write('A'+str(ip+2), result_list[ip][0]),
        worksheet.write('B'+str(ip+2), result_list[ip][1]),
        worksheet.write('C'+str(ip+2), result_list[ip][2]),
        worksheet.write('D'+str(ip+2), result_list[ip][3]),
        worksheet.write('E'+str(ip+2), result_list[ip][4]),
        worksheet.write('F'+str(ip+2), result_list[ip][5]),
        worksheet.write('G'+str(ip+2), result_list[ip][6]),
        worksheet.write('H'+str(ip+2), result_list[ip][7]),
        worksheet.write('I'+str(ip+2), result_list[ip][8])


    print(f"File saved at: \n{os.path.join(path, filename)}")
    workbook.close()


# Send IPs to API
def do_request(ips):
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        'Accept': 'application/json',
        'Key': abuseipdb_apikey
    }
    # Iterate through list of IPs and send to API
    for ip in ips:
        querystring = {
            'ipAddress': ip,
            'maxAgeInDays': '90'
        }
        response = requests.get(url=url, headers=headers, params=querystring)
        response_json = json.loads(response.text)
        update_result_list(response_json)  # Add results to list


def extract_ips_from_file(file):
    # Open and read input file
    with open(file) as f:
        fstring = f.readlines()
    
    # Declare Regex pattern
    pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
    
    # Extract IPs
    for line in fstring:
        ip = re.findall( r'[0-9]+(?:\.[0-9]+){3}', line )
        if ip:
            for i in ip:
                ips.append(pattern.search(line)[0])


if __name__ == "__main__":
    extract_ips_from_file(file)
    do_request(ips)
    write_to_excel()
    
