from shodan import Shodan
from tabulate import tabulate
from shodan.cli.helpers import get_api_key
import csv

api = Shodan(get_api_key())

fields = ['IP', 'CVE', 'CVSS', "CVE'ER", 'High CVES', 'Critical CVES']
table =  [['IP', 'CVSS', "CVE'ER", 'High CVES', 'Critical CVES']]

print('Welcome to VULN scanner')

userInput = input('Enter organisation to scan for vulns: ')

uniqueIPs = []
uniqueMachines = []
limits = 5


results = api.search(f'org:{userInput} has_vuln:true', limit=limits)
print('Total results founds {}'.format(results['total']))

with open('data.csv', 'w', encoding='UTF8', newline='') as f:
    writer = csv.writer(f)
    writer.writerow(fields)

    for result in results['matches']:
        numberOfCVEs = 0
        numberOfCriticalCVE = 0
        numberOfHighCVE = 0
        nameCVE = []
        # Denne række skal væk
        print('Machine IP: {}'.format(result['ip_str']))
        for item in result['vulns']:
            numberOfCVEs = numberOfCVEs + 1
            cvssScore = float(result['vulns'][item]['cvss'])
            nameCVE.append(item)

            if cvssScore >= 9:
                numberOfCriticalCVE = numberOfCriticalCVE + 1
            elif 9 > cvssScore >= 7:  # fucker dette det op?
                numberOfHighCVE = numberOfHighCVE + 1

            #print("Number of high CVE: {}".format(numberOfHighCVE))
            #print("Number of Critical cve: {}".format(numberOfCriticalCVE))
            #print("CVSS: {}".format(cvssScore))
            #print("Number of CVEs {}".format(numberOfCVEs))

        rows = [result['ip_str'], nameCVE, cvssScore,
                numberOfCVEs, numberOfHighCVE, numberOfCriticalCVE]
        tableData = [result['ip_str'], cvssScore,
                numberOfCVEs, numberOfHighCVE, numberOfCriticalCVE]

        table.append(tableData)

        # print(tabulate([rows], headers=['IP', 'CVE', 'CVSS',
        #      "CVE'ER", 'High CVES', 'Critical CVES']))
        writer.writerow(rows)
print(tabulate(table, headers='firstrow', tablefmt='fancy_grid'))
