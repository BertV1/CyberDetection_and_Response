import json

cve2002File = open('datafeeds/nvdcve-1.1-2002.json','r')

cveJson = json.loads(cve2002File.read())

cveIDs = []

for cve in cveJson['CVE_Items']:
    #print(cve['cve']['CVE_data_meta']['ID'])
    cveIDs.append(cve['cve']['CVE_data_meta']['ID'])
0
print(len(cveIDs))

cve2002File.close()

def getCVEIDs(jsonFile):
    cveIDs = []
    for cve in cveJson['CVE_Items']:
        #print(cve['cve']['CVE_data_meta']['ID'])
        cveIDs.append(cve['cve']['CVE_data_meta']['ID'])
    return cveIDs