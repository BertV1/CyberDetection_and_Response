def getCVEIDs(cveJsonFile):
    cveIDs = []
    for cve in cveJsonFile['CVE_Items']:
        #print(cve['cve']['CVE_data_meta']['ID'])
        cveIDs.append(cve['cve']['CVE_data_meta']['ID'])
    return cveIDs

# cve pub date by CVE-1999 = key
# cve cvss score of key = value
# data point  = sum(value)/count(key)
# plot datapoints per month for each available year
# pub date format: YYYY-MM-DDTHH:MMZ

years = ['1998','1999','2000','2001','2002','2003']

def getCVEpubDateAndScore(cveJsonFile):
    #todo discarding entries after 2002
    #todo only metric V2 items (97 are not baseMetricV2), none are V3
    CVE_pubDate_CVSS = {}
    for cve in cveJsonFile['CVE_Items']:
        #print(cve['publishedDate'],'->')
        if 'baseMetricV2' in cve['impact']:
            #print(str(cve['impact']['baseMetricV2']['cvssV2']['baseScore']))
            CVE_pubDate_CVSS[cve['publishedDate']] = cve['impact']['baseMetricV2']['cvssV2']['baseScore']
    return CVE_pubDate_CVSS

def handleMonths(list):
    return -1

def getCVEbyYear(CVEIDs):
    cve1999 = 0
    cve2000 = 0
    cve2001 = 0
    cve2002 = 0
    rest = 0
    for cveID in CVEIDs:
        if 'CVE-1999' in cveID:
            cve1999 += 1
        elif 'CVE-2000' in cveID:
            cve2000 += 1
        elif 'CVE-2001' in cveID:
            cve2001 += 1
        elif 'CVE-2002' in cveID:
            cve2002 += 1
        else:
            rest += 1
            print(cveID)
    if rest == 0: #todo: c
        return (list([cve1999,cve2000,cve2001,cve2002]))
