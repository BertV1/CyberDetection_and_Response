import json
import dataFunctions as DF
import bokeh.s

cve2002File = open('datafeeds/nvdcve-1.1-2002.json','r')
cveJson = json.loads(cve2002File.read())


# testing
# for cve in cveJson['CVE_Items']:
#     print(cve['cve']['CVE_data_meta']['ID'])
    

# TOTAL COUNT CVE
cveIDs = DF.getCVEIDs(cveJson)
ct_CVEs = len(cveIDs)
print(ct_CVEs)


CVEsByYear = DF.getCVEbyYear(cveIDs)
years = ['1999','2000','2001','2002']













cve2002File.close()

