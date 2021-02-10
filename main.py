import json
import sys
import dataFunctions as DF
import chartFunctions as CF

def prepareData(file):
    fileData = open(file,'r')
    jsonData = json.loads(fileData.read())
    fileData.close()
    return jsonData

def getUserInputForYears():
    lst_preferredYears = []
    print('input years you want to see in the chart\n & end with END!')
    userInput = input('year: ')
    while userInput:
        if int(userInput) >= 1997 and int(userInput) <= 2002:
            lst_preferredYears.append(userInput)
        else:
            break
        userInput = input('year: ')
    return lst_preferredYears

JsonCVEs = prepareData('datafeeds/nvdcve-1.1-2002.json')
chartChoice = input("Type '1' for Chart 1,\nType '2' for Chart 2\nType 3 for both\n CHART: ")
CF.bar_chart_CVE_count_by_CVSS_score_for_years(JSON_CVE_DATA=JsonCVEs,lst_years='1999')

if int(chartChoice) == 1:
    CF.bar_chart_CVE_by_ID(JsonCVEs)
elif int(chartChoice) == 2:
    lst_preferredYears = getUserInputForYears()
    CF.line_chart_avg_CVE_per_month_by_year(JsonCVEs,DF.sortIntStrings(lst_preferredYears))
elif int(chartChoice) == 3:
    getUserInputForYears()
    CF.bar_chart_CVE_by_ID(JsonCVEs)
    CF.line_chart_avg_CVE_per_month_by_year()




# for cve in cveJson['CVE_Items']:
#     print(cve['cve']['CVE_data_meta']['ID'])

# dat struct: lst_pubdateANDcvss = [[pubdate,cvss],[pubdate,cvss]...]

# cve pub date by CVE-1999 = key
# cve cvss score of key = value
# data point  = sum(value)/count(key)
# plot datapoints per month for each available year
# pub date format: YYYY-MM-DDTHH:MMZ