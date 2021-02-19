import json
import sys
import dataFunctions as DF
import chartFunctions as CF

def prepareData(file):
    fileData = open(file,'r',encoding='utf8')
    jsonData = json.loads(fileData.read())
    fileData.close()
    return jsonData

def getUserInputForYears():
    lst_preferredYears = []
    print('input years you want to see in the chart\n & end with END!')
    userInput = input('year: ')
    while userInput:
        if int(userInput) >= 1990 and int(userInput) <= 2015:
            print(type(userInput))
            lst_preferredYears.append(userInput)
        else:
            break
        userInput = input('year: ')
    return lst_preferredYears

JsonCVEs = prepareData('datafeeds/nvdcve-1.1-2002-2010.json')
print("""
    Available charts:\n\t
    --> 1:  bar chart of the total count of available CVEs by their CVE-ID year.\n\t
    --> 2:  bar chart of the total count of available CVEs by their year they were published.\n\t
    --> 3:  line chart of the average CVSS score by month for the selected year(s)\n\t
    --> 4:  bar chart of the CVE count by CVSS score bracket for the selected year(s)\n\t
    --> 5:  1 & 2 \n
    """)
chartChoice = input('CHART: ')
#CF.bar_chart_CVE_count_by_CVSS_score_for_years(JSON_CVE_DATA=JsonCVEs,lst_years='1999')

if int(chartChoice) == 1:
    CF.bar_chart_CVE_by_ID(JsonCVEs)
elif int(chartChoice) == 2:
    lst_preferredYears = getUserInputForYears()
    CF.bar_chart_CVE_by_YEAR(JSON_CVE_DATA=JsonCVEs,lst_years=DF.sortIntStrings(lst_preferredYears))
elif int(chartChoice) == 3:
    lst_preferredYears = getUserInputForYears()
    CF.line_chart_avg_CVE_per_month_by_year(JsonCVEs,DF.sortIntStrings(lst_preferredYears))
elif int(chartChoice) == 4:
    lst_preferredYears = getUserInputForYears()
    CF.bar_chart_CVE_count_by_CVSS_score_for_years(JsonCVEs,lst_preferredYears)
elif int(chartChoice) == 5:
    lst_preferredYears =getUserInputForYears()
    CF.bar_chart_CVE_by_ID(JsonCVEs)
    CF.bar_chart_CVE_by_YEAR(JSON_CVE_DATA=JsonCVEs,lst_years=DF.sortIntStrings(lst_preferredYears))




# for cve in cveJson['CVE_Items']:
#     print(cve['cve']['CVE_data_meta']['ID'])

# dat struct: lst_pubdateANDcvss = [[pubdate,cvss],[pubdate,cvss]...]

# cve pub date by CVE-1999 = key
# cve cvss score of key = value
# data point  = sum(value)/count(key)
# plot datapoints per month for each available year
# pub date format: YYYY-MM-DDTHH:MMZ