import json
import sys
import dataFunctions as DF
import chartFunctions as CF
from bokeh.io import output_notebook
from bokeh.plotting import figure, output_file, show
from bokeh.models import ColumnDataSource,ranges,LabelSet,Title
from bokeh.palettes import PuBu




def prepareData(file):
    fileData = open(file,'r')
    jsonData = json.loads(fileData.read())
    fileData.close()
    return jsonData

JsonCVEs = prepareData('datafeeds/nvdcve-1.1-2002.json')

def getUserInputForYears():
    lst_preferredYears = []
    print('input years you want to see in the chart\n & end with END!')
    userInput = input('year: ')
    while userInput != "END":
        if int(userInput) < 1997 or int(userInput) > 2002:
            userInput = input('The year must be between 1997 (inc) and 2002 (inc)\nyear:')
        else:
            lst_preferredYears.append(int(userInput))
    return lst_preferredYears

# greetings bla bla
# what u want: this? 
# then execute this line here
chartChoice = input("Type '1' for Chart 1,\nType '2' for Chart 2\nType 3 for both\n CHART: ")
if int(chartChoice) == 1:
    CF.bar_chart_CVE_by_ID(JsonCVEs)
elif int(chartChoice) == 2:
    getUserInputForYears()
    CF.line_chart_avg_CVE_per_month_by_year(JsonCVEs,lst_preferredYears)
elif int(chartChoice) == 3:
    getUserInputForYears()
    CF.bar_chart_CVE_by_ID(JsonCVEs)
    CF.line_chart_avg_CVE_per_month_by_year()


# testing
# for cve in cveJson['CVE_Items']:
#     print(cve['cve']['CVE_data_meta']['ID'])
# dat struct: lst_pubdateANDcvss = [[pubdate,cvss],[pubdate,cvss]...]
