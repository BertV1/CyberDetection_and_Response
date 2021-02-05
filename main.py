import json
import dataFunctions as DF
from bokeh.io import show, output_notebook
from bokeh.plotting import figure, output_file
from bokeh.models import ColumnDataSource,ranges,LabelSet
from bokeh.palettes import PuBu

cve2002File = open('datafeeds/nvdcve-1.1-2002.json','r')
cveJson = json.loads(cve2002File.read())


# testing
# for cve in cveJson['CVE_Items']:
#     print(cve['cve']['CVE_data_meta']['ID'])
    




# VISUAL OF CVEs BY YEAR
cveIDs = DF.getCVEIDs(cveJson)
CVEsByYear = DF.getCVEbyYear(cveIDs)
years = ['1999','2000','2001','2002']
x_label = "Years"
y_label = "number of CVEs"
labelSrc = ColumnDataSource(dict(x=years,y=CVEsByYear))
plt_CVEbyYear = figure(
                plot_height=600, 
                plot_width=600,
                tools='save',
                x_axis_label=x_label, 
                y_axis_label=y_label, 
                title='Total CVE count by Year (CVE ID based)',
                x_minor_ticks=6,
                x_range=labelSrc.data['x'],
                y_range=ranges.Range1d(start=0,end=3000)
                )

# plt_CVEbyYear.xgrid.grid_line_color = None

labels = LabelSet(x='x',y='y', text='y', level='glyph',
                x_offset=-13.5, y_offset=0, source=labelSrc,
                render_mode='canvas')
plt_CVEbyYear.vbar(source=labelSrc, x='x',top='y',bottom=0, width=0.7,color=PuBu[6][3])
plt_CVEbyYear.add_layout(labels)
#show(plt_CVEbyYear)

lst_pubdateANDcvss = DF.getCVEpubDateAndScore(cveJson)
# dat struct: lst_pubdateANDcvss = [[pubdate,cvss],[pubdate,cvss]...]



months = ['JAN','FEB','MAR','APR','MAY','JUN','JUL','SEP','OCT','NOV','DEC']
lst_1993_to_1996_pubdate = DF.getAverageCVSScountByMonth(DF.getCVSSbyMultipleYears(lst_pubdateANDcvss,['1993','1994','1995','1996']))
lst_1997_pubdate = DF.getAverageCVSScountByMonth(DF.getCVSSbyYear(lst_pubdateANDcvss,'1997'))
lst_1998_pubdate = DF.getAverageCVSScountByMonth(DF.getCVSSbyYear(lst_pubdateANDcvss,'1998'))
lst_1999_pubdate = DF.getAverageCVSScountByMonth(DF.getCVSSbyYear(lst_pubdateANDcvss,'1999'))
lst_2000_pubdate = DF.getAverageCVSScountByMonth(DF.getCVSSbyYear(lst_pubdateANDcvss,'2000'))
lst_2001_pubdate = DF.getAverageCVSScountByMonth(DF.getCVSSbyYear(lst_pubdateANDcvss,'2001'))
lst_2002_pubdate = DF.getAverageCVSScountByMonth(DF.getCVSSbyYear(lst_pubdateANDcvss,'2002'))
lst_2003_pubdate = DF.getAverageCVSScountByMonth(DF.getCVSSbyYear(lst_pubdateANDcvss,'2003'))

output_file("avgCVSScountByMonthByYear_1999-2000-2001.html")
x_label_cvssByMonth = "Months"
y_label_cvssByMonth = "CVSS score"
src_cvssByMonth = ColumnDataSource(
    data=dict(
        x=months,
        y1=lst_1999_pubdate,
        y2=lst_2000_pubdate,
        y3=lst_2001_pubdate
        )
)
plt_cvssByMonth = figure(
    plot_width=1200,
    plot_height=1000,
    title='Average CVSS score by month for 1999, 2000 & 2001',
    tools='save')

plt_cvssByMonth.vline_Stack(['y1','y2','y3'],x='x',source=src_cvssByMonth)
show(plt_cvssByMonth)

##############
##          ##
##  COUNTS  ##
##          ##
##############


for pubdateandcvss in lst_pubdateANDcvss:
    #print(pubdateandcvss[0],'->',pubdateandcvss[1])
    if '1993' in pubdateandcvss[0]:
        lst_1993_to_1996_pubdate += 1
    elif '1994' in pubdateandcvss[0]:
        lst_1993_to_1996_pubdate += 1     
    elif '1995' in pubdateandcvss[0]:
        lst_1993_to_1996_pubdate += 1
    elif '1996' in pubdateandcvss[0]:
        lst_1993_to_1996_pubdate += 1    
    elif '1997' in pubdateandcvss[0]:
        lst_1997_pubdate += 1
    elif '1998' in pubdateandcvss[0]:
        lst_1998_pubdate += 1    
    elif '1999' in pubdateandcvss[0]:
        lst_1999_pubdate += 1
    elif '2000' in pubdateandcvss[0]:
        lst_2000_pubdate += 1
    elif '2001' in pubdateandcvss[0]:
         lst_2001_pubdate += 1
    elif '2002' in pubdateandcvss[0]:
        lst_2002_pubdate += 1
    elif '2003' in pubdateandcvss[0]:
        lst_2003_pubdate += 1
    else:
        rest += 1

print(lst_1993_to_1996_pubdate)
print(lst_1997_pubdate)
print(lst_1998_pubdate)
print(lst_1999_pubdate)
print(lst_2000_pubdate)
print(lst_2001_pubdate)
print(lst_2002_pubdate)
print(lst_2003_pubdate)
print('--------------------')
print(rest)

ct_CVEs = len(cveIDs)
print(ct_CVEs)

cve2002File.close()
