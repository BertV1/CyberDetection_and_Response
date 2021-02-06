import json
import dataFunctions as DF
from bokeh.io import output_notebook
from bokeh.plotting import figure, output_file, show
from bokeh.models import ColumnDataSource,ranges,LabelSet,Title
from bokeh.palettes import PuBu

cve2002File = open('datafeeds/nvdcve-1.1-2002.json','r')
cveJson = json.loads(cve2002File.read())


# testing
# for cve in cveJson['CVE_Items']:
#     print(cve['cve']['CVE_data_meta']['ID'])
    
####################################
##                                ##
##    CVE COUNT BY CVE YEAR ID    ##
##                                ##
####################################

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
show(plt_CVEbyYear)

####################################
####################################
###                              ###
###   AVG CVSS SCORE BY MONTH    ###
###   FOR SELECTED YEARS         ###
###                              ###
####################################
####################################

# dat struct: lst_pubdateANDcvss = [[pubdate,cvss],[pubdate,cvss]...]
lst_pubdateANDcvss = DF.getCVEpubDateAndScore(cveJson)
months = ['JAN','FEB','MAR','APR','MAY','JUN','JUL','AUG','SEP','OCT','NOV','DEC']
#lst_1993_to_1996_pubdate = DF.getAverageCVSScountByMonth(DF.getCVSSbyMultipleYears(lst_pubdateANDcvss,['1993','1994','1995','1996']))
lst_1997_pubdate = DF.getAverageCVSScountByMonth(DF.getCVSSbyYear(lst_pubdateANDcvss,'1997'))
lst_1998_pubdate = DF.getAverageCVSScountByMonth(DF.getCVSSbyYear(lst_pubdateANDcvss,'1998'))
lst_1999_pubdate = DF.getAverageCVSScountByMonth(DF.getCVSSbyYear(lst_pubdateANDcvss,'1999'))
lst_2000_pubdate = DF.getAverageCVSScountByMonth(DF.getCVSSbyYear(lst_pubdateANDcvss,'2000'))
lst_2001_pubdate = DF.getAverageCVSScountByMonth(DF.getCVSSbyYear(lst_pubdateANDcvss,'2001'))
lst_2002_pubdate = DF.getAverageCVSScountByMonth(DF.getCVSSbyYear(lst_pubdateANDcvss,'2002'))
lst_2003_pubdate = DF.getAverageCVSScountByMonth(DF.getCVSSbyYear(lst_pubdateANDcvss,'2003'))

output_file("avgCVSScountByMonthByYear_1999-2002.html")
x_label_cvssByMonth = "Months"
y_label_cvssByMonth = "CVSS score"

plt_cvssByMonth = figure(
    plot_width=1200,
    plot_height=1000,
    tools='save',
    x_axis_label=x_label_cvssByMonth,
    y_axis_label=y_label_cvssByMonth,
    x_minor_ticks=10,
    x_range=months,
    y_range=ranges.Range1d(start=0,end=10)
    )
plt_cvssByMonth.add_layout(Title(
    text='Average CVSS score by month for 1997-2002.',
    align='center',
    text_font_size='1.5em'),'above')
#plt_cvssByMonth.vline_stack(['y1','y2','y3'],x='x',source=src_cvssByMonth)

plt_cvssByMonth.line(months,lst_1997_pubdate,legend_label='1997',line_color='aquamarine',line_width=3)
plt_cvssByMonth.circle(months,lst_1997_pubdate,legend_label='1997',line_color='aquamarine',fill_color='aquamarine',size=8)

plt_cvssByMonth.line(months,lst_1998_pubdate,legend_label='1998',line_color='orange',line_width=3)
plt_cvssByMonth.circle(months,lst_1998_pubdate,legend_label='1998',line_color='orange',fill_color='orange',size=8)

plt_cvssByMonth.line(months,lst_1999_pubdate,legend_label='1999',line_color='red',line_width=3)
plt_cvssByMonth.circle(months,lst_1999_pubdate,legend_label='1999',line_color='red',fill_color='red',size=8)
plt_cvssByMonth.line(months,lst_2000_pubdate,legend_label='2000',line_color='blue',line_width=3)
plt_cvssByMonth.circle(months,lst_2000_pubdate,legend_label='2000',line_color='blue',fill_color='blue',size=8)
plt_cvssByMonth.line(months,lst_2001_pubdate,legend_label='2001',line_color='green',line_width=3)
plt_cvssByMonth.circle(months,lst_2001_pubdate,legend_label='2001',line_color='green',fill_color='green',size=8)
plt_cvssByMonth.line(months,lst_2002_pubdate,legend_label='2002',line_color='purple',line_width=3)
plt_cvssByMonth.circle(months,lst_2002_pubdate,legend_label='2002',line_color='purple',fill_color='purple',size=8)

show(plt_cvssByMonth)

##############
##          ##
##  COUNTS  ##
##          ##
##############


# for pubdateandcvss in lst_pubdateANDcvss:
#     #print(pubdateandcvss[0],'->',pubdateandcvss[1])
#     if '1993' in pubdateandcvss[0]:
#         lst_1993_to_1996_pubdate += 1
#     elif '1994' in pubdateandcvss[0]:
#         lst_1993_to_1996_pubdate += 1     
#     elif '1995' in pubdateandcvss[0]:
#         lst_1993_to_1996_pubdate += 1
#     elif '1996' in pubdateandcvss[0]:
#         lst_1993_to_1996_pubdate += 1    
#     elif '1997' in pubdateandcvss[0]:
#         lst_1997_pubdate += 1
#     elif '1998' in pubdateandcvss[0]:
#         lst_1998_pubdate += 1    
#     elif '1999' in pubdateandcvss[0]:
#         lst_1999_pubdate += 1
#     elif '2000' in pubdateandcvss[0]:
#         lst_2000_pubdate += 1
#     elif '2001' in pubdateandcvss[0]:
#          lst_2001_pubdate += 1
#     elif '2002' in pubdateandcvss[0]:
#         lst_2002_pubdate += 1
#     elif '2003' in pubdateandcvss[0]:
#         lst_2003_pubdate += 1
#     else:
#         rest += 1

# print(lst_1993_to_1996_pubdate)
# print(lst_1997_pubdate)
# print(lst_1998_pubdate)
# print(lst_1999_pubdate)
# print(lst_2000_pubdate)
# print(lst_2001_pubdate)
# print(lst_2002_pubdate)
# print(lst_2003_pubdate)
# print('--------------------')
# print(rest)

ct_CVEs = len(cveIDs)
print(ct_CVEs)

cve2002File.close()
