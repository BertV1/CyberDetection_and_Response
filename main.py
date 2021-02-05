import json
import dataFunctions as DF
from bokeh.io import show, output_notebook
from bokeh.plotting import figure
from bokeh.models import ColumnDataSource,ranges,LabelSet
from bokeh.palettes import PuBu

cve2002File = open('datafeeds/nvdcve-1.1-2002.json','r')
cveJson = json.loads(cve2002File.read())


# testing
# for cve in cveJson['CVE_Items']:
#     print(cve['cve']['CVE_data_meta']['ID'])
    

# TOTAL COUNT CVE
cveIDs = DF.getCVEIDs(cveJson)
ct_CVEs = len(cveIDs)
print(ct_CVEs)



# VISUAL OF CVEs BY YEAR
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

pubdateANDcvss = DF.getCVEpubDateAndScore(cveJson)











cve2002File.close()

