import dataFunctions as DF
from bokeh.models import ColumnDataSource,ranges,LabelSet,Title,FactorRange
from bokeh.plotting import figure,show
from bokeh.palettes import PuBu
from bokeh.transform import factor_cmap
from bokeh.palettes import Spectral6
import random

####################################
##                                ##
##    CVE COUNT BY CVE YEAR ID    ##
##                                ##
####################################

def getYearForTitle(lst_years):
    titleYear = ''
    if len(lst_years) == 1:
        titleYear = lst_years
    else:
        #titleYear = lst_years[0]+'-'+lst_years[-1]
        titleYear = '%s- %s' % (lst_years[0],lst_years[-1])

    return titleYear

def bar_chart_CVE_by_ID(JSON_CVE_DATA):

    lst_CVE_IDs = DF.getCVEIDs(JSON_CVE_DATA)
    dct_cntByCVE_ID = DF.getCVEID_cnt_byYear(lst_CVE_IDs)

    #years = ['1999','2000','2001','2002','2003','2004','2005','2006']
    x_label = 'Years'
    y_label = 'Number of CVEs'

    lbl_src = ColumnDataSource(data=dict(x=list(dct_cntByCVE_ID.keys()),y=list(dct_cntByCVE_ID.values())))

    plt_bar_chart_CVE_by_ID = figure(
        plot_height=750,
        plot_width=900,
        toolbar_location='right',
        x_axis_label=x_label,
        y_axis_label=y_label,
        title='CVE-ID based total CVE count by Year: 1999-2002',
        x_minor_ticks=6,
        x_range=lbl_src.data['x'],
        y_range=ranges.Range1d(start=0,end=7500)
    )

    labels = LabelSet(x='x',y='y', text='y', level='glyph',
                x_offset=-13.5, y_offset=0, source=lbl_src,
                render_mode='canvas')
    
    plt_bar_chart_CVE_by_ID.vbar(source=lbl_src,x='x',top='y',bottom=0,width=0.7,color=PuBu[6][3])
    plt_bar_chart_CVE_by_ID.add_layout(labels)

    show(plt_bar_chart_CVE_by_ID)

def bar_chart_CVE_by_YEAR(JSON_CVE_DATA,lst_years):

    dct_cntBypubDateyear = DF.getCVE_count_by_pubdateYear(JSON_CVE_DATA,lst_years)
    lbl_src = ColumnDataSource(data=dict(x=list(dct_cntBypubDateyear.keys()),y=list(dct_cntBypubDateyear.values())))
    for k,v in dct_cntBypubDateyear.items():
        print(k,'->',v)

    x_label = 'Years'
    y_label = 'Number of CVEs'
    titleYear = getYearForTitle(list(dct_cntBypubDateyear.keys()))

    plt_bar_chart_CVE_by_ID = figure(
        plot_height=750,
        plot_width=900,
        toolbar_location='right',
        x_axis_label=x_label,
        y_axis_label=y_label,
        title='CVE publish date based total CVE count by Year: '+ titleYear,
        x_minor_ticks=6,
        x_range=lbl_src.data['x'],
        y_range=ranges.Range1d(start=0,end=8000)
    )

    labels = LabelSet(x='x',y='y', text='y', level='glyph',
                x_offset=-13.5, y_offset=0, source=lbl_src,
                render_mode='canvas')
    
    plt_bar_chart_CVE_by_ID.vbar(source=lbl_src,x='x',top='y',bottom=0,width=0.7,color=PuBu[6][3])
    plt_bar_chart_CVE_by_ID.add_layout(labels)

    show(plt_bar_chart_CVE_by_ID)

####################################
####################################
###                              ###
###   AVG CVSS SCORE BY MONTH    ###
###   FOR SELECTED YEARS         ###
###                              ###
####################################
####################################

def line_chart_avg_CVE_per_month_by_year(JSON_CVE_DATA,lst_years):

    lst_pubDate_and_cvss = DF.getCVEpubDateAndScore(JSON_CVE_DATA)
    lst_data_for_chosen_years = []
    for year in lst_years:
        lst_data_for_chosen_years.append(DF.getAverageCVSScountByMonth(DF.getCVSSbyYear(lst_pubDate_and_cvss,str(year))))    
    months = ['JAN','FEB','MAR','APR','MAY','JUN','JUL','AUG','SEP','OCT','NOV','DEC']

    x_label = 'Months'
    y_label = 'CVSS score'

    plt_line_chart_avg_CVE_per_month_by_year = figure(
        plot_width=1200,
        plot_height=1000,
        toolbar_location='right',
        x_axis_label=x_label,
        y_axis_label=y_label,
        x_minor_ticks=10,
        x_range=months,
        y_range=ranges.Range1d(start=0,end=10)     
    )

    plt_line_chart_avg_CVE_per_month_by_year.add_layout(Title(
        text='Average CVSS score by month for 1997-2002.',
        align='center',
        text_font_size='1.5em'),'above')
    
    if len(lst_years) == len(lst_data_for_chosen_years):
        randomNr = random.sample(range(0,len(possibleColours)),len(lst_years))
        for i in range(len(lst_data_for_chosen_years)):
            plt_line_chart_avg_CVE_per_month_by_year.line(months,lst_data_for_chosen_years[i],legend_label=str(lst_years[i]),line_color=possibleColours[randomNr[i]],line_width=3)
            plt_line_chart_avg_CVE_per_month_by_year.circle(months,lst_data_for_chosen_years[i],legend_label=str(lst_years[i]),line_color=possibleColours[randomNr[i]],fill_color=possibleColours[randomNr[i]],size=8)
  
    show(plt_line_chart_avg_CVE_per_month_by_year)


def bar_chart_CVE_count_by_CVSS_score_for_years(JSON_CVE_DATA,lst_years):
    lst_pubDate_and_cvss = DF.getCVEpubDateAndScore(JSON_CVE_DATA)
    lst_data_for_chosen_years = []
    for year in lst_years:
        lst_data_for_chosen_years.append(DF.getCVSSCountBracketsByYear(DF.getCVSSbyYear(lst_pubDate_and_cvss,year)))
    lbl_cvssBrackets = ['[0-1]',']1-2]',']2-3]',']3-4]',']4-5]',']5-6]',']6-7]',']7-8]',']8-9]',']9-10]']
    
    dataForChosenYears = {}
    dataForChosenYears['brackets'] = lbl_cvssBrackets
    if len(lst_years) == len(lst_data_for_chosen_years):
        for i in range(len(lst_data_for_chosen_years)):
            print(lst_years[i])
            dataForChosenYears[lst_years[i]] = lst_data_for_chosen_years[i]
    
    x = [(cvssBracket,year) for cvssBracket in lbl_cvssBrackets for year in lst_years]
    counts = sum(zip(*lst_data_for_chosen_years),())

    source = ColumnDataSource(data=dict(x=x,counts=counts))
    x_label = 'CVSS brackets'
    y_label = 'CVE Count'
    
    plt_bar_chart_CVE_count_by_CVSS_score_for_years = figure(
        plot_width=1500,
        plot_height=1200,
        toolbar_location='right',
        x_axis_label=x_label,
        y_axis_label=y_label,
        x_range=FactorRange(*x),
    )

    titleYear = getYearForTitle(lst_years)

    plt_bar_chart_CVE_count_by_CVSS_score_for_years.add_layout(Title(
        text='CVE count by CVSS score bracket for '+titleYear,
        align='center',
        text_font_size='1.7em'),'above')
    

    plt_bar_chart_CVE_count_by_CVSS_score_for_years.vbar(x='x',top='counts',width=0.9,source=source, line_color='white', fill_color=factor_cmap('x',palette=Spectral6,factors=lst_years,start=1, end=2))
    plt_bar_chart_CVE_count_by_CVSS_score_for_years.xaxis.major_label_orientation = 1
    plt_bar_chart_CVE_count_by_CVSS_score_for_years.axis.axis_label_text_font_size='1.2em'
    show(plt_bar_chart_CVE_count_by_CVSS_score_for_years)
    




possibleColours = ['aliceblue', 'antiquewhite', 'aqua', 'aquamarine', 'azure', 'beige', 'bisque', 'black', 'blanchedalmond', 'blue', 'blueviolet', 'brown', 'burlywood', 'cadetblue', 'chartreuse', 'chocolate', 'coral', 'cornflowerblue', 'cornsilk', 'crimson', 'cyan', 'darkblue', 'darkcyan', 'darkgoldenrod', 'darkgray', 'darkgreen', 'darkgrey', 'darkkhaki', 'darkmagenta', 'darkolivegreen', 'darkorange', 'darkorchid', 'darkred', 'darksalmon', 'darkseagreen', 'darkslateblue', 'darkslategray', 'darkslategrey', 'darkturquoise', 'darkviolet', 'deeppink', 'deepskyblue', 'dimgray', 'dimgrey', 'dodgerblue', 'firebrick', 'floralwhite', 'forestgreen', 'fuchsia', 'gainsboro', 'ghostwhite', 'gold', 'goldenrod', 'gray', 'green', 'greenyellow', 'grey', 'honeydew', 'hotpink', 'indianred', 'indigo', 'ivory', 'khaki', 'lavender', 'lavenderblush', 'lawngreen', 'lemonchiffon', 'lightblue', 'lightcoral', 'lightcyan', 'lightgoldenrodyellow', 'lightgray', 'lightgreen', 'lightgrey', 'lightpink', 'lightsalmon', 'lightseagreen', 'lightskyblue', 'lightslategray', 'lightslategrey', 'lightsteelblue', 'lightyellow', 'lime', 'limegreen', 'linen', 'magenta', 'maroon', 'mediumaquamarine', 'mediumblue', 'mediumorchid', 'mediumpurple', 'mediumseagreen', 'mediumslateblue', 'mediumspringgreen', 'mediumturquoise', 'mediumvioletred', 'midnightblue', 'mintcream', 'mistyrose', 'moccasin', 'navajowhite', 'navy', 'oldlace', 'olive', 'olivedrab', 'orange', 'orangered', 'orchid', 'palegoldenrod', 'palegreen', 'paleturquoise', 'palevioletred', 'papayawhip', 'peachpuff', 'peru', 'pink', 'plum', 'powderblue', 'purple', 'red', 'rosybrown', 'royalblue', 'saddlebrown', 'salmon', 'sandybrown', 'seagreen', 'seashell', 'sienna', 'silver', 'skyblue', 'slateblue', 'slategray', 'slategrey', 'snow', 'springgreen', 'steelblue', 'tan', 'teal', 'thistle', 'tomato', 'turquoise', 'violet', 'wheat', 'white', 'whitesmoke', 'yellow', 'yellowgreen']