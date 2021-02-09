import dataFunctions as DF
from bokeh.models import ColumnDataSource,ranges,LabelSet,Title
from bokeh.plotting import figure,show
from bokeh.palettes import PuBu
import random

####################################
##                                ##
##    CVE COUNT BY CVE YEAR ID    ##
##                                ##
####################################

def bar_chart_CVE_by_ID(JSON_CVE_DATA):

    lst_CVE_IDs = DF.getCVEIDs(JSON_CVE_DATA)
    lst_cnt_CVEs_By_Year = DF.getCVEbyYear(lst_CVE_IDs)

    years = ['1999','2000','2001','2002']
    x_label = 'Years'
    y_label = 'Number of CVEs'

    lbl_src = ColumnDataSource(dict(x=years,y=lst_cnt_CVEs_By_Year))

    plt_bar_chart_CVE_by_ID = figure(
        plot_height=750,
        plot_width=600,
        toolbar_location='right',
        x_axis_label=x_label,
        y_axis_label=y_label,
        title='CVE-ID based total CVE count by Year: 1999-2002',
        x_minor_ticks=6,
        x_range=lbl_src.data['x'],
        y_range=ranges.Range1d(start=0,end=3000)
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






possibleColours = ['aliceblue', 'antiquewhite', 'aqua', 'aquamarine', 'azure', 'beige', 'bisque', 'black', 'blanchedalmond', 'blue', 'blueviolet', 'brown', 'burlywood', 'cadetblue', 'chartreuse', 'chocolate', 'coral', 'cornflowerblue', 'cornsilk', 'crimson', 'cyan', 'darkblue', 'darkcyan', 'darkgoldenrod', 'darkgray', 'darkgreen', 'darkgrey', 'darkkhaki', 'darkmagenta', 'darkolivegreen', 'darkorange', 'darkorchid', 'darkred', 'darksalmon', 'darkseagreen', 'darkslateblue', 'darkslategray', 'darkslategrey', 'darkturquoise', 'darkviolet', 'deeppink', 'deepskyblue', 'dimgray', 'dimgrey', 'dodgerblue', 'firebrick', 'floralwhite', 'forestgreen', 'fuchsia', 'gainsboro', 'ghostwhite', 'gold', 'goldenrod', 'gray', 'green', 'greenyellow', 'grey', 'honeydew', 'hotpink', 'indianred', 'indigo', 'ivory', 'khaki', 'lavender', 'lavenderblush', 'lawngreen', 'lemonchiffon', 'lightblue', 'lightcoral', 'lightcyan', 'lightgoldenrodyellow', 'lightgray', 'lightgreen', 'lightgrey', 'lightpink', 'lightsalmon', 'lightseagreen', 'lightskyblue', 'lightslategray', 'lightslategrey', 'lightsteelblue', 'lightyellow', 'lime', 'limegreen', 'linen', 'magenta', 'maroon', 'mediumaquamarine', 'mediumblue', 'mediumorchid', 'mediumpurple', 'mediumseagreen', 'mediumslateblue', 'mediumspringgreen', 'mediumturquoise', 'mediumvioletred', 'midnightblue', 'mintcream', 'mistyrose', 'moccasin', 'navajowhite', 'navy', 'oldlace', 'olive', 'olivedrab', 'orange', 'orangered', 'orchid', 'palegoldenrod', 'palegreen', 'paleturquoise', 'palevioletred', 'papayawhip', 'peachpuff', 'peru', 'pink', 'plum', 'powderblue', 'purple', 'red', 'rosybrown', 'royalblue', 'saddlebrown', 'salmon', 'sandybrown', 'seagreen', 'seashell', 'sienna', 'silver', 'skyblue', 'slateblue', 'slategray', 'slategrey', 'snow', 'springgreen', 'steelblue', 'tan', 'teal', 'thistle', 'tomato', 'turquoise', 'violet', 'wheat', 'white', 'whitesmoke', 'yellow', 'yellowgreen']