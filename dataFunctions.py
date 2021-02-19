
import numpy as np

def getCVEIDs(cveJsonFile):
    cveIDs = []
    for cve in cveJsonFile['CVE_Items']:
        #print(cve['cve']['CVE_data_meta']['ID'])
        cveIDs.append(cve['cve']['CVE_data_meta']['ID'])
    return cveIDs

def getCVEpubDateAndScore(cveJsonFile):
    #todo discarding entries after 2002
    #todo only metric V2 items (97 are not baseMetricV2), none are V3 DONE
    CVE_pubDate_CVSS = []
    for cve in cveJsonFile['CVE_Items']:
        if 'baseMetricV2' in cve['impact']:
            CVE_pubDate_CVSS.append(list([cve['publishedDate'],cve['impact']['baseMetricV2']['cvssV2']['baseScore']]))
        if 'baseMetricV3' in cve['impact']:
            CVE_pubDate_CVSS.append(list([cve['publishedDate'],cve['impact']['baseMetricV3']['cvssV3']['baseScore']]))
    return CVE_pubDate_CVSS


def getCVSSbyYear(lst_pubdateAndCvss,year):
    lst_pubDateANDcvssBYyear = []
    for pubDateandcvss in lst_pubdateAndCvss:
        if year in pubDateandcvss[0]:
            lst_pubDateANDcvssBYyear.append(pubDateandcvss)
    return lst_pubDateANDcvssBYyear

def getCVSSbyMultipleYears(lst_pubdateAndCvss,lst_years):
    lst_pubDateANDcvssBYmultipleYears = []
    for pubDateandcvss in lst_pubdateAndCvss:
        for year in lst_years:
            if year in pubDateandcvss[0]:
                lst_pubDateANDcvssBYmultipleYears.append(pubDateandcvss)
    return lst_pubDateANDcvssBYmultipleYears

def getCVSSavgByMonth(lst_pubdate_cvss_oneYear_oneMonth):
    cvssSum = 0.0
    cvssCount = 0
    for pubDate_cvss in lst_pubdate_cvss_oneYear_oneMonth:
        #print("sum "+str(cvssSum)+" & count "+str(cvssCount)+" of "+pubDate_cvss[0])
        cvssSum += pubDate_cvss
        cvssCount += 1
    if cvssCount != 0: #todo check if cve count for this month is not zero
        return cvssSum / cvssCount
    else:
        return 0

# we suppose we already have the json file, and have performed the necessary queries to come to this point
# but instead of now computing the avg cvss score per month for this year, we are going to count the cve's by their score 
# dat struct: lst_pubDateANDcvssBYyear = [[pubdate,cvss],[pubdate,cvss]...]
# 0-1 1-2 2-3 3-4 4-5 5-6 6-7 7-8 8-9 9-10
def getCVSSCountBracketsByYear(lst_pubDateANDcvssBYyear):
    lst_CVSS_count_brackets = [0]*10 # the first bracket contains the count for  0 to 1, the second bracket 1 to 2, ...
    # for pubdateANDcvss in lst_pubDateANDcvssBYyear:
    #     if pubdateANDcvss[1]<=0:
    #         lst_CVSS_count_brackets[0]+=1
    #     else:
    #         lst_CVSS_count_brackets[int(np.floor(pubdateANDcvss[1]-0.0001))] += 1
    #         if pubdateANDcvss[1] > 4 and pubdateANDcvss[1] <=5:
    #             print(pubdateANDcvss[1])
    #             print(int(np.floor(pubdateANDcvss[1]+0.0001)))
    # return lst_CVSS_count_brackets
    for pubdateANDcvss in lst_pubDateANDcvssBYyear:
        cvss = pubdateANDcvss[1]
        if cvss >= 0 and cvss <= 1:
            lst_CVSS_count_brackets[0] += 1
        if cvss > 1 and cvss <= 2:
            lst_CVSS_count_brackets[1] += 1
        if cvss > 2 and cvss <= 3:
            lst_CVSS_count_brackets[2] += 1
        if cvss > 3 and cvss <= 4:
            lst_CVSS_count_brackets[3] += 1
        if cvss > 4 and cvss <= 5:
            lst_CVSS_count_brackets[4] += 1
        if cvss > 5 and cvss <= 6:
            lst_CVSS_count_brackets[5] += 1
        if cvss > 6 and cvss <= 7:
            lst_CVSS_count_brackets[6] += 1
        if cvss > 7 and cvss <= 8:
            lst_CVSS_count_brackets[7] += 1
        if cvss > 8 and cvss <= 9:
            lst_CVSS_count_brackets[8] += 1
        if cvss > 9 and cvss <= 10:
            lst_CVSS_count_brackets[9] += 1
    return lst_CVSS_count_brackets

def getAverageCVSScountByMonth(lst_pubdate_cvss_oneYear):
    lst_avgCVSSbyMonth = []
    JAN = []
    FEB = []
    MAR = []
    APR = []
    MAY = []
    JUN = []
    JUL = []
    AUG = []
    SEP = []
    OCT = []
    NOV = []
    DEC = []
    MONTHS = [JAN,FEB,MAR,APR,MAY,JUN,JUL,AUG,SEP,OCT,NOV,DEC]
    for pubDateandcvss in lst_pubdate_cvss_oneYear:
        month = pubDateandcvss[0].split('-')[1]
        if month == '01':
            JAN.append(pubDateandcvss[1])
        elif month == '02':
            FEB.append(pubDateandcvss[1])
        elif month == '03':
            MAR.append(pubDateandcvss[1])
        elif month == '04':
            APR.append(pubDateandcvss[1])
        elif month == '05':
            MAY.append(pubDateandcvss[1])
        elif month == '06':
            JUN.append(pubDateandcvss[1])
        elif month == '07':
            JUL.append(pubDateandcvss[1])
        elif month == '08':
            AUG.append(pubDateandcvss[1])
        elif month == '09':
            SEP.append(pubDateandcvss[1])
        elif month == '10':
            OCT.append(pubDateandcvss[1])
        elif month == '11':
            NOV.append(pubDateandcvss[1])
        elif month == '12':
            DEC.append(pubDateandcvss[1])
        else:
            print('wtf are you doing, wrong date format????')
    for month in MONTHS:
        lst_avgCVSSbyMonth.append(getCVSSavgByMonth(month))
        #print(getCVSSavgByMonth(month))
    return lst_avgCVSSbyMonth

def getCVEID_cnt_byYear(CVEIDs):
    dct_cntByCVE_ID = {}
    lst_cveStr_prefixes = ['CVE-199','CVE-200','CVE-201','CVE-202']
    for cveID in CVEIDs:
        #if cveStr1 in cveID:
        for prefix in lst_cveStr_prefixes:
            for i in range(10):
                if prefix+str(i) in cveID:
                    if prefix+str(i) in dct_cntByCVE_ID:    
                        dct_cntByCVE_ID[prefix+str(i)] += 1
                    else:
                        dct_cntByCVE_ID.update({prefix+str(i):1})
    # for k,v in dct_cntByCVE_ID.items():
    #     print(k,'->',v)
    return dct_cntByCVE_ID

def getCVE_count_by_pubdateYear(jsonCVEdata, lst_years):
    dct_cntBypubDateyear = {}
    for year in lst_years:
        for cve in jsonCVEdata['CVE_Items']:
            if str(year) in cve['publishedDate']:
                if str(year) in dct_cntBypubDateyear:
                    dct_cntBypubDateyear[str(year)] += 1
                else:
                    dct_cntBypubDateyear[str(year)] = 1
    return dct_cntBypubDateyear

def sortIntStrings(lst_stringsThatAreInts):
    numbers = [int(x) for x in lst_stringsThatAreInts]
    return sorted(numbers)
