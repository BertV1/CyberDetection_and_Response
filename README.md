# Cyber Detection & Response
>  Working with NVD' CVE / CVSS data feeds in Python to serve various purposes

## Background

1. Our primary data source will be the **JSON data feeds** from the National Vulnerability Database (NVD) (= primary source)
   * https://nvd.nist.gov/vuln/data-feeds
2. We will be working exclusively in **Python** (3.9)
   * optional libraries and modules are allowed
     * json
       * working with json data, this is a must
     * bokeh
       * have worked with bokeh when creating visualisations in Sentinel notebooks 
     * random
       * for getting access to those sweet, sweet random numbers
3. As code editor Visual Studio Code (**VSC**) will be used
4. for CI and ease of use, **GitKraken** seems ideal at this point
   * version 5.0.4, because we can work with private repos without purchasing a license.
5. As for documentation purposes, **Typora** is something I have used for a couple of years
   * going to increase writing area because too much whitespace is just not practical!

## Plan of attack

> Since the primary source is quite large, the first step to undertake is to extract relevant information from the JSON

<u>Layout</u>

* all properties start from the `CVE_Items` root property

* an Item in `CVE_Items` contains **3 main properties** 

  * `cve`
  * `configurations`
  * `impact`

  and two singular properties

  * `publishedDate`
  * `lastModifiedDate`



### required properties

* To serve our needs best we will need the following properties

| n°   | Property name   | JSON property name | JSON path                                                    | JSON value type |
| ---- | --------------- | ------------------ | ------------------------------------------------------------ | --------------- |
| 1    | CVE title       | ID                 | CVE_Items[**!**] -> cve -> CVE_data_meta -> ID               | str             |
| 2    | CVE description | value              | CVE_Items[**!**] -> cve -> description -> description_data -> value | str             |
| 3    | CVE CVSS score  | baseScore          | CVE_Items[**!**] -> impact -> impact -> baseMetricV**?** -> cvssV**?** -> baseScore | float           |

\***!** the CVE currently being queried

\***?** can be 2,3 or 3.1

### optional properties

* These properties could be useful in the future, so it would be wise to already look at ways how to extract them

| n°   | Property name               | JSON property name | JSON path                                                    | JSON value type     |
| ---- | --------------------------- | ------------------ | ------------------------------------------------------------ | ------------------- |
| 1    | CVE access vector           | accessVector       | CVE_Items[**!**] -> impact -> impact -> baseMetricV**?** -> cvssV**?** -> accessVector | str                 |
| 2    | CVE access complexity       | accessComplexity   | CVE_Items[**!**] -> impact -> impact -> baseMetricV**?** -> cvssV**?** -> accessComplexity | str                 |
| 3    | CVE requires authentication | authentication     | CVE_Items[**!**] -> impact -> impact -> baseMetricV**?** -> cvssV**?** -> authentication | bool                |
| 4    | CVE date of publication     | publishedDate      | CVE_Items[**!**] -> publishedDate                            | str (ISO 8601 date) |

## Plots

### I

The first plot aims give a general overview of the CVEs of our datapool: we are counting the CVE based on their *CVE ID* for 1997-2002

### II

The second plot goes for a more nuanced direction. We are calculating the average CVSS score for each month in a given year. This is then plotted as a line chart, for the same time range as plot I: 1997 - 2002. The basis for the time is the publication date of the CVE, which in many cases has a different year than the CVE ID.

### III

For the third plot, we are counting the number of CVEs by year, based on the publication date of the CVE. The basis of this calculation are specific CVSS score brackets: [0-1], ]1-2],…,]9-10]. The ‘[’ & ’]‘ need to interpreted mathematically, in the sense that a CVSS score of 1 is included in the bracket [0-1]. A CVSS score of 1.1 for example will fall into the next bracket.

The surprising results of this plot, bracket ]8-9] has almost no results, is a nice find.



## Addenda

### bokeh possible colors

```python
Enum('aliceblue', 'antiquewhite', 'aqua', 'aquamarine', 'azure', 'beige', 'bisque', 'black', 'blanchedalmond', 'blue', 'blueviolet', 'brown', 'burlywood', 'cadetblue', 'chartreuse', 'chocolate', 'coral', 'cornflowerblue', 'cornsilk', 'crimson', 'cyan', 'darkblue', 'darkcyan', 'darkgoldenrod', 'darkgray', 'darkgreen', 'darkgrey', 'darkkhaki', 'darkmagenta', 'darkolivegreen', 'darkorange', 'darkorchid', 'darkred', 'darksalmon', 'darkseagreen', 'darkslateblue', 'darkslategray', 'darkslategrey', 'darkturquoise', 'darkviolet', 'deeppink', 'deepskyblue', 'dimgray', 'dimgrey', 'dodgerblue', 'firebrick', 'floralwhite', 'forestgreen', 'fuchsia', 'gainsboro', 'ghostwhite', 'gold', 'goldenrod', 'gray', 'green', 'greenyellow', 'grey', 'honeydew', 'hotpink', 'indianred', 'indigo', 'ivory', 'khaki', 'lavender', 'lavenderblush', 'lawngreen', 'lemonchiffon', 'lightblue', 'lightcoral', 'lightcyan', 'lightgoldenrodyellow', 'lightgray', 'lightgreen', 'lightgrey', 'lightpink', 'lightsalmon', 'lightseagreen', 'lightskyblue', 'lightslategray', 'lightslategrey', 'lightsteelblue', 'lightyellow', 'lime', 'limegreen', 'linen', 'magenta', 'maroon', 'mediumaquamarine', 'mediumblue', 'mediumorchid', 'mediumpurple', 'mediumseagreen', 'mediumslateblue', 'mediumspringgreen', 'mediumturquoise', 'mediumvioletred', 'midnightblue', 'mintcream', 'mistyrose', 'moccasin', 'navajowhite', 'navy', 'oldlace', 'olive', 'olivedrab', 'orange', 'orangered', 'orchid', 'palegoldenrod', 'palegreen', 'paleturquoise', 'palevioletred', 'papayawhip', 'peachpuff', 'peru', 'pink', 'plum', 'powderblue', 'purple', 'red', 'rosybrown', 'royalblue', 'saddlebrown', 'salmon', 'sandybrown', 'seagreen', 'seashell', 'sienna', 'silver', 'skyblue', 'slateblue', 'slategray', 'slategrey', 'snow', 'springgreen', 'steelblue', 'tan', 'teal', 'thistle', 'tomato', 'turquoise', 'violet', 'wheat', 'white', 'whitesmoke', 'yellow', 'yellowgreen')
```

