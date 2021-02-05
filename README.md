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

