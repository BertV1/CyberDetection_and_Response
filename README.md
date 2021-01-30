# Cyber Detection & Response
>  Working with NVD' CVE / CVSS data feeds in Python to serve various purposes

## Background

1. Our primary data source will be the **JSON data feeds** from the National Vulnerability Database (NVD) (= primary source)
   * https://nvd.nist.gov/vuln/data-feeds
2. We will be working exclusively in **Python** (3.9)
   * optional libraries and modules are allowed
3. As code editor Visual Studio Code (**VSC**) will be used
4. for CI and ease of use, **GitKraken** seems ideal at this point
   * version 5.0.4, because we can work with private repos without purchasing a license.

## Plan of attack

> Since the primary source is quite large, the first step to undertake is to extract relevant information from the JSON

### required properties

* To serve our needs best we will need the following properties

| n°   | Property name   | JSON property name | JSON path |
| ---- | --------------- | ------------------ | --------- |
| 1    | CVE title       |                    |           |
| 2    | CVE description |                    |           |
| 3    | CVSS score      |                    |           |

### optional properties

* These properties could be useful in the future, so it would be wise to already look at ways how to extract them

| n°   | Property name               | JSON property name | JSON path |
| ---- | --------------------------- | ------------------ | --------- |
| 1    | CVE access vector           |                    |           |
| 2    | CVE access complexity       |                    |           |
| 3    | CVE requires authentication |                    |           |

