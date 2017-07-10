# VulnWhisperer

<p align="center"><img src="https://github.com/austin-taylor/vulnwhisperer/blob/master/docs/source/vuln_whisperer_logo_s.png" width="400px">
_Create actionable data from your vulnerability scans_
</p>
<p align="center" style="width:400px"><img src="https://github.com/austin-taylor/vulnwhisperer/blob/master/docs/source/vulnwhisp_dashboard.jpg" style="width:400px"></p>


VulnWhisperer is a vulnerability report aggregator for nessus (more scanners to come). VulnWHisperer will pull all the reports
 and create a file with a unique filename which is then fed into logstash. Logstash extracts data from the filename and tags all of the information inside the report (see logstash_vulnwhisp.conf file). Data is then shipped to elasticsearch to be indexed.


Getting Started
---------------

Currently supports python 2.7

```python
sudo pip install -r requirements.txt
python setup.py install
```

Currently Supports
-------------
####
*   Nessus


Setup
===============


Configuration
-----

There are a few configuration steps to setting up VulnWhisperer:
*   Configure Ini file
*   Setup Logstash File
*   Import ElasticSearch Templates
*   Import Kibana Dashboards


Credit
------
Big thank you to <a href="https://github.com/SMAPPER">Justin Henderson</a> for his contributions to vulnWhisperer!