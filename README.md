<p align="center"><img src="https://github.com/austin-taylor/vulnwhisperer/blob/master/docs/source/vuln_whisperer_logo_s.png" width="400px"></p>

<p align="center"> <i>Create <u><b>actionable data</b></u> from your vulnerability scans </i> </p> 

<p align="center" style="width:400px"><img src="https://github.com/austin-taylor/vulnwhisperer/blob/master/docs/source/vulnwhisp_dashboard.jpg" style="width:400px"></p>


VulnWhisperer is a vulnerability report aggregator for nessus (more scanners to come). VulnWhisperer will pull all the reports
 and create a file with a unique filename which is then fed into logstash. Logstash extracts data from the filename and tags all of the information inside the report (see logstash_vulnwhisp.conf file). Data is then shipped to elasticsearch to be indexed.


Requirements
-------------
####
*   ElasticStack
*   Python 2.7
*   Vulnerability Scanner - (Nessus)
*   Optional: Message broker such as Kafka or RabbitMQ 

Currently Supports
-------------
####
*   Elasticsearch 2.x
*   Python 2.7
*   Nessus


Setup
===============

```python
Install pip:
sudo <pkg-manager> install python-pip
sudo pip install --upgrade pip

Manually install requirements:
sudo pip install pytz
sudo pip install pandas

Using requirements file:
sudo pip install -r /path/to/VulnWhisperer/requirements.txt

python /path/to/VulnWhisperer/setup.py install
```


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
