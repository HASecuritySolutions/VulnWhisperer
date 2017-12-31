<p align="center"><img src="https://github.com/austin-taylor/vulnwhisperer/blob/master/docs/source/vuln_whisperer_logo_s.png" width="400px"></p>

<p align="center"> <i>Create <u><b>actionable data</b></u> from your vulnerability scans </i> </p> 

<p align="center" style="width:400px"><img src="https://github.com/austin-taylor/vulnwhisperer/blob/master/docs/source/vulnWhispererWebApplications.png" style="width:400px"></p>


VulnWhisperer is a vulnerability report aggregator. VulnWhisperer will pull all the reports
 and create a file with a unique filename which is then fed into logstash. Logstash extracts data from the filename and tags all of the information inside the report (see logstash_vulnwhisp.conf file). Data is then shipped to elasticsearch to be indexed.


Requirements
-------------
####
*   ElasticStack 5.x
*   Python 2.7
*   Vulnerability Scanner
*   Optional: Message broker such as Kafka or RabbitMQ 

Currently Supports
-----------------

### Vulnerability Frameworks

- [X] Nessus V6
- [X] Qualys Web Applications
- [ ] Qualys Vulnerability Management (_in progress_)
- [ ] OpenVAS
- [ ] Nexpose
- [ ] NMAP
- [ ] More to come


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

cd /path/to/VulnWhisperer
sudo python setup.py install
```


Configuration
-----

There are a few configuration steps to setting up VulnWhisperer:
*   Configure Ini file
*   Setup Logstash File
*   Import ElasticSearch Templates
*   Import Kibana Dashboards

Run
-----
To run, fill out the configuration file with your vulnerability scanner settings. Then you can execute from the command line.
```python

vuln_whisperer -c configs/example.ini -s nessus
or
vuln_whisperer -c configs/example.ini -s qualys

```
<p align="center" style="width:300px"><img src="https://github.com/austin-taylor/vulnwhisperer/blob/master/docs/source/running_vuln_whisperer.png" style="width:400px"></p>
Next you'll need to import the visualizations into Kibana and setup your logstash config. A more thorough README is underway with setup instructions.

_For windows, you may need to type the full path of the binary in vulnWhisperer located in the bin directory._

Credit
------
Big thank you to <a href="https://github.com/SMAPPER">Justin Henderson</a> for his contributions to vulnWhisperer!

AS SEEN ON TV
-------------
<p align="center" style="width:400px"><a href="https://twitter.com/MalwareJake/status/935654519471353856"><img src="https://github.com/austin-taylor/vulnwhisperer/blob/master/docs/source/as_seen_on_tv.png" style="width:400px"></a></p>