<p align="center"><img src="https://github.com/austin-taylor/vulnwhisperer/blob/master/docs/source/vuln_whisperer_logo_s.png" width="400px"></p>
<p align="center"> <i>Create <u><b>actionable data</b></u> from your vulnerability scans </i> </p> 

<p align="center" style="width:400px"><img src="https://github.com/austin-taylor/vulnwhisperer/blob/master/docs/source/vulnWhispererWebApplications.png" style="width:400px"></p>


VulnWhisperer is a vulnerability data and report aggregator. VulnWhisperer will pull all the reports
 and create a file with a unique filename which is then fed into logstash. Logstash extracts data from the filename and tags all of the information inside the report (see logstash_vulnwhisp.conf file). Data is then shipped to elasticsearch to be indexed.

[![Build Status](https://travis-ci.org/austin-taylor/VulnWhisperer.svg?branch=master)](https://travis-ci.org/austin-taylor/VulnWhisperer)
[![MIT License](https://img.shields.io/badge/license-MIT-blue.svg?style=flat)](http://choosealicense.com/licenses/mit/)
[!Twitter](https://img.shields.io/twitter/follow/VulnWhisperer.svg?style=social&label=Follow)


Currently Supports
-----------------

### Vulnerability Frameworks

- [X] Nessus (v6 & **v7**)
- [X] Qualys Web Applications
- [ ] Qualys Vulnerability Management (_in progress_)
- [ ] OpenVAS
- [ ] Nexpose
- [ ] Insight VM
- [ ] NMAP
- [ ] More to come

Getting Started
===============

1) Follow the [install requirements](#installreq)
2) Fill out the section you want to process in <a href="https://github.com/austin-taylor/VulnWhisperer/blob/master/configs/frameworks_example.ini">example.ini file</a>
3) Modify the IP settings in the <a href="https://github.com/austin-taylor/VulnWhisperer/tree/master/logstash">logstash files to accomodate your environment</a> and import them to your logstash conf directory (default is /etc/logstash/conf.d/)
4) Import the <a href="https://github.com/austin-taylor/VulnWhisperer/tree/master/kibana/vuln_whisp_kibana">kibana visualizations</a>
5) [Run Vulnwhisperer](#run)

Requirements
-------------
####
*   ElasticStack 5.x
*   Python 2.7
*   Vulnerability Scanner
*   Optional: Message broker such as Kafka or RabbitMQ 

<a id="installreq">Install Requirements (may require sudo)</a>
--------------------

**First, install dependant modules**
```python

cd deps/qualysapi
python setup.py install
```


**Second, install requirements**

```python
pip install -r /path/to/VulnWhisperer/requirements.txt
cd /path/to/VulnWhisperer
python setup.py install
```

Now you're ready to pull down scans. (see <a href="#run">run section</a>)

Configuration
-----

There are a few configuration steps to setting up VulnWhisperer:
*   Configure Ini file
*   Setup Logstash File
*   Import ElasticSearch Templates
*   Import Kibana Dashboards

<a href="https://github.com/austin-taylor/VulnWhisperer/blob/master/configs/frameworks_example.ini">example.ini file</a>
<p align="left" style="width:200px"><img src="https://github.com/austin-taylor/vulnwhisperer/blob/master/docs/source/config_example.png" style="width:200px"></p>


<a id="run">Run</a>
-----
To run, fill out the configuration file with your vulnerability scanner settings. Then you can execute from the command line.
```python

vuln_whisperer -c configs/example.ini -s nessus
or
vuln_whisperer -c configs/example.ini -s qualys

```
<p align="center" style="width:300px"><img src="https://github.com/austin-taylor/vulnwhisperer/blob/master/docs/source/running_vuln_whisperer.png" style="width:400px"></p>
Next you'll need to import the visualizations into Kibana and setup your logstash config. A more thorough README is underway with setup instructions.

Running Nightly
---------------
If you're running linux, be sure to setup a cronjob to remove old files that get stored in the database. Be sure to change .csv if you're using json.

Setup crontab -e with the following config (modify to your environment) - this will run vulnwhisperer each night at 0130:

`00 1 * * * /usr/bin/find /opt/vulnwhisp/ -type f -name '*.csv' -ctime +3 -exec rm {} \;`

`30 1 * * * /usr/local/bin/vuln_whisperer -c /opt/vulnwhisp/configs/example.ini`


_For windows, you may need to type the full path of the binary in vulnWhisperer located in the bin directory._

Video Walkthrough -- Featured on ElasticWebinar
----------------------------------------------
<a href="http://www.youtube.com/watch?feature=player_embedded&v=zrEuTtRUfNw?start=30
" target="_blank"><img src="https://github.com/austin-taylor/vulnwhisperer/blob/master/docs/source/elastic_webinar.png" 
alt="Elastic presentation on VulnWhisperer" border="10" /></a>

Credit
------
Big thank you to <a href="https://github.com/SMAPPER">Justin Henderson</a> for his contributions to vulnWhisperer!


AS SEEN ON TV
-------------
<p align="center" style="width:400px"><a href="https://twitter.com/MalwareJake/status/935654519471353856"><img src="https://github.com/austin-taylor/vulnwhisperer/blob/master/docs/source/as_seen_on_tv.png" style="width:400px"></a></p>
