<p align="center"><img src="https://github.com/austin-taylor/vulnwhisperer/blob/master/docs/source/vuln_whisperer_logo_s.png" width="400px"></p>
<p align="center"> <i>Create <u><b>actionable data</b></u> from your vulnerability scans </i> </p> 

<p align="center" style="width:400px"><img src="https://github.com/austin-taylor/vulnwhisperer/blob/master/docs/source/vulnWhispererWebApplications.png" style="width:400px"></p>


VulnWhisperer is a vulnerability data and report aggregator. VulnWhisperer will pull all the reports
 and create a file with a unique filename which is then fed into logstash. Logstash extracts data from the filename and tags all of the information inside the report (see logstash_vulnwhisp.conf file). Data is then shipped to elasticsearch to be indexed.

[![Build Status](https://travis-ci.org/austin-taylor/VulnWhisperer.svg?branch=master)](https://travis-ci.org/austin-taylor/VulnWhisperer)
[![MIT License](https://img.shields.io/badge/license-MIT-blue.svg?style=flat)](http://choosealicense.com/licenses/mit/)
[![Twitter](https://img.shields.io/twitter/follow/VulnWhisperer.svg?style=social&label=Follow)](https://twitter.com/VulnWhisperer)


Currently Supports
-----------------

### Vulnerability Frameworks

- [X] [Nessus (v6 & **v7**)](https://www.tenable.com/products/nessus/nessus-professional)
- [X] [Qualys Web Applications](https://www.qualys.com/apps/web-app-scanning/)
- [X] [Qualys Vulnerability Management](https://www.qualys.com/apps/vulnerability-management/)
- [X] [OpenVAS](http://www.openvas.org/)
- [X] [Tenable.io](https://www.tenable.com/products/tenable-io)
- [ ] [Detectify](https://detectify.com/)
- [ ] [Nexpose](https://www.rapid7.com/products/nexpose/)
- [ ] [Insight VM](https://www.rapid7.com/products/insightvm/)
- [ ] [NMAP](https://nmap.org/)
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

<a id="installreq">Install Requirements-VulnWhisperer(may require sudo)</a>
--------------------
**First, install requirement dependencies**
```shell

sudo apt-get install  zlib1g-dev libxml2-dev libxslt1-dev 
```

**Second, install dependant modules**
```python

cd deps/qualysapi
python setup.py install
```


**Third, install requirements**

```python
pip install -r /path/to/VulnWhisperer/requirements.txt
cd /path/to/VulnWhisperer
python setup.py install
```

Now you're ready to pull down scans. (see <a href="#run">run section</a>)


Install Requirements-ELK Node **\*SAMPLE\***
--------------------
The following instructions should be utilized as a **Sample Guide** in the absence of an existing ELK Cluster/Node. This will cover a Debian example install guide of a stand-alone node of Elasticsearch & Kibana.

While Logstash is included in this install guide, it it recommended that a seperate host pulling the VulnWhisperer data is utilized with Logstash to ship the data to the Elasticsearch node.

*Please note there is a docker-compose.yml available as well.*

**Debian:** *(https://www.elastic.co/guide/en/elasticsearch/reference/5.6/deb.html)*
```shell
sudo apt-get install -y default-jre
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -
sudo apt-get install apt-transport-https
echo "deb https://artifacts.elastic.co/packages/5.x/apt stable main" | sudo tee -a /etc/apt/sources.list.d/elastic-5.x.list
sudo apt-get update && sudo apt-get install elasticsearch kibana logstash
sudo /bin/systemctl daemon-reload
sudo /bin/systemctl enable elasticsearch.service
sudo /bin/systemctl enable kibana.service
sudo /bin/systemctl enable logstash.service
```

**Elasticsearch & Kibana Sample Config Notes** 

Utilizing your favorite text editor:
*   Grab your host IP and change the IP of your /etc/elasticsearch/elasticsearch.yml file. (This defaults to 'localhost')
*   Validate Elasticsearch is set to run on port 9200 (Default)
*   Grab your host IP and change the IP of your /etc/kibana/kibana.yml file. (This defaults to 'localhost') *Validate that Kibana is pointing to the correct Elasticsearch IP (This was set in the previous step)*
*   Validate Kibana is set to run on port 5601 (Default)

*Start elasticsearch and validate they are running/communicating with one another:* 
```shell
sudo service elasticsearch start
sudo service kibana start
```
OR
```shell
sudo systemctl start elasticsearch.service
sudo systemctl start kibana.service
```

**Logstash Sample Config Notes**

*   Copy/Move the Logstash .conf files from */VulnWhisperer/logstash/* to */etc/logstash/conf.d/*
*   Validate the Logstash.conf files *input* contains the correct location of VulnWhisper Scans in the *input.file.path* directory identified below:
```
input {
  file {
    path => "/opt/vulnwhisperer/nessus/**/*"
    start_position => "beginning"
    tags => "nessus"
    type => "nessus"
  }
}
```
*   Validate the Logstash.conf files *output* contains the correct Elasticsearch IP set during the previous step above: (This will default to localhost)
```
output {
  if "nessus" in [tags] or [type] == "nessus" {
    #stdout { codec => rubydebug }
    elasticsearch {
      hosts => [ "localhost:9200" ]
      index => "logstash-vulnwhisperer-%{+YYYY.MM}"
    }
  }
```
*   Validate logstash has the correct file permissions to read the location of the VulnWhisperer Scans

Once configured run Logstash: (Running Logstash as a service will pick up all the files in */etc/logstash/conf.d/* If you would like to run only one logstash file please reference the command below):

Logstash as a service:
```shell
sudo service logstash start
```
*OR*
```shell
sudo systemctl start logstash.service
```
Single Logstash file:
```shell
sudo /usr/share/logstash/bin/logstash --path.settings /etc/logstash/ -f /etc/logstash/conf.d/1000_nessus_process_file.conf
```

Configuration
-----

There are a few configuration steps to setting up VulnWhisperer:
*   Configure Ini file
*   Setup Logstash File
*   Import ElasticSearch Templates
*   Import Kibana Dashboards

<a href="https://github.com/austin-taylor/VulnWhisperer/blob/master/configs/frameworks_example.ini">frameworks_example.ini file</a>
<p align="left" style="width:200px"><img src="https://github.com/austin-taylor/vulnwhisperer/blob/master/docs/source/config_example.png" style="width:200px"></p>


<a id="run">Run</a>
-----
To run, fill out the configuration file with your vulnerability scanner settings. Then you can execute from the command line.
```python

vuln_whisperer -c configs/frameworks_example.ini -s nessus
or
vuln_whisperer -c configs/frameworks_example.ini -s qualys

```
If no section is specified (e.g. -s nessus), vulnwhisperer will check on the config file for the modules that have the property enabled=true and run them sequentially.

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
