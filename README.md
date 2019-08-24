<p align="center"><img src="https://github.com/austin-taylor/vulnwhisperer/blob/master/docs/source/vuln_whisperer_logo_s.png" width="400px"></p>
<p align="center"> <i>Create <u><b>actionable data</b></u> from your vulnerability scans </i> </p> 

<p align="center" style="width:400px"><img src="https://github.com/austin-taylor/vulnwhisperer/blob/master/docs/source/vulnWhispererWebApplications.png" style="width:400px"></p>


VulnWhisperer is a vulnerability management tool and report aggregator. VulnWhisperer will pull all the reports from the different Vulnerability scanners and create a file with a unique filename for each one, using that data later to sync with Jira and feed Logstash. Jira does a closed cycle full Sync with the data provided by the Scanners, while Logstash indexes and tags all of the information inside the report (see logstash files at /resources/elk6/pipeline/). Data is then shipped to ElasticSearch to be indexed, and ends up in a visual and searchable format in Kibana with already defined dashboards.

[![Build Status](https://travis-ci.org/HASecuritySolutions/VulnWhisperer.svg?branch=master)](https://travis-ci.org/HASecuritySolutions/VulnWhisperer)
[![MIT License](https://img.shields.io/badge/license-MIT-blue.svg?style=flat)](http://choosealicense.com/licenses/mit/)
[![Twitter](https://img.shields.io/twitter/follow/VulnWhisperer.svg?style=social&label=Follow)](https://twitter.com/VulnWhisperer)

Currently Supports
-----------------

### Vulnerability Frameworks

- [X] [Nessus (**v6**/**v7**/**v8**)](https://www.tenable.com/products/nessus/nessus-professional)
- [X] [Qualys Web Applications](https://www.qualys.com/apps/web-app-scanning/)
- [X] [Qualys Vulnerability Management](https://www.qualys.com/apps/vulnerability-management/)
- [X] [OpenVAS (**v7**/**v8**/**v9**)](http://www.openvas.org/)
- [X] [Tenable.io](https://www.tenable.com/products/tenable-io)
- [ ] [Detectify](https://detectify.com/)
- [ ] [Nexpose](https://www.rapid7.com/products/nexpose/)
- [ ] [Insight VM](https://www.rapid7.com/products/insightvm/)
- [ ] [NMAP](https://nmap.org/)
- [ ] [Burp Suite](https://portswigger.net/burp)
- [ ] [OWASP ZAP](https://www.zaproxy.org/)
- [ ] More to come

### Reporting Frameworks

- [X] [ELK (**v6**/**v7**)](https://www.elastic.co/elk-stack)
- [X] [Jira](https://www.atlassian.com/software/jira)
- [ ] [Splunk](https://www.splunk.com/)

Getting Started
===============

1) Follow the [install requirements](#installreq)
2) Fill out the section you want to process in <a href="https://github.com/HASecuritySolutions/VulnWhisperer/blob/master/configs/frameworks_example.ini">frameworks_example.ini file</a>
3) [JIRA] If using Jira, fill Jira config in the config file mentioned above.
3) [ELK] Modify the IP settings in the <a href="https://github.com/HASecuritySolutions/VulnWhisperer/tree/master/resources/elk6/pipeline">Logstash files to accommodate your environment</a> and import them to your logstash conf directory (default is /etc/logstash/conf.d/)
4) [ELK] Import the <a href="https://github.com/HASecuritySolutions/VulnWhisperer/blob/master/resources/elk6/kibana.json">Kibana visualizations</a>
5) [Run Vulnwhisperer](#run)

Need assistance or just want to chat? Join our [slack channel](https://join.slack.com/t/vulnwhisperer/shared_invite/enQtNDQ5MzE4OTIyODU0LWQxZTcxYTY0MWUwYzA4MTlmMWZlYWY2Y2ZmM2EzNDFmNWVlOTM4MzNjYzI0YzdkMDA0YmQyYWRhZGI2NGUxNGI)

Requirements
-------------
####
*   Python 2.7
*   Vulnerability Scanner
*   Reporting System: Jira / ElasticStack 6.6

<a id="installreq">Install Requirements-VulnWhisperer(may require sudo)</a>
--------------------
**Install OS packages requirement dependencies** (Debian-based distros, CentOS don't need it)
```shell

sudo apt-get install  zlib1g-dev libxml2-dev libxslt1-dev 
```

**(Optional) Use a python virtualenv to not mess with host python libraries**
```shell
virtualenv venv (will create the python 2.7 virtualenv)
source venv/bin/activate (start the virtualenv, now pip will run there and should install libraries without sudo)

deactivate (for quitting the virtualenv once you are done)
```

**Install python libraries requirements**

```python
pip install -r /path/to/VulnWhisperer/requirements.txt
cd /path/to/VulnWhisperer
python setup.py install
```

**(Optional) If using a proxy, add proxy URL as environment variable to PATH**
```shell
export HTTP_PROXY=http://example.com:8080
export HTTPS_PROXY=http://example.com:8080
```

Now you're ready to pull down scans. (see <a href="#run">run section</a>)

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
(optional flag: -F -> provides "Fancy" log colouring, good for comprehension when manually executing VulnWhisperer)
vuln_whisperer -c configs/frameworks_example.ini -s nessus 
or
vuln_whisperer -c configs/frameworks_example.ini -s qualys

```
If no section is specified (e.g. -s nessus), vulnwhisperer will check on the config file for the modules that have the property `enabled=true` and run them sequentially.

<p align="center" style="width:300px"><img src="https://github.com/austin-taylor/vulnwhisperer/blob/master/docs/source/running_vuln_whisperer.png" style="width:400px"></p>
Next you'll need to import the visualizations into Kibana and setup your logstash config. You can either follow the sample setup instructions [here](https://github.com/HASecuritySolutions/VulnWhisperer/wiki/Sample-Guide-ELK-Deployment) or go for the `docker-compose` solution we offer.


Docker-compose
-----
ELK is a whole world by itself, and for newcomers to the platform, it requires basic Linux skills and usually a bit of troubleshooting until it is deployed and working as expected. As we are not able to provide support for each users ELK problems, we put together a docker-compose which includes:

- VulnWhisperer
- Logstash 6.6
- ElasticSearch 6.6
- Kibana 6.6

The docker-compose just requires specifying the paths where the VulnWhisperer data will be saved, and where the config files reside. If ran directly after `git clone`, with just adding the Scanner config to the VulnWhisperer config file ([/resources/elk6/vulnwhisperer.ini](https://github.com/HASecuritySolutions/VulnWhisperer/blob/master/resources/elk6/vulnwhisperer.ini)), it will work out of the box.

It also takes care to load the Kibana Dashboards and Visualizations automatically through the API, which needs to be done manually otherwise at Kibana's startup.

For more info about the docker-compose, check on the [docker-compose wiki](https://github.com/HASecuritySolutions/VulnWhisperer/wiki/docker-compose-Instructions) or the [FAQ](https://github.com/HASecuritySolutions/VulnWhisperer/wiki).

Getting Started
===============

Our current Roadmap is as follows:
- [ ] Create a Vulnerability Standard
- [ ] Map every scanner results to the standard 
- [ ] Create Scanner module guidelines for easy integration of new scanners (consistency will allow #14)
- [ ] Refactor the code to reuse functions and enable full compatibility among modules
- [ ] Change Nessus CSV to JSON (Consistency and Fix #82)
- [ ] Adapt single Logstash to standard and Kibana Dashboards
- [ ] Implement Detectify Scanner
- [ ] Implement Splunk Reporting/Dashboards

On top of this, we try to focus on fixing bugs as soon as possible, which might delay the development. We also very welcome PR's, and once we have the new standard implemented, it will be very easy to add compatibility with new scanners. 

The Vulnerability Standard will initially be a new simple one level JSON with all the information that matches from the different scanners having standardized variable names, while maintaining the rest of the variables as they are. In the future, once everything is implemented, we will evaluate moving to an existing standard like ECS or AWS Vulnerability Schema; we prioritize functionality over perfection.

Video Walkthrough -- Featured on ElasticWebinar
----------------------------------------------
<a href="http://www.youtube.com/watch?feature=player_embedded&v=zrEuTtRUfNw?start=30
" target="_blank"><img src="https://github.com/austin-taylor/vulnwhisperer/blob/master/docs/source/elastic_webinar.png" 
alt="Elastic presentation on VulnWhisperer" border="10" /></a>

Authors
------
   - [Austin Taylor (@HuntOperator)](https://github.com/austin-taylor)
   - [Justin Henderson (@smapper)](https://github.com/SMAPPER)
   
Contributors
------------
   - [Quim Montal (@qmontal)](https://github.com/qmontal)
   - [@pemontto](https://github.com/pemontto)
   - [@cybergoof](https://github.com/cybergoof)

AS SEEN ON TV
-------------
<p align="center" style="width:400px"><a href="https://twitter.com/MalwareJake/status/935654519471353856"><img src="https://github.com/austin-taylor/vulnwhisperer/blob/master/docs/source/as_seen_on_tv.png" style="width:400px"></a></p>
