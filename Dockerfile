FROM centos:latest

MAINTAINER Justin Henderson justin@hasecuritysolutions.com

RUN yum update -y
RUN yum install -y python python-devel git gcc
RUN curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py
RUN python get-pip.py

WORKDIR /opt/VulnWhisperer

COPY requirements.txt requirements.txt
COPY setup.py setup.py
COPY vulnwhisp/ vulnwhisp/
COPY bin/ bin/
COPY deps/ deps/
COPY configs/frameworks_example.ini frameworks_example.ini

RUN python setup.py clean --all
RUN pip install -r requirements.txt

WORKDIR /opt/VulnWhisperer/deps/qualysapi
RUN python setup.py install

WORKDIR /opt/VulnWhisperer
RUN python setup.py install


CMD  vuln_whisperer -c /opt/VulnWhisperer/frameworks_example.ini
