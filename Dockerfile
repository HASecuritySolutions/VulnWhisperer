FROM centos:7

MAINTAINER Justin Henderson justin@hasecuritysolutions.com

RUN yum update -y && \
    yum install -y python python-devel git gcc && \
    curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py && \
    python get-pip.py

WORKDIR /opt/VulnWhisperer

COPY requirements.txt requirements.txt
COPY setup.py setup.py
COPY vulnwhisp/ vulnwhisp/
COPY bin/ bin/
COPY configs/frameworks_example.ini frameworks_example.ini

RUN python setup.py clean --all && \
    pip install -r requirements.txt


WORKDIR /opt/VulnWhisperer
RUN python setup.py install


CMD  vuln_whisperer -c /opt/VulnWhisperer/frameworks_example.ini
