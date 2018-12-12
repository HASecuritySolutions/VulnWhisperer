FROM centos:latest

MAINTAINER Justin Henderson justin@hasecuritysolutions.com

RUN yum update -y
RUN yum install -y python python-devel git gcc
RUN curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py
RUN python get-pip.py
#RUN cd /opt && git clone https://github.com/austin-taylor/VulnWhisperer.git
RUN mkdir /opt/VulnWhisperer
COPY requirements.txt /opt/VulnWhisperer
COPY setup.py /opt/VulnWhisperer
COPY vulnwhisp /opt/VulnWhisperer/vulnwhisp
COPY bin/ /opt/VulnWhisperer/bin
#RUN cd /opt/VulnWhisperer && pip install -r requirements.txt
#RUN cd /opt/VulnWhisperer && python setup.py install
#RUN useradd -ms /bin/bash vulnwhisperer
#RUN mkdir /var/log/vulnwhisperer
#RUN chown vulnwhisperer: /var/log/vulnwhisperer
#RUN ln -sf /dev/stderr /var/log/vulnwhisperer/vulnwhisperer.log
RUN chown -R vulnwhisperer: /opt/VulnWhisperer
USER vulnwhisperer

STOPSIGNAL SIGTERM

CMD  vuln_whisperer -c /opt/VulnWhisperer/frameworks_example.ini
