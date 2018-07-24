FROM python:2.7
WORKDIR /opt/app
RUN apt-get update
RUN mkdir /opt/app -p
RUN apt-get -y install snmpd
COPY snmpd.conf /etc/snmp/snmpd.conf
EXPOSE 161/udp
CMD ["snmpd", "-f", "-V"]
