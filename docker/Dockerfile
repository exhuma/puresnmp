FROM python:2.7
WORKDIR /opt/app
RUN apt-get update
RUN mkdir /opt/app -p
RUN apt-get -y install snmpd snmp
COPY snmpd.conf /etc/snmp/snmpd.conf
COPY send_trap /usr/local/bin
RUN chmod +x /usr/local/bin/send_trap
EXPOSE 161/udp
CMD ["snmpd", "-f", "-V"]
