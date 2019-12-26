FROM python:2.7
WORKDIR /opt/app
RUN apt-get update
RUN mkdir /opt/app -p
RUN apt-get -y install snmpd snmp libsnmp-dev
COPY snmpd.conf /etc/snmp/snmpd.conf
COPY send_trap /usr/local/bin
RUN chmod +x /usr/local/bin/send_trap
EXPOSE 161/udp
# RUN snmpd && snmpusm -v3 -u initial -n "" -l authNoPriv -a MD5 -A setup_passphrase localhost create wes initial && killall snmpd
# RUN snmpd && snmpusm -v3 -Ca -u wes -n "" -l authNoPriv -a MD5 -A setup_passphrase localhost passwd setup_passphrase new_passphrase
RUN net-snmp-create-v3-user -A theauthpass -a MD5 helloworld
RUN net-snmp-create-v3-user -A theauthpass -X privpass -x DES -a MD5 ninja
CMD ["snmpd", "-f", "-V"]
