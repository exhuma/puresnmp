FROM python:2.7
WORKDIR /opt/app
RUN apt-get update
RUN mkdir /opt/app -p
RUN apt-get -y install snmpd
COPY snmpd.conf /etc/snmp/snmpd.conf
EXPOSE 161
# COPY requirements.txt /opt/app
# RUN pip install -r /opt/app/requirements.txt
# COPY . /opt/app
# RUN pip install /opt/app
# VOLUME /var/lost_tracker/data
# RUN mkdir -p /opt/app/.mamerwiselen/lost-tracker
# COPY lost_docker.ini /opt/app/.mamerwiselen/lost-tracker/app.ini
# COPY logging.conf /opt/app
# RUN pip install alembic
# COPY alembic /opt/app/alembic
# COPY alembic.ini /opt/app
CMD ["snmpd", "-f", "-V"]
