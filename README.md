# NVR-Honeypot-system

This is a NVR Honeypot system that me and my team created and worked on as part of the Research & Development course of our university. The honeypot logs attacks on NVR protocols, that include HTTP, RTSP and ONVIF. These logs files are then preprocessed, indexed and visualised using the ELK stack (Elastic, Logstash and Kibana). The project also contains a dockerfile that can make a docker container of main2.py and a docker-compose.yml that containerises main2.py and the ELK stack.

## flaskapp.py
Contains a fake NVR dashboard

## honeypot.py
Listens for traffic on NVR protocols (HTTP, RTSP, ONVIF) and logs them to /logs

## main2.py
An integration of flaskapp.py and honeypot.py

## logstash.conf
Processes the log files stored in logs and sends them to Elastic


