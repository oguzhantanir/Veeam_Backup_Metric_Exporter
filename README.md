This Python script allows you to retrieve metric data from the Veaam API and create a Grafana Dashboard using the Prometheus.

Fill in the required fields "IP, Port, Service User and Password" in the script, and ensure Veeam API service is enabled.

Run the script:
- python veeam_exporter.py

Check to Result:
- curl http://localhost:8000/metrics
