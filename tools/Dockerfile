# CloudShield v2.1 hotfix: Suricata is packaged in Ubuntu 24.04 universe,
# not in the Debian 12 Bookworm base used by the previous toolbox image.
FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates python3 suricata iperf3 iptables \
 && ln -s /usr/bin/python3 /usr/local/bin/python \
 && command -v suricata \
 && command -v iperf3 \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /lab
COPY tools/worker.py /lab/worker.py
COPY config/suricata/lab.rules /lab/lab.rules
COPY config/suricata/ips.rules /lab/ips.rules
COPY config/suricata/lab-demo.pcap /lab/lab-demo.pcap
EXPOSE 8099
CMD ["python3", "/lab/worker.py"]
