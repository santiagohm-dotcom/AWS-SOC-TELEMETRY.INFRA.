# ASOP – Automated Security Observability Platform

**DevOps Engineer – Portfolio Project**  
*Infrastructure as Code · Cloud Networking · Security Telemetry Pipeline*

---

## 📌 Project Snapshot

| Metric | Value |
|--------|-------|
| **Status** | Production‑ready (lab environment) |
| **Deployment Time** | ≈ 8 minutes (fully automated) |
| **Cost** | Optimised for AWS Free Tier (no NAT Gateway, `t3.micro` instances) |
| **Key Skills Demonstrated** | Infrastructure Engineering & Telemetry Pipeline Design, IaC (Terraform), AWS Networking (VPC, Security Groups), Cloud‑Init, Bash Automation, ELK Stack, IDS/Honeypots |

---

## 1. Situation – The Problem We Faced

Modern security labs require **reproducible**, **observable**, and **low‑cost** environments. Manual deployments lead to:

- Configuration drift
- Inconsistent logging
- Wasted time on repeatable tasks

**We needed a fully automated AWS lab that:**

- Ingests security telemetry from honeypots and an IDS
- Centralises logs in a SIEM (Elastic Stack)
- Provides a CLI assistant that translates technical alerts into human‑readable intelligence
- Can be destroyed and recreated in **minutes, with zero manual interventions**

---

## 2. Task – Our Mission

Design and implement an **idempotent, infrastructure‑as‑code** deployment that:

- Spins up three EC2 instances (Kali attacker, detection sensor, SIEM core)
- Automatically configures Suricata (IDS), Cowrie/Dionaea honeypots, Filebeat, Logstash, Elasticsearch, Kibana, and a **custom CLI dashboard**
- Hardens network access using **AWS Security Groups** and local firewalls
- Proves the pipeline by generating attack traffic (from Kali or local scripts) and showing real‑time alerts in both **Kibana** and the **terminal**

The project must be **portfolio‑ready** – clean code, professional documentation, and a clear demonstration of **infrastructure engineering skills**.

---

## 3. Action – How We Built It  

### 3.1. Infrastructure Design (AWS + Terraform)

> **Visual reference** – see `aws-network-topology.jpg` for the AWS network layout.

- **VPC** with two public subnets (Kali isolated, lab shared)
- **Internet Gateway only** – no NAT Gateway (cost control)
- **Security Groups micro‑segmented** (principle of least privilege):
  - `kali_sg` – SSH only from your IP.
  - `sensor_sg` – SSH from your IP + honeypot ports (`2222,21,445,1433`) open to `0.0.0.0/0` + **all traffic allowed from Kali SG** for attack simulation.
  - `siem_sg` – SSH & Kibana from your IP, Logstash (`5044`) and Elasticsearch (`9200`) **only from sensor SG**.

- **Three EC2 instances** (Ubuntu 22.04 for SIEM & sensor, Kali Linux as attacker):
  - `t3.medium` (SIEM) – enough RAM for Elasticsearch
  - `t3.micro` (sensor and Kali) – cost‑optimised

- **User‑Data scripts** (`install_siem.sh`, `install_sensor.sh`):
  - Idempotent
  - Detailed logging to `/var/log/asop-debug.log` (structured debugging)

### 3.2. Data Pipeline (End‑to‑End)

> **Data flow diagram** – see `data-flow-diagram.png` for a visual representation.
Kali (attacker) → Sensor Node → SIEM Node
│ │
├─ Suricata (IDS) ├─ Filebeat (shipper)
├─ Cowrie (SSH honeypot) ├─ Logstash (processor)
└─ Dionaea (FTP/SMB/MSSQL) └─ Elasticsearch (storage)
│
├─ Kibana (UI)
└─ soc_cli_dashboard.py (CLI assistant)

text

- **Traffic generation** – manual attacks from Kali or local scripts (`nmap`, `ssh -p 2222`, `ftp`)
- **Detection** – Suricata with three test rules (ICMP, TCP, UDP) + honeypot logs
- **Shipping** – Filebeat watches JSON logs and forwards them to Logstash
- **Processing** – Logstash parses, enriches and indexes data into `asop-logs-*`
- **Storage & visualisation** – Elasticsearch + Kibana
- **Intelligent CLI assistant** – a Python script that queries Elasticsearch and **filters out noise** (flow/stats events), showing only security alerts. This architectural decision **reduces Time to Insight** for a SOC analyst.

### 3.3. Key Automation & Resilience Decisions

| Challenge | Solution |
|-----------|----------|
| Suricata YAML syntax errors | Use heredoc with `'EOF'` to prevent Bash variable expansion; add `%YAML 1.1` and `---` headers. |
| Kibana 8.x rejects `usageCollection.enabled` | Use `telemetry.enabled: false` (correct property). |
| Filebeat not found | Add Elastic repository **before** `apt-get install filebeat`. |
| Docker permission denied after `usermod` | Health script uses `sudo docker …`; new session needed for non‑root docker. |
| Cowrie cannot write logs | Create directories with `mkdir -p` and apply `chmod -R 777` to the mounted volume. |
| Cloud‑init fails on `fuser` (missing psmisc) | Replace `fuser` loop with a simple `sleep 5` (the lock is rarely held). |
| No alerts in dashboard | Dashboard query filters `exists alert` or `fields.event_type` in (cowrie, dionaea, system). |

> **Resilience by design** – All scripts log to `/var/log/asop-debug.log`. A failed run can be debugged in minutes.

---

## 4. Result – A Fully Automated, Low‑Cost Security Lab

After a clean `terraform apply` (**≈ 8 minutes**), the environment is **ready to use**:

- ✅ **SIEM node** – Elasticsearch, Logstash, Kibana, `asop-dashboard` & `asop-health`
- ✅ **Sensor node** – Suricata, Cowrie, Dionaea, Filebeat, `asop-sensor-health`
- ✅ **Kali node** – ready for manual attacks

### Live test (from sensor):

```bash
ping 8.8.8.8
ssh -p 2222 root@localhost   # any password works
On the SIEM:
bash
asop-dashboard --limit 10
Output (real example):

text
[1] 2026-05-31 05:23:12
   10.0.20.105 → 8.8.8.8
   ⚠️ [IDS] 🟡 MEDIUM | ICMP Ping Detected
Kibana is accessible via http://<siem_public_ip>:5601 (your IP must be whitelisted in the security group).

The entire infrastructure can be destroyed with terraform destroy, leaving no ongoing costs.

5. Technology Stack (Summary)
Category	Tools
Cloud & IaC	AWS (VPC, EC2, IAM, Security Groups), Terraform (~5.0)
Operating System	Ubuntu 22.04 (SIEM & sensor), Kali Linux (attacker)
Detection	Suricata (IDS), Cowrie (SSH honeypot), Dionaea (FTP/SMB/MSSQL)
Log shipping	Filebeat (to Logstash)
Pipeline	Logstash (parsing & enrichment) → Elasticsearch (storage) → Kibana (UI)
CLI assistant	Python 3 + requests – custom alert filter
Containers	Docker + Docker Compose (honeypots)
6. My Role – Senior Infrastructure Engineer
I designed the network architecture, IAM roles, Security Group segmentation and wrote the idempotent user‑data scripts that bring every node to a fully operational state without any manual post‑deployment steps.

I focused on:

Observability – extensive logging, health checks, CLI dashboard

Cost control – no NAT gateway, t3.micro for non‑critical nodes, terraform destroy command documented

Resilience – structured logging to /var/log/asop-debug.log and non‑fatal error handling

The result is a production‑grade automation blueprint that can be reused for any security telemetry pipeline.

7. How to Reproduce the Project
Clone the repository and place your AWS SSH key in ~/.ssh/.

Create terraform/dev.tfvars with your IP, key name and AWS region.

Run:

bash
cd terraform
terraform init
terraform apply -var-file="dev.tfvars" -auto-approve
Wait ≈ 8 minutes – the scripts will automatically configure everything.

Use the outputs (IPs, Kibana URL) to connect and test.

Destroy when done:

bash
terraform destroy -var-file="dev.tfvars" -auto-approve
All scripts, Terraform files and this documentation are part of the repository.

8. Future Work / Scaling
To demonstrate vision and scalability, the following improvements are planned:

Multi‑sensor deployment – allow multiple sensor nodes to send logs to the same SIEM (using a Load Balancer or multiple Logstash instances).

Alerting via Webhooks – integrate with Slack/PagerDuty using Elasticsearch Watchers or Logstash outputs.

Anomaly detection – leverage Elasticsearch’s machine learning features to detect unusual patterns (e.g., new attack vectors).

Terraform modules – refactor into reusable modules for even cleaner code.

Immutable golden images – use Packer to pre‑bake AMIs instead of running user‑data scripts on every boot.

9. Conclusion
The ASOP project proves that a professional, fully automated security observability platform can be built with open‑source tools and AWS free‑tier eligible resources. It demonstrates:

Infrastructure as Code

Network segmentation & least privilege

Telemetry pipeline engineering

Smart alert filtering (Time to Insight)

Repository structure (simplified):

text
AWS-SOC-TELEMETRY.INFRA/
├── terraform/          # VPC, EC2, SGs, IAM, outputs
├── scripts/            # install_siem.sh, install_sensor.sh, soc_cli_dashboard.py
├── aws-network-topology.jpg
├── data-flow-diagram.png
└── README.md           # this file
Questions or feedback? I treat this project as a living infrastructure – improvements are always welcome.
