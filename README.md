# CloudTrail Sentinel

A detection pipeline for AWS CloudTrail logs. Ingests control-plane audit
events, normalises them into a common schema, evaluates them against
version-controlled detection rules mapped to MITRE ATT&CK, and surfaces
alerts through a local dashboard.

Built to explore cloud detection engineering: how attacks against cloud
identity and infrastructure become visible in logs, and how detection
logic is written, tested, and validated.

**Status:** In development. See [Roadmap](#roadmap) for current progress.

---

## Contents

- [Problem](#problem)
- [Architecture](#architecture)
- [Detections](#detections)
- [Quick Start](#quick-start)
- [AWS Sandbox Deployment](#aws-sandbox-deployment)
- [Validation](#validation)
- [Project Structure](#project-structure)
- [Roadmap](#roadmap)
- [Glossary](#glossary)
- [Notes](#notes)

---

## Problem

Cloud compromise rarely looks like malware on a server. It looks like a
valid API call from a valid credential: an access key created, a policy
attached, a logging trail switched off. AWS records all of it in
CloudTrail, but raw CloudTrail is high-volume JSON with no opinion about
what matters.

This project sits between the raw log and the analyst. It answers a
narrow question well: given a stream of CloudTrail events, which ones
represent attacker behaviour, and why?

Scope is deliberately limited to the AWS control plane. Network-layer
telemetry (VPC Flow Logs) and multi-cloud support are out of scope for
this iteration.

---

## Architecture

```
    +---------------------+
    |   AWS Sandbox       |   Terraform-provisioned
    |   Account           |   CloudTrail --> S3
    +----------+----------+
               |
               |   Optional. Sample logs are bundled
               |   for offline use.
               v
    +---------------------+
    |   Ingestion         |   boto3 / local reader
    |                     |   gzip --> JSON events
    +----------+----------+
               |
               v
    +---------------------+
    |   Normalisation     |   CloudTrail --> ECS-style schema
    |                     |   actor, source_ip, action,
    |                     |   resource, outcome
    +----------+----------+
               |
               v
    +---------------------+
    |   Detection Engine  |   YAML rules
    |                     |   MITRE ATT&CK mapped
    +----------+----------+
               |
               v
    +---------------------+       +---------------------+
    |   DuckDB            | ----> |   Dashboard         |
    |   events + alerts   |       |   Streamlit         |
    +---------------------+       +---------------------+
```

**Design decisions**

| Decision | Rationale |
| --- | --- |
| DuckDB over Elasticsearch | Embedded and zero-config. Keeps the repository runnable in one command rather than requiring a search cluster. |
| YAML rules over Python | Detection logic stays readable and editable without touching application code. Follows detection-as-code practice. |
| Offline-first | Bundled sample logs mean the project can be run and reviewed without an AWS account or credentials. |
| Terraform for the sandbox | Infrastructure is reproducible and, more importantly, destroyable. |

---

## Detections

Each rule is a YAML file under `rules/`, mapped to a MITRE ATT&CK
technique and covered by unit tests.

| Rule | ATT&CK | Severity | Trigger |
| --- | --- | --- | --- |
| Root account usage | T1078.004 | High | Any API call where identity type is Root |
| Console login without MFA | T1078.004 | Medium | ConsoleLogin with MFAUsed = No |
| CloudTrail disabled or deleted | T1562.008 | Critical | StopLogging or DeleteTrail |
| GuardDuty detector disabled | T1562.001 | Critical | DeleteDetector or UpdateDetector to disabled |
| Admin policy attached to user | T1098 | High | AttachUserPolicy granting AdministratorAccess |
| S3 bucket exposed publicly | T1530 | High | PutBucketPolicy or PutBucketAcl granting public access |
| Console brute force | T1110 | Medium | 5 or more failed ConsoleLogin from one source IP within 10 minutes |
| Activity in unapproved region | T1496 | Medium | RunInstances outside the configured region allowlist |

Full rule documentation, including tuning notes and known false positive
sources, is in [`docs/detections.md`](docs/detections.md).

Most rules are stateless single-event matches. The brute force rule is
stateful and requires windowed correlation across events; its
implementation and the tradeoffs in window sizing are documented
separately.

---

## Quick Start

No AWS account required. Runs against bundled sample logs.

```
git clone https://github.com/danielkosatka/cloudtrail-sentinel.git
cd cloudtrail-sentinel
docker compose up
```

Dashboard available at `http://localhost:8501`.

To run without Docker:

```
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m src.pipeline --input sample_logs/
streamlit run src/dashboard/app.py
```

Run the test suite:

```
pytest
```

---

## AWS Sandbox Deployment

<!-- FILL: complete this section once Terraform is written and tested -->

To run against live CloudTrail data, the `terraform/` directory
provisions an isolated sandbox: a CloudTrail trail, a destination S3
bucket with encryption and public access blocked, and a read-only IAM
role for the ingestion process.

```
cd terraform
terraform init
terraform plan
terraform apply
```

To tear down:

```
terraform destroy
```

**Cost warning.** CloudTrail management events and S3 storage at this
volume fall within or near the AWS free tier, but this is not guaranteed
and pricing changes. Set an AWS Budget alert before deploying, use a
dedicated account you do not care about, and run `terraform destroy` when
finished. Do not deploy this into an account containing anything of
value.

---

## Validation

Detection rules are only meaningful if they fire on real behaviour.
Each rule is validated in two ways:

**Unit tests.** Every rule has at least one event that must match and one
similar event that must not. These run on every push via GitHub Actions.

**Attack simulation.** Techniques are executed against the sandbox
account and the resulting alerts captured end to end. Simulation scripts
are in `simulate/`.

<!-- FILL: replace with real screenshots once Phase 4 is complete.
     Suggested images:
       docs/images/attack-to-alert.png   (simulated action -> dashboard alert)
       docs/images/dashboard.png         (overview view)
       docs/images/alert-detail.png      (single alert expanded)
       docs/images/ci-passing.png        (test suite green)
     Redact account IDs, ARNs and source IPs before committing. -->

---

## Project Structure

```
cloudtrail-sentinel/
|
+-- src/
|   +-- ingest/          Log collection from S3 or local disk
|   +-- normalise/       CloudTrail to common schema
|   +-- detect/          Rule loading and evaluation engine
|   +-- dashboard/       Streamlit interface
|
+-- rules/               YAML detection rules
+-- tests/               Unit tests, one positive and one negative per rule
+-- sample_logs/         Sanitised CloudTrail events for offline use
+-- simulate/            Attack simulation scripts
+-- terraform/           Sandbox infrastructure
+-- docs/
|   +-- architecture.md
|   +-- detections.md
|   +-- setup.md
|   +-- images/
|
+-- docker-compose.yml
+-- requirements.txt
+-- README.md
```

---

## Roadmap

**Phase 1 - Ingestion and normalisation**
- [x] Read CloudTrail JSON from local disk
- [x] Handle gzip-compressed S3 objects
- [x] Normalise events to common schema

**Phase 2 - Detection engine**
- [ ] YAML rule loader and schema
- [ ] Stateless rule evaluation
- [ ] First four detection rules
- [ ] Unit tests and CI pipeline

**Phase 3 - Storage and interface**
- [ ] DuckDB persistence for events and alerts
- [ ] Remaining four rules, including stateful brute force detection
- [ ] Streamlit dashboard with alert detail and ATT&CK coverage view

**Phase 4 - Live validation**
- [ ] Terraform sandbox environment
- [ ] Attack simulation scripts
- [ ] End-to-end validation evidence

**Beyond current scope**
- VPC Flow Log ingestion for network-layer detection
- Alert deduplication and correlation into incidents
- Event-driven ingestion via SQS rather than batch polling
- Notification output to Slack or email
- Sigma rule format compatibility

---

## Glossary

Terminology and acronyms used throughout this repository, grouped by
area. Expand a section to read it.

<details>
<summary><strong>AWS and cloud infrastructure</strong></summary>

<br>

| Term | Meaning |
| --- | --- |
| **AWS** | Amazon Web Services. Amazon's cloud computing platform. |
| **Region** | A geographic cluster of AWS data centres, for example `eu-west-2` (London). Resources are created in a specific region. Activity in a region an organisation does not use is a common indicator of compromise. |
| **CloudTrail** | AWS's audit log service. Records every API call made in an account: the identity, timestamp, source address, parameters and outcome. The primary data source for this project. |
| **Control plane** | The layer that manages infrastructure, for example creating a server or changing a permission. CloudTrail records control-plane activity. |
| **Data plane** | The layer that uses infrastructure, for example network traffic between servers. Recorded by VPC Flow Logs rather than CloudTrail. |
| **IAM** | Identity and Access Management. AWS's system of users, roles and permissions. The majority of cloud attacks are ultimately attacks on IAM. |
| **Root account** | The original, unrestricted login for an AWS account. Best practice is to secure it and never use it, which makes any root activity inherently suspicious. |
| **Access key** | A credential pair used for programmatic access by scripts and applications, consisting of an access key ID and a secret key. Leaked access keys are among the most common causes of cloud compromise. |
| **MFA** | Multi-Factor Authentication. Requiring a second proof of identity beyond a password. |
| **S3** | Simple Storage Service. AWS object storage. Containers are called buckets. Misconfigured buckets are a frequent cause of public data exposure. |
| **ACL** | Access Control List. A permission mechanism for S3 objects and buckets, modified by the `PutBucketAcl` API call. |
| **EC2** | Elastic Compute Cloud. AWS virtual servers. Launched via the `RunInstances` API call. |
| **VPC** | Virtual Private Cloud. An isolated private network within AWS. |
| **VPC Flow Logs** | Records of network connections in and out of a VPC. Out of scope for this project. |
| **GuardDuty** | AWS's managed threat detection service, using machine learning and threat intelligence. Complementary to, not replaced by, this project. |
| **ARN** | Amazon Resource Name. A unique identifier for an AWS resource. Often contains the account ID, so redacted in documentation. |
| **Sandbox account** | An isolated, disposable AWS account used solely for testing, containing nothing of value. |
| **Free tier** | AWS's allowance of free usage for new accounts. Coverage varies by service and changes over time. |

</details>

<details>
<summary><strong>Security concepts</strong></summary>

<br>

| Term | Meaning |
| --- | --- |
| **SIEM** | Security Information and Event Management. Software that centralises logs from across an organisation, correlates them and raises alerts. Commercial examples include Splunk, Microsoft Sentinel and Elastic Security. |
| **Telemetry** | The signals a system emits about its own operation: logs, metrics and events. |
| **Detection engineering** | The discipline of designing, writing, testing and maintaining the logic that converts raw telemetry into actionable alerts. |
| **Detection-as-code** | Managing detection rules with software engineering practice: version control, peer review, automated testing and CI deployment, rather than manual configuration in a console. |
| **MITRE ATT&CK** | A public knowledge base of observed adversary behaviour, maintained by the MITRE Corporation. Stands for Adversarial Tactics, Techniques and Common Knowledge. Provides the shared vocabulary used to classify the rules in this project. |
| **Tactic** | In ATT&CK, an attacker's objective, for example Persistence. Identified as `TA` followed by four digits. |
| **Technique** | In ATT&CK, the method used to achieve a tactic, for example Impair Defenses. Identified as `T` followed by four digits. Sub-techniques add a suffix, for example `T1562.008`. |
| **CIS Benchmarks** | Consensus security hardening standards published by the Center for Internet Security, widely used as an audit baseline. |
| **Privilege escalation** | Moving from limited access to greater access. Attaching an administrative policy to a compromised user is a common cloud example. |
| **Impair Defenses** | The ATT&CK technique covering deliberate disabling of security controls, such as stopping audit logging. |
| **Brute force** | Repeatedly attempting credentials until one succeeds. Observable as a concentration of authentication failures from a single source. |
| **Cryptojacking** | Unauthorised use of compromised compute resources to mine cryptocurrency. A frequent outcome of leaked cloud credentials. |
| **Adversary emulation** | Deliberately performing known attacker techniques against systems you own, in order to verify that detection logic responds as intended. |
| **Purple team** | Collaborative work combining offensive testing and defensive detection, as opposed to running them as separate exercises. |
| **Threat intelligence** | Data on known malicious infrastructure and actors, such as indicator feeds of hostile IP addresses and domains. |
| **True positive** | An alert that correctly identifies genuine malicious activity. |
| **False positive** | An alert raised on benign activity. High false positive rates cause alert fatigue and lead to real detections being ignored. |
| **Tuning** | Adjusting a rule to reduce false positives without losing genuine detections. Environment-specific and ongoing. |
| **Alert deduplication** | Collapsing repeated alerts describing the same underlying event into a single incident. |
| **SOC** | Security Operations Centre. The team responsible for monitoring alerts and responding to incidents. |

</details>

<details>
<summary><strong>Data and pipeline</strong></summary>

<br>

| Term | Meaning |
| --- | --- |
| **Normalisation** | Converting logs from differing sources into one consistent field structure, so that detection logic can be written once rather than per source format. |
| **Schema** | The defined structure of data: which fields exist and what type each holds. |
| **ECS** | Elastic Common Schema. An open specification for naming normalised security event fields, published by Elastic. |
| **JSON** | JavaScript Object Notation. A structured text format of nested key-value pairs. The format CloudTrail delivers events in. |
| **YAML** | A human-readable configuration format using indentation rather than brackets. Used here for detection rules so they remain editable without modifying application code. |
| **gzip** | A compression format. CloudTrail delivers log files to S3 gzip-compressed. |
| **Stateless rule** | A rule evaluated against a single event in isolation. |
| **Stateful rule** | A rule requiring knowledge of previous events, for example counting failures across a time period. |
| **Windowed correlation** | Grouping events within a defined time window to identify patterns. The window length is a tradeoff between detecting slow attacks and generating noise. |
| **Batch polling** | Periodically checking for new data. Simpler than event-driven ingestion but introduces latency bounded by the polling interval. |
| **Event-driven ingestion** | Processing data as it arrives, typically via a message queue. Lower latency, higher complexity. |

</details>

<details>
<summary><strong>Tooling and development</strong></summary>

<br>

| Term | Meaning |
| --- | --- |
| **boto3** | The official AWS SDK for Python, used to interact with AWS services programmatically. |
| **SDK** | Software Development Kit. A library providing programmatic access to a service. |
| **API** | Application Programming Interface. The defined set of operations a service exposes to other software. Every action in AWS is an API call, which is why CloudTrail can record them all. |
| **DuckDB** | An embedded analytical database. Runs inside the application as a single file rather than as a separate server, keeping deployment simple. |
| **Elasticsearch / OpenSearch** | Search and analytics engines commonly underpinning commercial SIEM platforms. Deliberately not used here, to keep the repository runnable without additional infrastructure. |
| **Streamlit** | A Python library for building web interfaces directly from scripts, without separate frontend code. |
| **IaC** | Infrastructure as Code. Defining cloud infrastructure in version-controlled configuration files rather than through manual console operations. |
| **Terraform** | The most widely used IaC tool. Provisions infrastructure with `terraform apply` and removes it with `terraform destroy`. |
| **Container** | A packaged application bundled with its dependencies, so that it runs identically across environments. |
| **Docker Compose** | A tool for defining and starting multiple containers from a single configuration file. |
| **CI** | Continuous Integration. Automated building and testing of code on every change. Implemented here with GitHub Actions. |
| **GitHub Actions** | GitHub's built-in automation service, used to run the test suite on every push. |
| **pytest** | The standard Python testing framework. |
| **Unit test** | An automated check that one component behaves as expected in isolation. |
| **Repository** | A project directory tracked by version control, including its full history of changes. |
| **Commit** | A recorded snapshot of changes, accompanied by a descriptive message. |
| **Pull request** | A proposed set of changes submitted for review before being merged. |
| **Virtual environment** | An isolated Python installation for a single project, preventing dependency conflicts between projects. |
| **CLI** | Command Line Interface. Interaction with software through typed commands rather than a graphical interface. Standard for cloud and infrastructure tooling. |

</details>

---

## Notes

**Known limitations.** Ingestion is batch-based rather than
event-driven, so detection latency is bounded by the polling interval.
False positive rates are untested against production-scale data; the
region allowlist and brute force threshold in particular would require
per-organisation tuning before real use. This is a learning project, not
a production security control.

**Relationship to AWS-native tooling.** This does not replace GuardDuty.
GuardDuty applies machine learning and threat intelligence to a broader
set of sources; this project implements deterministic, transparent,
version-controlled rules. Real environments benefit from both.

**Data handling.** All bundled sample logs are synthetic or sanitised.
Account identifiers, ARNs and source addresses in documentation and
screenshots are redacted or replaced with placeholder values.

---

## Author

Daniel Kosatka - Cybersecurity student, University of Lancashire

<!-- FILL: add LinkedIn if you want recruiters to find you from here -->

## Licence

MIT
