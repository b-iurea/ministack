# MiniStack Real Infrastructure — Full Roadmap

## Legend
🟢 **Already Real** | 🟡 **Logic/In-Memory** | 🔴 **Mock Only** | ⬜ **Not Implemented Yet**

---

## 🔐 IAM / STS — Real Identity & Access Management

IAM è il servizio più impattante da rendere reale perché tutto il resto ci si appoggia.

| Feature | Come | Dettaglio |
|---|---|---|
| **Users** | File JSON `/data/iam/users.json` + bcrypt password hash | `CreateUser`, `GetUser`, `DeleteUser`, `ListUsers` |
| **Access Keys** | Generate real AKIA-style keys, store hashed secret | `CreateAccessKey`, `DeleteAccessKey`, `ListAccessKeys` |
| **Roles** | File JSON + trust policy | `CreateRole`, `AssumeRole` (STS), `GetRole` |
| **Policies** | JSON policy document, evaluated at request time | Inline + managed policies, `Allow`/`Deny` evaluation |
| **Policy Simulation** | `SimulatePrincipalPolicy` — valuta se un'azione è permessa | Basato su policy engine reale (no chiamate API reali) |
| **Instance Profiles** | Associano un ruolo a un'istanza EC2 | L'istanza può assumere il ruolo via IMDS |
| **IMDS** | Endpoint `169.254.169.254` su ogni container EC2 | `http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>` |
| **SigV4 Validation** | Validazione reale della firma sulle richieste | Oggi è lax (qualsiasi credenziale passa) |
| **Account Aliases** | `CreateAccountAlias`, `ListAccountAliases` | Multi-account IAM |

### IAM Policy Engine (come funzionerebbe)

```
1. Request arriva → estrai AccessKey dal header Authorization
2. Cerca AccessKey nel DB → trova User/Role
3. Carica tutte le policy (inline + attached + group)
4. Valuta: match Action + Resource + Condition
5. Explicit DENY vince su Allow
6. Se nessun Allow → DENY implicito
```

**Costo implementazione**: ~800-1000 linee Python. Il grosso è il policy evaluation engine.

---

## 🌐 Networking

| Service | Oggi | Realizzazione | Sforzo |
|---|---|---|---|
| **VPC** | 🟢 Docker bridge | — | Fatto |
| **Subnet** | 🟡 In-memory | Assegna IP range nel Docker network | Basso |
| **Security Group** | 🟢 iptables | — | Fatto |
| **Internet Gateway** | 🟡 In-memory | `iptables -t nat -A POSTROUTING` sul container per abilitare internet | Basso |
| **NAT Gateway** | 🔴 Mock | Container con `iptables MASQUERADE` + routing | Medio |
| **Route Table** | 🔴 Mock | `ip route add` nel container EC2 | Basso |
| **Network ACL** | 🔴 Mock | iptables a livello di subnet (regole sul bridge Docker) | Medio |
| **VPC Peering** | ⬜ Non esiste | Collega due Docker bridge con una rotta | Medio |
| **Transit Gateway** | ⬜ Non esiste | Container centrale con routing table, tutte le VPC collegate | Alto |
| **VPC Endpoint** | ⬜ Non esiste | Proxy HTTP su un container dedicato (es. S3 endpoint) | Medio |
| **Elastic IP** | 🟡 In-memory | IP statico sul container (ipvlan/macvlan) | Basso |
| **PrivateLink** | ⬜ Non esiste | Endpoint service + NLB interno | Alto |

---

## 💻 Compute

| Service | Oggi | Realizzazione | Sforzo |
|---|---|---|---|
| **EC2** | 🟢 Alpine containers | — | Fatto |
| **Lambda** | 🟢 Docker warm pool | — | Fatto |
| **ECS** | 🟢 Docker task containers | — | Fatto |
| **EKS** | 🟢 k3s containers | — | Fatto |
| **Auto Scaling** | 🔴 Mock | `docker stats` per CPU, scaling basato su threshold | Alto |
| **ELB / ALB** | 🔴 Mock | **Traefik** container: reverse proxy, listener rules, target groups, health check, TLS termination | Medio |
| **Batch** | 🔴 Mock | Container che esegue un comando e termina (`docker run --rm`) | Basso |
| **Launch Templates** | 🟡 In-memory | — | Fatto |

---

## 🗄️ Storage & Database

| Service | Oggi | Realizzazione | Sforzo |
|---|---|---|---|
| **S3** | 🟡 File persist | **MinIO** container: vera S3-compatible API, versioning, encryption | Medio |
| **EBS Volumes** | 🟡 In-memory | Directory bind-mount sul container EC2: `/dev/xvda` → `/data/ebs/vol-xxx/` | Basso |
| **EFS** | 🔴 Mock | NFS server container (nfs-ganesha) | Alto |
| **RDS** | 🟢 PostgreSQL/MySQL/MariaDB | — | Fatto |
| **DynamoDB** | 🟡 In-memory | SQLite backend (persistente, con indici) o FoundationDB container | Alto |
| **ElastiCache** | 🟢 Redis/Memcached | — | Fatto |
| **Athena** | 🟢 DuckDB | — | Fatto |
| **Backup** | 🔴 Mock | Tarball dei volumi/data directory su S3 | Medio |
| **S3 Tables** | 🔴 Mock | Apache Iceberg su MinIO | Alto |

---

## 📨 Messaging & Events

| Service | Oggi | Realizzazione | Sforzo |
|---|---|---|---|
| **SQS** | 🟡 In-memory | Redis Lists: `LPUSH`/`RPOP`, visibility timeout con TTL, DLQ | Medio |
| **SNS** | 🟡 In-memory | Redis PubSub: `PUBLISH`/`SUBSCRIBE`, fan-out, filtri | Medio |
| **EventBridge** | 🟡 In-memory | Event bus su Redis Streams. Rules → pattern matching. Targets → HTTP/Docker/Redis | Alto |
| **Step Functions** | 🟡 In-memory | Workflow engine (ASL parser + executor), integrazione con Lambda/ECS | Alto |
| **Kinesis** | 🔴 Mock | Kafka container (KRaft mode, no ZooKeeper). Shard = partition | Alto |
| **Firehose** | 🔴 Mock | Buffer in memoria → flush a S3/Lambda/Elasticsearch su soglia | Medio |
| **MQ (ActiveMQ)** | ⬜ Non esiste | Container ActiveMQ/RabbitMQ | Basso |
| **MSK (Kafka)** | ⬜ Non esiste | Container Kafka KRaft | Medio |

---

## 🔒 Security & Crypto

| Service | Oggi | Realizzazione | Sforzo |
|---|---|---|---|
| **KMS** | 🔴 Mock | AES-256-GCM con chiavi generate. `Encrypt`/`Decrypt`/`GenerateDataKey` reali. HSM simulato in memoria | Alto |
| **Secrets Manager** | 🔴 Mock | File JSON con AES encryption. `GetSecretValue` decritta, `PutSecretValue` cripta | Medio |
| **ACM** | 🔴 Mock | OpenSSL per generare certificati self-signed o CSR | Basso |
| **WAF** | 🔴 Mock | ModSecurity/Nginx container come proxy WAF davanti a ALB/CloudFront | Alto |
| **CloudTrail** | 🟡 In-memory logging | File JSON su disco: `/data/cloudtrail/<account>/<region>/<year>/<month>/<day>.json` | Basso |
| **Inspector** | 🔴 Mock | Trivy/Clair container scan sulle immagini | Alto |
| **GuardDuty** | ⬜ Non esiste | Analisi log CloudTrail + VPC Flow Logs | Molto Alto |
| **Shield** | ⬜ Non esiste | Rate limiting su iptables/WAF | Basso |

---

## 📊 Monitoring & Logging

| Service | Oggi | Realizzazione | Sforzo |
|---|---|---|---|
| **CloudWatch Metrics** | 🔴 Mock | Prometheus + `cw_metric → prometheus_metric`. Dashboard = Grafana | Alto |
| **CloudWatch Logs** | 🔴 Mock | Log groups = directory, log streams = file. `tail -f`, `grep`, `aws logs tail` funzionante | Basso |
| **CloudWatch Alarms** | 🔴 Mock | Valuta metriche Prometheus, trigger SNS/Lambda su soglia | Medio |

---

## 🌍 DNS & CDN

| Service | Oggi | Realizzazione | Sforzo |
|---|---|---|---|
| **Route 53** | 🔴 Mock | **CoreDNS** container. Zone = file di zona. `ChangeResourceRecordSets` scrive nel file e ricarica | Medio |
| **CloudFront** | 🔴 Mock | Nginx cache container. Distribution = vhost. Origin = URL backend | Alto |
| **Certificate Manager (ACM)** | 🔴 Mock | Vedi Security → ACM | Basso |

---

## 🔧 Developer Tools

| Service | Oggi | Realizzazione | Sforzo |
|---|---|---|---|
| **CloudFormation** | 🟡 In-memory | Provisioning engine reale: `AWS::EC2::Instance` → chiama `run_instances`, `AWS::S3::Bucket` → MinIO bucket, ecc. | Molto Alto |
| **ECR** | 🔴 Mock | Docker Registry v2 container. `docker push localhost:4566/repo:tag` | Basso |
| **CodeBuild** | 🔴 Mock | Container effimero che esegue `buildspec.yml`, log a CloudWatch Logs | Medio |
| **SSM Parameter Store** | 🔴 Mock | File JSON: `/data/ssm/parameters.json`. `GetParameter`/`PutParameter` reali | Basso |
| **AppConfig** | 🔴 Mock | File JSON con feature flags. Valutazione real-time | Basso |
| **X-Ray** | ⬜ Non esiste | OpenTelemetry collector container | Alto |

---

## 👤 Identity & Federation

| Service | Oggi | Realizzazione | Sforzo |
|---|---|---|---|
| **Cognito User Pools** | 🔴 Mock | **Keycloak** container. User pool = realm. Client = app. JWT reale | Alto |
| **Cognito Identity Pools** | 🔴 Mock | Scambia token Cognito/Google/FB per credenziali AWS temporanee | Alto |
| **STS** | 🟡 In-memory | `AssumeRole` reale: genera credenziali temporanee firmate, validate dal policy engine | Medio |
| **Organizations** | 🔴 Mock | Gerarchia di account con policy SCP. SCP = filtro sulle azioni permesse | Medio |
| **SSO** | ⬜ Non esiste | Integrazione Keycloak SAML/OIDC | Alto |

---

## 🌐 API & Integration

| Service | Oggi | Realizzazione | Sforzo |
|---|---|---|---|
| **API Gateway** | 🟡 In-memory | HTTP proxy (Nginx/Envoy) con path-based routing a Lambda/ECS/HTTP, API keys, throttling | Alto |
| **API Gateway v2 (WebSocket)** | 🟡 In-memory | WebSocket proxy con `$connect`/`$disconnect`/`$default` routes | Alto |
| **AppSync** | 🔴 Mock | GraphQL gateway con resolver a DynamoDB/Lambda. Hasura container? | Alto |

---

## 📦 Containers & Registry

| Service | Oggi | Realizzazione | Sforzo |
|---|---|---|---|
| **ECR** | 🔴 Mock | Docker Registry v2 container. `GetAuthorizationToken`, `CreateRepository` | Basso |
| **ECS** | 🟢 Docker containers | — | Fatto |
| **EKS** | 🟢 k3s cluster | — | Fatto |

---

## 🤖 IoT & Edge

| Service | Oggi | Realizzazione | Sforzo |
|---|---|---|---|
| **IoT Core** | 🔴 Mock | **Mosquitto MQTT** container. `CreateThing`, `CreateCertificate`. MQTT su WebSocket | Medio |
| **IoT Data** | 🔴 Mock | Publish/Subscribe via MQTT | Basso |
| **Greengrass** | ⬜ Non esiste | Container con simulatore di dispositivo edge | Molto Alto |

---

## 📈 Analytics

| Service | Oggi | Realizzazione | Sforzo |
|---|---|---|---|
| **Athena** | 🟢 DuckDB | — | Fatto |
| **Glue** | 🔴 Mock | Hive Metastore container + Spark job container per ETL | Alto |
| **EMR** | 🔴 Mock | Spark cluster container (master + workers) | Alto |
| **OpenSearch** | 🔴 Mock | Elasticsearch container (single-node) | Basso |
| **QuickSight** | ⬜ Non esiste | Apache Superset container | Alto |

---

## 🎯 Priority Roadmap (next 4 steps)

### 🔴 CRITICAL — IAM reale (Step 3)
IAM è il prerequisito per tutto. Senza IAM reale, policy evaluation e SigV4 vero, gli altri servizi non possono essere davvero isolati.

### 🟠 HIGH — S3 → MinIO (Step 4)  
S3 è il servizio più usato in assoluto. Avere storage reale sblocca backup, static hosting, versioning, lifecycle policies.

### 🟡 MEDIUM — Networking completo (Step 5)
Internet Gateway, NAT Gateway, VPC Peering, Route Tables. Completano l'isolamento di rete.

### 🟢 NICE — ALB/ELB → Traefik (Step 6, già in Tier 1)
Primo vero servizio di bilanciamento del carico. Sblocca architetture multi-tier.
