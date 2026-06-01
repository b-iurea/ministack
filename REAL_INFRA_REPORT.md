# MiniStack Real Infrastructure — Status Report

## Branches

| Repo | Branch | Status |
|---|---|---|
| ministack | `feat/real-infra-step2-sg-iptables` | **Active — implementing** |
| ministack | `feat/real-infra-step1-vpc` | Merged into step2 |
| ministack-dashboard | `feat/resource-detail-modal` | Active |
| ministack | `feat/region-isolation` | PR aperta su fork |
| ministack | `feat/real-containers` | Merged into step1 |

---

## Completed Features

### ✅ Region Isolation (`feat/region-isolation`)
- `AccountRegionScopedDict` in `responses.py` — scopes by `(account_id, region, key)`
- 53 regional services switched, 6 global services kept on `AccountScopedDict`
- Region extracted from SigV4 Authorization header
- **Verified:** EC2 instances in eu-south-1 invisible from us-east-1

### ✅ EC2 Instances as Docker Containers
- `run_instances` spawns real Alpine Linux containers
- Container name: `ministack-ec2-{instance_id}-{NameTag}`
- `terminate_instances` stops and removes containers
- Windows AMIs skipped (AMI starts with `ami-win`)
- **Verified:** Create, describe, terminate lifecycle

### ✅ EKS Multi-Node Cluster
- `create_cluster` spawns k3s master (control-plane, hidden from EC2)
- `create_nodegroup` spawns `desiredSize` × k3s agent containers
- Agents join cluster via master token → visible in `kubectl get nodes`
- `delete_nodegroup` stops and removes agent containers
- **Verified:** 3-node cluster (1 master + 2 workers)

### ✅ EKS Workers as EC2 Instances
- Each k3s agent also registered as EC2 instance
- Tags: `Name`, `eks:cluster-name`, `eks:nodegroup-name`, `aws:autoscaling:groupName`
- Workers visible via `describe_instances` with `ami-eks-worker`
- Control plane hidden from EC2 (like real AWS)
- `delete_nodegroup` removes EC2 instance records
- **Verified:** Workers show in EC2 console with correct tags

### ✅ VPC as Docker Bridge Network
- `create_vpc` creates Docker bridge network: `vpc-vpc-{id}` with VPC CIDR
- `delete_vpc` removes Docker network
- EC2 instances attach to their VPC's Docker network
- **Cross-VPC isolation:** ping fails between different VPCs (100% loss)
- Private IP synced between API and Docker container
- **Verified:** 2 VPCs, isolated networks, correct CIDR allocation

### ✅ Dashboard Features
- Region/account switch via `?region=` query param (pure sync redirect)
- Sub-resource navigation: `/services/ec2/vpcs?region=eu-west-3`
- Resource detail drawer (bottom sheet, drag-to-resize)
- Resource filtering by ID, name, tag
- Tags rendered inline as `KEY: VALUE`
- Resource names from `Name` tag
- Search sub-services (e.g. "vpc" → "VPCs · EC2")
- Global services pinned to us-east-1
- EKS cluster and node-group listers

---

## Real vs Mock Services

| Service | Infrastructure | Type |
|---|---|---|
| EKS | k3s cluster (master + agents) | 🟢 Real |
| EC2 | Alpine Linux containers | 🟢 Real |
| VPC | Docker bridge network | 🟢 Real |
| Lambda | Docker warm pool | 🟢 Real |
| RDS | PostgreSQL/MySQL/MariaDB containers | 🟢 Real |
| ElastiCache | Redis/Memcached containers | 🟢 Real |
| ECS | Docker task containers | 🟢 Real |
| Athena | DuckDB (full image) | 🟢 Real |
| Transfer | SSH/SFTP server (asyncssh) | 🟢 Real |
| DynamoDB | In-memory engine | 🟡 Logic |
| SQS | In-memory queues | 🟡 Logic |
| SNS | In-memory topics | 🟡 Logic |
| Step Functions | In-memory state machine | 🟡 Logic |
| S3 | In-memory (optional file persist) | 🟡 Logic |
| IAM, STS, Route53, CloudFront, ... | API mock only | 🔴 Mock |

---

## Next Steps — Real Infrastructure Roadmap

### ✅ Security Group → iptables (`feat/real-infra-step2-sg-iptables`)
- iptables rules applied inside EC2 containers via `docker exec`
- `_iptables_build_commands` translates SG IpPermissions → iptables ACCEPT/DROP
- Custom chains: `MINISTACK_IN` (ingress), `MINISTACK_OUT` (egress)
- Stateful: `ESTABLISHED,RELATED` conntrack for response traffic
- Authorize / revoke propagate changes to all running instances (background thread)
- Loopback allowed; default DROP inbound; default ACCEPT outbound
- IPv6 support via `ip6tables`
- **Verified:** unit tests for proto mapping, port matching, multi-SG aggregation

### Tier 1 — High Impact
1. ~~**Security Group → iptables**~~ ✅ DONE

2. **ALB/ELB → Traefik**
   - Container Traefik for reverse proxy
   - Listener rules → HTTP routing
   - Target groups → EKS/EC2 backends
   - Health checks, TLS termination

3. **API Gateway → HTTP Proxy**
   - Path-based routing to Lambda/ECS/HTTP
   - WebSocket support

4. **S3 → MinIO**
   - Container MinIO (S3-compatible API)
   - Real upload/download, versioning

5. **CloudWatch Logs → File System**
   - Log groups = directories
   - Log streams = files
   - Real `tail -f`, grep filtering

### Tier 2 — Medium Impact
6. **Route53 → CoreDNS**
7. **SQS → Redis List**
8. **SNS → Redis PubSub**
9. **Secrets Manager → AES encryption**
10. **Cognito → Keycloak**
11. **CloudFront → Nginx cache**
12. **ECR → Docker Registry**
13. **Certificate Manager → OpenSSL**
14. **IoT Core → Mosquitto MQTT**

### Tier 3 — Nice to Have
15. **KMS → Real AES-256**
16. **EventBridge → Real event dispatch**
17. **Step Functions → Workflow engine**
18. **CloudWatch Metrics → Prometheus**
19. **Kinesis → Kafka**
20. **CloudFormation → Provisioning engine**
21. **OpenSearch → Elasticsearch**
22. **Glue → Apache Spark**
23. **SSM → File JSON**

---

## How to Test

```bash
# Build & run
docker compose up --build -d

# Create VPC
VPC=$(aws --endpoint-url http://localhost:4566 ec2 create-vpc \
  --cidr-block 10.0.0.0/16 --region us-east-1 \
  --tag-specifications 'ResourceType=vpc,Tags=[{Key=Name,Value=my-vpc}]' \
  --query 'Vpc.VpcId' --output text)

# Create subnet + EC2 instance
SUB=$(aws --endpoint-url http://localhost:4566 ec2 create-subnet \
  --vpc-id $VPC --cidr-block 10.0.1.0/24 \
  --availability-zone us-east-1a --region us-east-1 \
  --query 'Subnet.SubnetId' --output text)

IID=$(aws --endpoint-url http://localhost:4566 ec2 run-instances \
  --image-id ami-123 --instance-type t3.nano \
  --subnet-id $SUB --region us-east-1 \
  --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=web}]' \
  --query 'Instances[0].InstanceId' --output text)

# Verify
docker ps --filter "label=ministack=ec2"
docker network ls --filter "label=ministack=vpc"
aws --endpoint-url http://localhost:4566 ec2 describe-instances \
  --instance-ids $IID --region us-east-1 \
  --query 'Reservations[0].Instances[0].[InstanceId,PrivateIpAddress,VpcId]' --output text

# EKS
aws --endpoint-url http://localhost:4566 eks create-cluster \
  --name demo --role-arn arn:aws:iam::000000000000:role/eks-role \
  --resources-vpc-config subnetIds=$SUB --region us-east-1

aws --endpoint-url http://localhost:4566 eks create-nodegroup \
  --cluster-name demo --nodegroup-name workers \
  --node-role arn:aws:iam::000000000000:role/eks-node-role \
  --subnets $SUB --scaling-config minSize=1,maxSize=3,desiredSize=2 \
  --region us-east-1

# Dashboard
open http://localhost:9090
```

---

_Report generated: 2026-06-01_
