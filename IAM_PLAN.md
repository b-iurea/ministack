# IAM Reale — Piano di Implementazione

## Architettura Generale

```
                    AWS CLI / boto3 / Terraform
                           │
                           │ SigV4(AccessKey, SecretKey, ...)
                           ▼
                    ┌──────────────┐
                    │  MiniStack   │
                    │  Gateway     │
                    └──────┬───────┘
                           │
                    ┌──────▼───────┐
                    │ SigV4 Parser │  ← Estrai AccessKey dal header
                    │              │    Cerca nel DB, prendi SecretKey
                    │              │    Ricomputa firma → verifica
                    └──────┬───────┘
                           │
                    ┌──────▼───────┐
                    │  Principal   │  ← User o Role identificato
                    │  Resolver    │
                    └──────┬───────┘
                           │
                    ┌──────▼───────┐
                    │   Policy     │  ← Carica tutte le policy
                    │   Engine     │    (inline + attached + group)
                    │              │    Valuta: Action, Resource, Condition
                    │              │    Explicit DENY > Allow > Implicit DENY
                    └──────┬───────┘
                           │
                    ┌──────▼───────┐
                    │   Service    │  ← EC2, S3, Lambda, ...
                    │   Handler    │
                    └──────────────┘
```

Il flusso è: ogni richiesta API passa attraverso **SigV4 validation** (oggi è lax), poi il **policy engine** decide se l'azione è permessa, poi arriva al service handler.

---

## Step 3a — Data Layer (persistenza IAM)

### File JSON su disco (come funziona oggi con `PERSIST_STATE`)

```
/data/state/iam.json
{
  "users": {
    "alice": {
      "Arn": "arn:aws:iam::000000000000:user/alice",
      "UserId": "AIDAJQABLZS4A3QDU576Q",
      "CreateDate": "2026-06-02T10:00:00Z",
      "Path": "/",
      "Password": "$2b$12$..."  // bcrypt, opzionale per login console
    }
  },
  "access_keys": {
    "AKIAIOSFODNN7EXAMPLE": {
      "UserName": "alice",
      "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
      "SecretHash": "$2b$12$...",  // bcrypt del SecretAccessKey
      "Status": "Active",
      "CreateDate": "2026-06-02T10:00:00Z"
    }
  },
  "roles": {
    "ec2-admin": {
      "Arn": "arn:aws:iam::000000000000:role/ec2-admin",
      "RoleId": "AROAJQABLZS4A3QDU576Q",
      "RoleName": "ec2-admin",
      "AssumeRolePolicyDocument": {
        "Version": "2012-10-17",
        "Statement": [{
          "Effect": "Allow",
          "Principal": {"Service": "ec2.amazonaws.com"},
          "Action": "sts:AssumeRole"
        }]
      },
      "Path": "/",
      "CreateDate": "2026-06-02T10:00:00Z",
      "MaxSessionDuration": 3600,
      "Tags": []
    }
  },
  "policies": {
    "AdministratorAccess": {
      "Arn": "arn:aws:iam::aws:policy/AdministratorAccess",
      "PolicyName": "AdministratorAccess",
      "PolicyDocument": {
        "Version": "2012-10-17",
        "Statement": [{
          "Effect": "Allow",
          "Action": "*",
          "Resource": "*"
        }]
      },
      "IsAttachable": true
    }
  },
  "user_policies": {
    "alice": ["AdministratorAccess"]
  },
  "role_policies": {
    "ec2-admin": ["AdministratorAccess"]
  },
  "groups": {}
}
```

### Operazioni CRUD (file `ministack/services/iam.py`)

```python
# Utenti
CreateUser(UserName, Path, Tags)        → User dict
GetUser(UserName)                       → User dict
DeleteUser(UserName)                    → bool
ListUsers(PathPrefix, MaxItems)         → [User]
UpdateUser(UserName, NewPath, NewName)  → User dict

# Access Keys
CreateAccessKey(UserName)               → {AccessKeyId, SecretAccessKey}
DeleteAccessKey(UserName, AccessKeyId)  → bool
ListAccessKeys(UserName)                → [AccessKey dict]
UpdateAccessKey(UserName, AccessKeyId, Status) → bool

# Ruoli
CreateRole(RoleName, AssumeRolePolicyDocument, Path, Tags) → Role dict
GetRole(RoleName)                       → Role dict
DeleteRole(RoleName)                    → bool
ListRoles(PathPrefix, MaxItems)         → [Role]
UpdateRole(RoleName, Description, MaxSessionDuration) → Role dict

# Policy
CreatePolicy(PolicyName, PolicyDocument) → Policy dict
GetPolicy(PolicyArn)                     → Policy dict
DeletePolicy(PolicyArn)                  → bool
ListPolicies(Scope, OnlyAttached)        → [Policy]
AttachUserPolicy(UserName, PolicyArn)    → bool
DetachUserPolicy(UserName, PolicyArn)    → bool
AttachRolePolicy(RoleName, PolicyArn)    → bool
DetachRolePolicy(RoleName, PolicyArn)    → bool

# Gruppi
CreateGroup(GroupName, Path)             → Group dict
AddUserToGroup(GroupName, UserName)      → bool
RemoveUserFromGroup(GroupName, UserName) → bool
```

---

## Step 3b — Policy Engine

Il cuore di IAM. File `ministack/services/iam_policy.py`.

### Algoritmo

```python
def evaluate(principal, action, resource, context=None):
    """
    principal: {"type": "user", "name": "alice"} | {"type": "role", "name": "ec2-admin"}
    action: "ec2:RunInstances"
    resource: "arn:aws:ec2:us-east-1:000000000000:instance/*"
    
    Returns: "allow" | "deny" | "implicit_deny"
    """
    statements = _collect_statements(principal)  # inline + attached + group policies
    
    explicit_deny = False
    explicit_allow = False
    
    for stmt in statements:
        if not _action_matches(stmt["Action"], action):
            continue
        if not _resource_matches(stmt["Resource"], resource):
            continue
        # Condition skipped for now
        
        if stmt["Effect"] == "Deny":
            explicit_deny = True
        elif stmt["Effect"] == "Allow":
            explicit_allow = True
    
    if explicit_deny:
        return "deny"         # Explicit Deny vince su tutto
    if explicit_allow:
        return "allow"
    return "implicit_deny"    # Default deny
```

### Pattern Matching

```python
def _action_matches(pattern, action):
    """
    "ec2:*"        → ec2:RunInstances ✅, ec2:DescribeInstances ✅
    "ec2:Run*"     → ec2:RunInstances ✅, ec2:RunScheduledInstances ✅
    "*"            → qualsiasi azione ✅
    "ec2:RunInstances" → solo match esatto
    """
    regex = "^" + pattern.replace("*", ".*") + "$"
    return bool(re.match(regex, action))
```

```python
def _resource_matches(pattern, resource):
    """
    "arn:aws:ec2:*:*:instance/*" → arn:aws:ec2:us-east-1:000000000000:instance/i-xxx ✅
    "*" → qualsiasi risorsa ✅
    """
    regex = "^" + re.escape(pattern).replace("\\*", ".*") + "$"
    return bool(re.match(regex, resource))
```

### Raccogliere le policy

```python
def _collect_statements(principal):
    statements = []
    name = principal["name"]
    is_user = principal["type"] == "user"
    
    # 1. Policy inline (attached direttamente)
    policy_list = _user_policies.get(name, []) if is_user else _role_policies.get(name, [])
    for policy_name in policy_list:
        policy = _policies.get(policy_name, {})
        for stmt in policy.get("PolicyDocument", {}).get("Statement", []):
            statements.append(stmt)
    
    # 2. Policy via gruppo (solo per user)
    if is_user:
        for group_name, members in _groups.items():
            if name in members:
                for policy_name in _group_policies.get(group_name, []):
                    policy = _policies.get(policy_name, {})
                    for stmt in policy.get("PolicyDocument", {}).get("Statement", []):
                        statements.append(stmt)
    
    return statements
```

---

## Step 3c — SigV4 Validation

Oggi il codice SigV4 è in `app.py` — estrae la regione e l'account, ma non valida la firma.

### Da modificare in `app.py`

```python
# Oggi:
def extract_region(headers):
    # Estrae regione dal header Authorization (senza validare)
    ...
    return region

# Domani:
def authenticate_request(method, path, headers, body, query_params):
    """
    1. Estrai AccessKey dal header Authorization
    2. Cerca l'AccessKey nel DB IAM → ottieni SecretKey hash
    3. Ricomputa la firma SigV4
    4. Se match → restituisci (principal, account_id, region)
    5. Se no match → 403 Forbidden
    """
    auth = headers.get("authorization", "")
    cred = _extract_credential(auth)
    if not cred:
        return None, None, None  # No auth → default account
    
    access_key = cred["access_key"]
    key_data = _access_keys.get(access_key)
    if not key_data:
        return None, None, None  # Unknown key → fallback (per retrocompatibilità)
    
    # Valida firma
    secret = _get_secret(key_data["UserName"])  # dal db
    expected_sig = _compute_sigv4(secret, method, path, headers, body, query_params, cred)
    actual_sig = _extract_signature(auth)
    
    if not hmac.compare_digest(expected_sig, actual_sig):
        raise HTTPException(403, "InvalidClientTokenId")
    
    return {"type": "user", "name": key_data["UserName"]}, cred["account_id"], cred["region"]
```

### Note importanti

- **Retrocompatibilità**: se l'AccessKey non esiste nel DB, usiamo il comportamento attuale (default account, nessuna validazione). Così i test esistenti non si rompono.
- **Feature flag**: `IAM_ENFORCE=1` per attivare la validazione. Di default `0` (lax).
- **Performance**: la validazione SigV4 è costosa (HMAC-SHA256 su tutto il body). Cache per AccessKey lookup.

---

## Step 3d — STS AssumeRole

```python
def assume_role(p):
    role_arn = extract_role_name_from_arn(p["RoleArn"])
    role = _roles.get(role_arn)
    if not role:
        return error("InvalidRole", "Role not found")
    
    # Validazione trust policy
    caller = _current_principal  # dal contesto SigV4
    trust_doc = role["AssumeRolePolicyDocument"]
    if not _validate_trust(trust_doc, caller):
        return error("AccessDenied", "Not authorized to assume role")
    
    # Genera credenziali temporanee
    session_name = p.get("RoleSessionName", "session")
    access_key = _generate_access_key()
    secret_key = _generate_secret_key()
    session_token = _generate_session_token(role, session_name)
    
    # Salva sessione (TTL configurabile)
    _sessions[session_token] = {
        "role_name": role_arn,
        "access_key": access_key,
        "secret_key": secret_key,
        "expires": time.time() + (p.get("DurationSeconds", 3600)),
        "session_name": session_name,
    }
    
    return xml(200, "AssumeRoleResponse", {
        "AccessKeyId": access_key,
        "SecretAccessKey": secret_key,
        "SessionToken": session_token,
        "Expiration": timestamp,
    })
```

---

## Step 3e — Multi-Account IAM

Oggi c'è `MINISTACK_ACCOUNT_ID=000000000000`. Per supportare multi-account IAM:

```python
# Il DB IAM è scoped per account
_iam_state = AccountScopedDict()  # key = (account_id, "users"|"roles"|...)

# Ogni account ha i suoi utenti/ruoli separati
_iam_state[(account_id, "users")] = {...}
_iam_state[(account_id, "roles")] = {...}
```

Quando si chiama `AssumeRole` cross-account, la trust policy deve permetterlo.

---

## Step 3f — IMDS (Instance Metadata Service) — da fare dopo

Per le istanze EC2 che assumono ruoli via instance profile:

```
Container EC2:
  http://169.254.169.254/latest/meta-data/iam/security-credentials/ec2-admin
  → {"AccessKeyId": "...", "SecretAccessKey": "...", "Token": "..."}
```

Implementazione: un mini HTTP server avviato nel container EC2 che forwarda le richieste al ministack API.

---

## Piano di Sviluppo

### Fase 1 — Data Layer (`iam_store.py`) — ~200 linee
- Dizionari in memoria per users, keys, roles, policies
- CRUD operations
- Persistenza via `PERSIST_STATE`
- Formato JSON come descritto sopra

### Fase 2 — Policy Engine (`iam_policy.py`) — ~250 linee
- `evaluate()` function
- Pattern matching per Action e Resource
- Raccolta policy (inline + attached + group)

### Fase 3 — API Handler (`iam.py`) — ~400 linee
- Tutti gli endpoint CRUD
- AssumeRole in STS
- GetCallerIdentity in STS

### Fase 4 — SigV4 Validation (`app.py` + `sigv4.py`) — ~300 linee
- Validazione firma reale
- Feature flag `IAM_ENFORCE`
- Integrazione con il dispatch esistente

### Fase 5 — Test — ~300 linee
- Unit test per policy engine
- Integration test: crea utente, assumi ruolo, verifica permessi

---

## Riepilogo

| Cosa | File | Linee stimate |
|---|---|---|
| Data layer | `iam_store.py` (nuovo) | ~200 |
| Policy engine | `iam_policy.py` (nuovo) | ~250 |
| API handler | `iam.py` (modifica) | ~400 |
| STS AssumeRole | `sts.py` (modifica) | ~100 |
| SigV4 validation | `app.py` + `sigv4.py` | ~300 |
| Test | `test_iam.py` + `test_iam_policy.py` | ~400 |
| **Totale** | | **~1650 linee** |

### Feature flag

```bash
IAM_ENFORCE=0  # default: comportamento attuale (lax)
IAM_ENFORCE=1  # validazione SigV4 + policy enforcement attivi
```

Così possiamo merged su main senza rompere niente, e attivare quando siamo pronti.
