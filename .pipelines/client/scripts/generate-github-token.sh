#!/bin/bash
set -euo pipefail

[ -z "${PRIVATE_KEY:-}" ] && echo "PRIVATE_KEY must be set" && exit 1
[ -z "${CLIENT_ID:-}" ] && echo "CLIENT_ID must be set" && exit 1
[ -z "${INSTALLATION_ID:-}" ] && echo "INSTALLATION_ID must be set" && exit 1

REPO_NAME="aks-secure-tls-bootstrap"

now=$(date +%s)
iat=$((${now} - 60)) # issues 60 seconds in the past
exp=$((${now} + 600)) # expires 10 minutes in the future

b64enc() { openssl base64 | tr -d '=' | tr '/+' '_-' | tr -d '\n'; }

header_json='{
    "typ":"JWT",
    "alg":"RS256"
}'
# encode the JWT header
header=$(echo -n "${header_json}" | b64enc)

payload_json="{
    \"iat\":${iat},
    \"exp\":${exp},
    \"iss\":\"${CLIENT_ID}\"
}"
# encode the JWT payload
payload=$(echo -n "${payload_json}" | b64enc)

# create the JWT signature
header_payload="${header}"."${payload}"
signature=$(
    openssl dgst -sha256 -sign <(echo -n "${PRIVATE_KEY}") \
    <(echo -n "${header_payload}") | b64enc
)

# create the JWT
jwt="${header_payload}"."${signature}"

# get the installation token
response=$(curl -X POST -L \
    -H "Accept: application/vnd.github+json" \
    -H "Authorization: Bearer $jwt" \
    -H "X-GitHub-Api-Version: 2022-11-28" \
    -d "{\"repositories\":[\"$REPO_NAME\"]}" \
    "https://api.github.com/app/installations/${INSTALLATION_ID}/access_tokens")

token="$(echo $response | jq -r '.token')"
if [ -z "$token" ] || [ "$token" == "null" ]; then
    echo "unable to generate installation access token for repository: $REPO_NAME"
    echo "unable to extract token from GitHub resposne"
    exit 1
fi

echo "##vso[task.setvariable variable=GITHUB_TOKEN;issecret=true]$token"
echo "generated installation access token for repository: $REPO_NAME"
