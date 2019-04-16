#!/usr/bin/env bash

NORMAL=$(tput sgr0)
GREEN=$(tput setaf 2)
YELLOW=$(tput setaf 3)
RED=$(tput setaf 1)

function red() {
    echo -e "$RED$*$NORMAL"
}

function green() {
    echo -e "$GREEN$*$NORMAL"
}

function yellow() {
    echo -e "$YELLOW$*$NORMAL"
}

elasticsearch_url="localhost:9200"
logstash_url="localhost:9600"

until curl -s "$elasticsearch_url/_cluster/health?pretty" | grep '"status"' | grep -qE "green|yellow"; do
    yellow $(curl -s "$elasticsearch_url/_cluster/health?pretty")
    yellow "\nWaiting for Elasticsearch..."
    sleep 5
done
curl -s "$elasticsearch_url/_cluster/health?pretty"

until [[ $(curl -s "$logstash_url/_node/stats" | jq '.events.out') == 1236 ]] ; do
    yellow $(curl -s "$logstash_url/_node/stats" | jq '.events')
    yellow "\nWaiting for Logstash load to finish..."
    sleep 10
done

return_code=0

if [[ $(curl -s "$elasticsearch_url/logstash-vulnwhisperer-2019.03/_count" | jq '.count') == 1232 ]]; then
    green "✅ Passed logstash-vulnwhisperer-2019.03 document count == 1232"
else
    red "❌ Failed logstash-vulnwhisperer-2019.03 document count == 1232 was: $(curl -s "$elasticsearch_url/logstash-vulnwhisperer-2019.03/_count") instead"
    ((return_code = return_code + 1))
fi

# Test Nessus plugin_name:Backported Security Patch Detection (FTP)
nessus_doc=$(curl -s "$elasticsearch_url/logstash-vulnwhisperer-2019.03/_search?q=plugin_name:%22Backported%20Security%20Patch%20Detection%20(FTP)%22%20AND%20asset:176.28.50.164%20AND%20tags:nessus" | jq '.hits.hits[]._source')
if echo $nessus_doc | jq '.risk' | grep -q "None"; then
    green "✅ Passed Nessus risk == None"
else
    red "❌ Failed Nessus risk == None was: $(echo $nessus_doc | jq '.risk') instead"
    ((return_code = return_code + 1))
fi

# Test Tenable plugin_name:Backported Security Patch Detection (FTP)
tenable_doc=$(curl -s "$elasticsearch_url/logstash-vulnwhisperer-2019.03/_search?q=plugin_name:%22Backported%20Security%20Patch%20Detection%20(FTP)%22%20AND%20asset:176.28.50.164%20AND%20tags:tenable" | jq '.hits.hits[]._source')
# Test asset
if echo $tenable_doc | jq .asset | grep -q '176.28.50.164'; then
    green "✅ Passed Tenable asset == 2019-03-30T10:17:41.000Z"
else
    red "❌ Failed Tenable asset == 176.28.50.164 was: $(echo $tenable_doc | jq .asset) instead"
    ((return_code = return_code + 1))
fi

# Test @timestamp
if echo $tenable_doc | jq '.["@timestamp"]' | grep -q '2019-03-30T15:45:44.000Z'; then
    green "✅ Passed Tenable @timestamp == 2019-03-30T10:17:41.000Z"
else
    red "❌ Failed Tenable @timestamp == 2019-03-30T15:45:44.000Z was: $(echo $tenable_doc | jq '.["@timestamp"]') instead"
    ((return_code = return_code + 1))
fi

# Test Qualys plugin_name:OpenSSL Multiple Remote Security Vulnerabilities
qualys_vuln_doc=$(curl -s "$elasticsearch_url/logstash-vulnwhisperer-2019.03/_search?q=tags:qualys_vuln%20AND%20ip:%22176.28.50.164%22%20AND%20plugin_name:%22OpenSSL%20Multiple%20Remote%20Security%20Vulnerabilities%22%20AND%20port:465" | jq '.hits.hits[]._source')
# Test @timestamp
if echo $qualys_vuln_doc | jq '.["@timestamp"]' | grep -q '2019-03-30T10:17:41.000Z'; then
    green "✅ Passed Qualys VM @timestamp == 2019-03-30T10:17:41.000Z"
else
    red "❌ Failed Qualys VM @timestamp == 2019-03-30T10:17:41.000Z was: $(echo $qualys_vuln_doc | jq '.["@timestamp"]') instead"
    ((return_code = return_code + 1))
fi

# Test @XXXX
if echo $qualys_vuln_doc | jq '.cvss' | grep -q '6.8'; then
    green "✅ Passed Qualys VM cvss == 6.8"
else
    red "❌ Failed Qualys VM cvss == 6.8 was: $(echo $qualys_vuln_doc | jq '.cvss') instead"
    ((return_code = return_code + 1))
fi

exit $return_code
