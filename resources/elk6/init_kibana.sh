#!/bin/bash

#kibana_url="localhost:5601"
kibana_url="kibana.local:5601"
elasticsearch_url="elasticsearch.local:9200"
add_saved_objects="curl -s -u elastic:changeme -k -XPOST 'http://"$kibana_url"/api/saved_objects/_bulk_create' -H 'Content-Type: application/json' -H \"kbn-xsrf: true\" -d @"

#Create all saved objects - including index pattern
saved_objects_file="kibana_APIonly.json"

#if [ `curl -I localhost:5601/status | head -n1 |cut -d$' ' -f2` -eq '200' ]; then echo "Loading VulnWhisperer Saved Objects"; eval $(echo $add_saved_objects$saved_objects_file); else echo "waiting for kibana"; fi

until curl -s "$elasticsearch_url/_cluster/health?pretty" | grep '"status"' | grep -qE "green|yellow"; do
    curl -s "$elasticsearch_url/_cluster/health?pretty"
    echo "Waiting for Elasticsearch..."
    sleep 5
done

count=0
until  curl -s --fail -XPUT "http://$elasticsearch_url/_template/vulnwhisperer" -H 'Content-Type: application/json' -d '@/opt/index-template.json'; do
    echo "Loading VulnWhisperer index template..."
    ((count++)) && ((count==60)) && break
    sleep 1
done

if [[ count -le 60 && $(curl -s -I http://$elasticsearch_url/_template/vulnwhisperer | head -n1 |cut -d$' ' -f2) == "200" ]]; then
    echo -e "\n✅ VulnWhisperer index template loaded"
else
    echo -e "\n❌ VulnWhisperer index template failed to load"
fi

until [ "`curl -s -I "$kibana_url"/status | head -n1 |cut -d$' ' -f2`" == "200" ]; do
    curl -s -I "$kibana_url"/status
    echo "Waiting for Kibana..."
    sleep 5
done

echo "Loading VulnWhisperer Saved Objects"
echo $add_saved_objects$saved_objects_file
eval $(echo $add_saved_objects$saved_objects_file)

#set "*" as default index
#id_default_index="87f3bcc0-8b37-11e8-83be-afaed4786d8c"
#os.system("curl -X POST -H \"Content-Type: application/json\" -H \"kbn-xsrf: true\" -d '{\"value\":\""+id_default_index+"\"}' http://elastic:changeme@"+kibana_url+"kibana/settings/defaultIndex")

#Create vulnwhisperer index pattern
#index_name = "logstash-vulnwhisperer-*"
#os.system(add_index+index_name+"' '-d{\"attributes\":{\"title\":\""+index_name+"\",\"timeFieldName\":\"@timestamp\"}}'")

#Create jira index pattern, separated for not fill of crap variables the Discover tab by default
#index_name = "logstash-jira-*"
#os.system(add_index+index_name+"' '-d{\"attributes\":{\"title\":\""+index_name+"\",\"timeFieldName\":\"@timestamp\"}}'")