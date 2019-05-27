import json
import requests

api_objects = []

for object_type in ['dashboard', 'visualization', 'search', 'index-pattern', 'timelion-sheet']:
    r = requests.get('http://localhost:5601/api/saved_objects/_find?per_page=500&type={}'.format(object_type)).json()
    api_objects += r['saved_objects']
    print object_type, len(r['saved_objects'])
    print len(api_objects)

for api_object in api_objects:
    api_object.pop('updated_at', None)

json.dump(sorted(api_objects, key=lambda x:x['id']), open('kibana_APIonly.json', 'w'), indent=2)
