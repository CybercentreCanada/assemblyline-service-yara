import os
import sys
import yaml

service = sys.argv[1]

SERVICE_MANIFEST = f"../{service}/service_manifest.yml"
UPDATE_CONFIG = f"/tmp/{service.replace('_', '')}_updater_config.yaml"

USER = os.environ.get("API_USER", "admin")
API_KEY = os.environ.get("API_KEY", "devkey:admin")
SERVER = os.environ.get("SERVER", "https://localhost")
PREVIOUS_UPDATE = os.environ.get("PREVIOUS_UPDATE", "1970-01-01T00:00:00.000Z")
PREVIOUS_HASH = os.environ.get("PREVIOUS_HASH", None)

with open(SERVICE_MANIFEST, 'r') as svc:
    service = yaml.safe_load(svc)

with open(UPDATE_CONFIG, 'w') as fh:
    print()
    yml = yaml.safe_dump({
        'previous_update': PREVIOUS_UPDATE,
        'previous_hash': PREVIOUS_HASH,
        'sources': [x for x in service.get("update_config", {}).get("sources", [])],
        'api_user': USER,
        'api_key': API_KEY,
        'ui_server': SERVER
    })
    fh.write(yml)
    print(yml)
