import os
import yaml

SERVICE_MANIFEST = "../service_manifest.yml"
UPDATE_CONFIG = "/tmp/yara_updater_config.yaml"

USER = os.environ.get("USER", None)
API_KEY = os.environ.get("API_KEY", None)
SERVER = os.environ.get("SERVER", None)

with open(SERVICE_MANIFEST, 'r') as svc:
    service = yaml.safe_load(svc)

with open(UPDATE_CONFIG, 'w') as fh:
    yaml.safe_dump({
        'previous_update': "1900-01-01T00:00:00.000Z",
        'previous_hash': "NONE",
        'sources': [x for x in service.get("update_config", {}).get("sources", [])],
        'api_user': USER,
        'api_key': API_KEY,
        'ui_server': SERVER
    }, fh)

