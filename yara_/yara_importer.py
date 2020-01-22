import logging
import os

from plyara import Plyara, utils

from assemblyline.common import forge
from assemblyline.odm.models.signature import Signature

UPDATE_CONFIGURATION_PATH = os.environ.get('UPDATE_CONFIGURATION_PATH', None)
DEFAULT_STATUS = "DEPLOYED"


class YaraImporter(object):
    def __init__(self, al_client, logger=None):
        if not logger:
            from assemblyline.common import log as al_log
            al_log.init_logging('yara_importer')
            logger = logging.getLogger('assemblyline.yara_importer')
            logger.setLevel(logging.INFO)

        self.update_client = al_client
        self.parser = Plyara()
        self.classification = forge.get_classification()
        self.log = logger

    def _save_signatures(self, signatures, source, default_status=DEFAULT_STATUS):
        saved_sigs = []
        order = 1
        for signature in signatures:
            classification = self.classification.UNRESTRICTED
            signature_id = None
            version = 1
            status = default_status

            for meta in signature.get('metadata', {}):
                for k, v in meta.items():
                    if k in ["classification"]:
                        classification = v
                    elif k in ['id', 'rule_id', 'signature_id']:
                        signature_id = v
                    elif k in ['version', 'rule_version', 'revision']:
                        version = v
                    elif k in ['status', 'al_status']:
                        status = v

            # Convert CCCS YARA status to AL signature status
            if status == "RELEASED":
                status = "DEPLOYED"
            elif status == "DEPRECATED":
                status = "DISABLED"

            # Fallback status
            if status not in ["DEPLOYED", "NOISY", "DISABLED", "STAGING", "TESTING", "INVALID"]:
                status = default_status

            # Fix imports and remove cuckoo
            signature['imports'] = utils.detect_imports(signature)
            if "cuckoo" in signature['imports']:
                signature['imports'].remove('cuckoo')

            sig = Signature(dict(
                classification=classification,
                data=utils.rebuild_yara_rule(signature),
                name=signature.get('rule_name'),
                order=order,
                revision=int(float(version)),
                signature_id=signature_id or signature.get('rule_name'),
                source=source,
                status=status,
                type="yara",
            ))
            r = self.update_client.signature.add_update(sig.as_primitives())

            if r['success']:
                self.log.info(f"Successfully added signature {signature.get('rule_name')} (ID: {r['id']})")
                saved_sigs.append(sig)
                order += 1
            else:
                self.log.warning(f"Failed to add signature {signature.get('rule_name')}")

        self.log.info(f"Imported {order - 1} signatures from {source} into Assemblyline")

        return saved_sigs

    def _split_signatures(self, data):
        self.parser = Plyara()
        return self.parser.parse_string(data)

    def import_data(self, yara_bin, source, default_status=DEFAULT_STATUS):
        return self._save_signatures(self._split_signatures(yara_bin), source, default_status=default_status)

    def import_file(self, file_path: str, source: str, default_status=DEFAULT_STATUS):
        self.log.info(f"Importing file: {file_path}")
        cur_file = os.path.expanduser(file_path)
        if os.path.exists(cur_file):
            with open(cur_file, "r") as yara_file:
                yara_bin = yara_file.read()
                return self.import_data(yara_bin, source or os.path.basename(cur_file), default_status=default_status)
        else:
            raise Exception(f"File {cur_file} does not exists.")
