import logging
import os

from plyara import Plyara, utils

from assemblyline.common import forge
from assemblyline.odm.models.signature import Signature

UPDATE_CONFIGURATION_PATH = os.environ.get('UPDATE_CONFIGURATION_PATH', None)
DEFAULT_STATUS = "DEPLOYED"


class YaraImporter(object):
    def __init__(self, importer_type, al_client, logger=None):
        if not logger:
            from assemblyline.common import log as al_log
            al_log.init_logging('yara_importer')
            logger = logging.getLogger('assemblyline.yara_importer')
            logger.setLevel(logging.INFO)

        self.importer_type = importer_type
        self.update_client = al_client
        self.parser = Plyara()
        self.classification = forge.get_classification()
        self.log = logger

    def _save_signatures(self, signatures, source, default_status=DEFAULT_STATUS, default_classification=None):
        order = 1
        upload_list = []
        for signature in signatures:
            classification = default_classification or self.classification.UNRESTRICTED
            signature_id = None
            version = 1
            status = default_status

            for meta in signature.get('metadata', {}):
                for k, v in meta.items():
                    if k in ["classification", "sharing"]:
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
                type=self.importer_type,
            ))
            upload_list.append(sig.as_primitives())
            order += 1

        r = self.update_client.signature.add_update_many(source, self.importer_type, upload_list)
        self.log.info(f"Imported {r['success']}/{order - 1} signatures from {source} into Assemblyline")

        return r['success']

    def _split_signatures(self, data):
        self.parser = Plyara()
        return self.parser.parse_string(data)

    def import_data(self, yara_bin, source, default_status=DEFAULT_STATUS,
                    default_classification=None):
        return self._save_signatures(self._split_signatures(yara_bin), source, default_status=default_status,
                                     default_classification=default_classification)

    def import_file(self, file_path: str, source: str, default_status=DEFAULT_STATUS,
                    default_classification=None):
        self.log.info(f"Importing file: {file_path}")
        cur_file = os.path.expanduser(file_path)
        if os.path.exists(cur_file):
            with open(cur_file, "r") as yara_file:
                yara_bin = yara_file.read()
                return self.import_data(yara_bin, source or os.path.basename(cur_file),
                                        default_status=default_status, default_classification=default_classification)
        else:
            raise Exception(f"File {cur_file} does not exists.")
