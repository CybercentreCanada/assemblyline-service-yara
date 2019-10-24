import logging
import os

from assemblyline.common import forge
from assemblyline.common.str_utils import safe_str
from assemblyline.odm.models.signature import Signature

UPDATE_CONFIGURATION_PATH = os.environ.get('UPDATE_CONFIGURATION_PATH', None)
DEFAULT_STATUS = "TESTING"


class YaraImporter(object):
    def __init__(self, al_client, logger=None):
        if not logger:
            from assemblyline.common import log as al_log
            al_log.init_logging('yara_importer')
            logger = logging.getLogger('assemblyline.yara_importer')
            logger.setLevel(logging.INFO)

        self.update_client = al_client

        self.classification = forge.get_classification()
        self.log = logger

    @staticmethod
    def get_signature_name(signature):
        name = None
        for line in signature.splitlines():
            line = line.strip()
            if line.startswith("rule ") or line.startswith("private rule ") \
                    or line.startswith("global rule ") or line.startswith("global private rule "):
                name = line.split(":")[0].split("{")[0]
                name = name.replace("global ", "").replace("private ", "").replace("rule ", "")
                break

        if name is None:
            return name
        return name.strip()

    @staticmethod
    def parse_meta(signature):
        meta = {}
        meta_started = False
        for line in signature.splitlines():
            line = line.strip()
            if not meta_started and line.startswith('meta') and line.endswith(':'):
                meta_started = True
                continue

            if meta_started:
                if line.startswith("//") or line == "":
                    continue

                if "=" not in line:
                    break

                key, val = line.split("=", 1)
                key = key.strip()
                val = val.strip().strip('"')
                meta[key] = safe_str(val)

        return meta

    def _save_signatures(self, signatures, source, default_status=DEFAULT_STATUS):
        saved_sigs = []
        order = 1
        for signature in signatures:
            meta = self.parse_meta(signature)

            name = self.get_signature_name(signature)
            classification = meta.get('classification', self.classification.UNRESTRICTED)
            signature_id = meta.get('id', meta.get('rule_id', meta.get('signature_id', f'{source}_{name}')))
            version = meta.get('version', meta.get('rule_version', meta.get('revision', 1)))

            status = meta.get('status', meta.get('al_status', default_status))

            # Convert CCCS YARA status to AL status
            if status == "RELEASED":
                status = "DEPLOYED"
            elif status == "DEPRECATED":
                status = "DISABLED"

            sig = Signature(dict(
                classification=classification,
                data=signature,
                name=name,
                order=order,
                revision=int(float(version)),
                signature_id=signature_id,
                source=source,
                status=status,
                type="yara",
            ))
            r = self.update_client.signature.add_update(sig.as_primitives())

            if r['success']:
                self.log.info(f"Successfully added signature {name} (ID: {r['id']}")
            else:
                self.log.warning(f"Failed to add signature {name}")

            saved_sigs.append(sig)
            order += 1

        return saved_sigs

    @ staticmethod
    def _split_signatures(data):
        current_signature = []
        signatures = []
        in_rule = False
        for line in data.splitlines():
            temp_line = line.strip()

            if in_rule:
                current_signature.append(line)

                if temp_line == "}":
                    signatures.append("\n".join(current_signature))
                    current_signature = []
                    in_rule = False

            if temp_line.startswith("rule ") or temp_line.startswith("private rule ") \
                    or temp_line.startswith("global rule ") or temp_line.startswith("global private rule "):
                in_rule = True
                current_signature.append(line)

        return signatures

    def import_data(self, yara_bin, source, default_status=DEFAULT_STATUS):
        return self._save_signatures(self._split_signatures(yara_bin), source, default_status=default_status)

    def import_file(self, file_path: str, source: str, default_status=DEFAULT_STATUS):
        cur_file = os.path.expanduser(file_path)
        if os.path.exists(cur_file):
            with open(cur_file, "r") as yara_file:
                yara_bin = yara_file.read()
                return self.import_data(yara_bin, source or os.path.basename(cur_file), default_status=default_status)
        else:
            raise Exception(f"File {cur_file} does not exists.")
