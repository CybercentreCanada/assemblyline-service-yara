import json
import logging
import os
import re
import subprocess
import tempfile

from assemblyline.common import forge
from assemblyline.common.str_utils import safe_str
from assemblyline.odm.models.signature import Signature

from plyara import Plyara, utils

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
        if len(signatures) == 0:
            self.log.info(f"There are no signatures for {source}, skipping...")
            return False

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
                        if isinstance(v, (int, bool, )):
                            # Handle integer or boolean revisions
                            version = str(v)
                        elif "." in v:
                            # Maintain version schema (M.m)
                            version_split = v.split(".", 1)
                            major = ''.join(filter(str.isdigit, version_split[0]))
                            minor = ''.join(filter(str.isdigit, version_split[1]))
                            version = f"{major}.{minor}"
                        else:
                            # Fair to assume number found is the major only
                            version = ''.join(filter(str.isdigit, v))
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
            if "cuckoo" not in signature['imports']:
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
            else:
                self.log.warning(f"Signature '{signature.get('rule_name')}' skipped because it uses cuckoo module.")

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


class YaraValidator(object):

    def __init__(self, externals=None, logger=None):
        if not logger:
            from assemblyline.common import log as al_log
            al_log.init_logging('YaraValidator')
            logger = logging.getLogger('assemblyline.yara_validator')
            logger.setLevel(logging.WARNING)
        if not externals:
            externals = {'dummy': ''}
        self.log = logger
        self.externals = externals
        self.rulestart = re.compile(r'^(?:global )?(?:private )?(?:private )?rule ', re.MULTILINE)
        self.rulename = re.compile('rule ([^{^:]+)')

    def clean(self, rulefile, eline, message, invalid_rule_name):
        with open(rulefile, 'r') as f:
            f_lines = f.readlines()
        # List will start at 0 not 1
        error_line = eline - 1

        if invalid_rule_name:
            f_lines[error_line] = f_lines[error_line].replace(invalid_rule_name, f"{invalid_rule_name}_1")
            self.log.warning(f"Yara rule '{invalid_rule_name}' was renamed '{invalid_rule_name}_1' because it's "
                             f"rule name was used more then once.")
        else:
            # First loop to find start of rule
            start_idx = 0
            while True:
                find_start = error_line - start_idx
                if find_start == -1:
                    raise Exception("Yara Validator failed to find invalid rule start. "
                                    f"Yara Error: {message} Line: {eline}")
                line = f_lines[find_start]
                if re.match(self.rulestart, line):
                    invalid_rule_name = re.search(self.rulename, line).group(1).strip()

                    # Second loop to find end of rule
                    end_idx = 0
                    while True:
                        find_end = error_line + end_idx
                        if find_end >= len(f_lines):
                            raise Exception("Yara Validator failed to find invalid rule end. "
                                            f"Yara Error: {message} Line: {eline}")
                        line = f_lines[find_end]
                        if re.match(self.rulestart, line) or find_end == len(f_lines) - 1:
                            # Now we have the start and end, strip from file
                            if find_end == len(f_lines) - 1:
                                f_lines = f_lines[:find_start]
                            else:
                                f_lines = f_lines[:find_start] + f_lines[find_end:]
                            break
                        end_idx += 1
                    # Send the error output to AL logs
                    error_message = f"Yara rule '{invalid_rule_name}' removed from rules file because of an error " \
                                    f"at line {eline} [{message}]."
                    self.log.warning(error_message)
                    break
                start_idx += 1

        with open(rulefile, 'w') as f:
            f.writelines(f_lines)

        return invalid_rule_name

    def paranoid_rule_check(self, rulefile):
        # Run rules separately on command line to ensure there are no errors
        print_val = "--==Rules_validated++__"
        external_file = os.path.join(tempfile.gettempdir(), "externals.json")
        try:
            with open(external_file, "wb") as out_json:
                out_json.write(json.dumps(self.externals).encode("utf-8"))

            p = subprocess.Popen(f"python3 paranoid_check.py {rulefile} {external_file}",
                                 cwd=os.path.dirname(os.path.realpath(__file__)),
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
            stdout, stderr = p.communicate()

        finally:
            os.unlink(external_file)

        stdout = safe_str(stdout)
        stderr = safe_str(stderr)

        if print_val not in stdout:
            if stdout.strip().startswith('yara.SyntaxError'):
                raise Exception(stdout.strip())
            else:
                raise Exception("YaraValidator has failed!--+--" + str(stderr) + "--:--" + str(stdout))

    def validate_rules(self, rulefile):
        change = False
        while True:
            try:
                self.paranoid_rule_check(rulefile)
                return change

            # If something goes wrong, clean rules until valid file given
            except Exception as e:
                error = str(e)
                change = True
                if error.startswith('yara.SyntaxError'):

                    e_line = int(error.split('):', 1)[0].split("(", -1)[1])
                    e_message = error.split("): ", 1)[1]
                    if "duplicated identifier" in error:
                        invalid_rule_name = e_message.split('"')[1]
                    else:
                        invalid_rule_name = ""
                    try:
                        self.clean(rulefile, e_line, e_message, invalid_rule_name)
                    except Exception as ve:
                        raise ve

                else:
                    raise e

                continue
