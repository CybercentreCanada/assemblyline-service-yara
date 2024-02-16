import logging
import os
import re

import yara
from assemblyline.common import forge
from assemblyline.odm.models.signature import Signature
from assemblyline_v4_service.updater.client import UpdaterClient
from plyara import Plyara, utils

DEFAULT_STATUS = "DEPLOYED"
Classification = forge.get_classification()
YARA_EXTERNALS = {f"al_{x}": x for x in ["submitter", "mime", "file_type", "tag"]}


class YaraImporter(object):
    def __init__(self, importer_type: str, al_client: UpdaterClient, logger=None):
        if not logger:
            from assemblyline.common import log as al_log

            al_log.init_logging("yara_importer")
            logger = logging.getLogger("assemblyline.yara_importer")
            logger.setLevel(logging.INFO)

        self.importer_type: str = importer_type
        self.update_client: UpdaterClient = al_client
        self.parser = Plyara()
        self.parser.STRING_ESCAPE_CHARS.add("r")
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

            for meta in signature.get("metadata", {}):
                for k, v in meta.items():
                    if k in ["classification", "sharing"]:
                        classification = v
                    elif k in ["id", "rule_id", "signature_id"]:
                        signature_id = v
                    elif k in ["version", "rule_version", "revision"]:
                        if isinstance(
                            v,
                            (
                                int,
                                bool,
                            ),
                        ):
                            # Handle integer or boolean revisions
                            version = str(v)
                        elif "." in v:
                            # Maintain version schema (M.m)
                            version_split = v.split(".", 1)
                            major = "".join(filter(str.isdigit, version_split[0]))
                            minor = "".join(filter(str.isdigit, version_split[1]))
                            version = f"{major}.{minor}"
                        else:
                            # Fair to assume number found is the major only
                            version = "".join(filter(str.isdigit, v))
                    elif k in ["status", "al_status"]:
                        status = v

            if not version:
                # If there is a null value for a version, then default to original value
                version = 1

            signature_id = signature_id or signature.get("rule_name")

            # Convert CCCS YARA status to AL signature status
            if status == "RELEASED":
                status = "DEPLOYED"
            elif status == "DEPRECATED":
                status = "DISABLED"

            # Fallback status
            if status not in ["DEPLOYED", "NOISY", "DISABLED", "STAGING", "TESTING", "INVALID"]:
                status = default_status

            # Fix imports and remove cuckoo
            signature["imports"] = utils.detect_imports(signature)
            if "cuckoo" not in signature["imports"]:
                sig = Signature(
                    dict(
                        classification=classification,
                        data=utils.rebuild_yara_rule(signature),
                        name=signature.get("rule_name"),
                        order=order,
                        revision=int(float(version)),
                        signature_id=signature_id,
                        source=source,
                        status=status,
                        type=self.importer_type,
                    )
                )
                upload_list.append(sig.as_primitives())
            else:
                self.log.warning(f"Signature '{signature.get('rule_name')}' skipped because it uses cuckoo module.")

            order += 1

        r = self.update_client.signature.add_update_many(source, self.importer_type, upload_list)
        self.log.info(f"Imported {r['success']}/{order - 1} signatures from {source} into Assemblyline")

        return r["success"]

    def _split_signatures(self, data):
        self.parser = Plyara()
        self.parser.STRING_ESCAPE_CHARS.add("r")
        return self.parser.parse_string(data)

    def import_data(self, yara_bin, source, default_status=DEFAULT_STATUS, default_classification=None):
        return self._save_signatures(
            self._split_signatures(yara_bin),
            source,
            default_status=default_status,
            default_classification=default_classification,
        )

    def import_file(self, file_path: str, source: str, default_status=DEFAULT_STATUS, default_classification=None):
        self.log.info(f"Importing file: {file_path}")
        cur_file = os.path.expanduser(file_path)
        if os.path.exists(cur_file):
            with open(cur_file, "r") as yara_file:
                yara_bin = yara_file.read()
                return self.import_data(
                    yara_bin,
                    source or os.path.basename(cur_file),
                    default_status=default_status,
                    default_classification=default_classification,
                )
        else:
            raise Exception(f"File {cur_file} does not exists.")


class YaraValidator(object):
    def __init__(self, externals=None, logger=None):
        if not logger:
            from assemblyline.common import log as al_log

            al_log.init_logging("YaraValidator")
            logger = logging.getLogger("assemblyline.yara_validator")
            logger.setLevel(logging.WARNING)
        if not externals:
            externals = {"dummy": ""}
        self.log = logger
        self.externals = externals
        self.rulestart = re.compile(r"^(?:global )?(?:private )?(?:private )?rule ", re.MULTILINE)
        self.rulename = re.compile("rule ([^{^:]+)")

    def clean(self, rulefile, eline, message, invalid_rule_name):
        with open(rulefile, "r") as f:
            f_lines = f.readlines()
        # List will start at 0 not 1
        error_line = eline - 1

        if invalid_rule_name and "duplicated identifier" in message:
            f_lines[error_line] = f_lines[error_line].replace(invalid_rule_name, f"{invalid_rule_name}_1")
            self.log.warning(
                f"Yara rule '{invalid_rule_name}' was renamed '{invalid_rule_name}_1' because it's "
                f"rule name was used more then once."
            )
        else:
            # First loop to find start of rule
            start_idx = 0
            while True:
                find_start = error_line - start_idx
                if find_start == -1:
                    raise Exception(
                        "Yara Validator failed to find invalid rule start. " f"Yara Error: {message} Line: {eline}"
                    )
                line = f_lines[find_start]
                if re.match(self.rulestart, line):
                    invalid_rule_name = re.search(self.rulename, line).group(1).strip()

                    # Second loop to find end of rule
                    end_idx = 0
                    while True:
                        find_end = error_line + end_idx
                        if find_end >= len(f_lines):
                            raise Exception(
                                "Yara Validator failed to find invalid rule end. "
                                f"Yara Error: {message} Line: {eline}"
                            )
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
                    error_message = (
                        f"Yara rule '{invalid_rule_name}' removed from rules file because of an error "
                        f"at line {eline} [{message}]."
                    )
                    self.log.warning(error_message)
                    break
                start_idx += 1

        with open(rulefile, "w") as f:
            f.writelines(f_lines)

        return invalid_rule_name

    def validate_rules(self, rulefile, al_client: UpdaterClient = None):
        change = False
        while True:
            try:
                yara.compile(filepath=rulefile, externals=self.externals).match(data="")
                return change

            # If something goes wrong, clean rules until valid file given
            except yara.SyntaxError as e:
                error = str(e)
                e_line = int(error.split("):", 1)[0].split("(", -1)[1])
                e_message = error.split("): ", 1)[1]
                if "identifier" in error:
                    # Problem with a rule associated to the identifier (unknown, duplicated)
                    invalid_rule_name = e_message.split('"')[1]
                else:
                    invalid_rule_name = ""
                try:
                    invalid_rule_name = self.clean(rulefile, e_line, e_message, invalid_rule_name)
                    if al_client:
                        # Disable offending rule from Signatures API
                        sig_id = al_client.datastore.signature.search(
                            f"type:yara AND source:{os.path.basename(rulefile)} AND name:{invalid_rule_name}",
                            rows=1, fl="id", as_obj=False)['items'][0]["id"]
                        self.log.warning(f"Disabling rule with signature_id {sig_id} because of: {error}")
                        al_client.signature.change_status(sig_id, "DISABLED")
                except Exception as ve:
                    raise ve

                continue


class YaraMetadata(object):
    MITRE_ATT_DEFAULTS = dict(
        packer="T1045", cryptography="T1032", obfuscation="T1027", keylogger="T1056", shellcode="T1055"
    )

    def __init__(self, match):
        meta = match.meta
        for k, v in meta.items():
            if len(v) == 1:
                meta[k] = v[0]

        self.name = match.rule
        self.id = meta.get("id", meta.get("rule_id", meta.get("signature_id", None)))
        self.category = meta.get("category", meta.get("rule_group", "info"))
        self.malware_type = meta.get("malware_type", None)
        self.version = meta.get("version", meta.get("rule_version", meta.get("revision", 1)))
        self.description = meta.get("description", None)
        self.classification = meta.get("classification", meta.get("sharing", Classification.UNRESTRICTED))
        self.source = meta.get("source", meta.get("organisation", None))
        self.summary = meta.get("summary", meta.get("behavior", None))
        self.author = meta.get("author", meta.get("poc", None))
        self.status = meta.get("status", None)  # Status assigned by the rule creator
        self.al_status = meta.get(self.status, meta.get("al_status", "DEPLOYED"))
        self.actor_type = meta.get("actor_type", meta.get("ta_type", meta.get("family", None)))
        self.mitre_att = meta.get("mitre_att", meta.get("attack_id", None))
        self.actor = meta.get("used_by", meta.get("actor", meta.get("threat_actor", meta.get("mitre_group", None))))
        self.exploit = meta.get("exploit", None)
        self.al_tag = meta.get("al_tag", None)
        self.al_score = meta.get("al_score", None)

        def _set_default_attack_id(key):
            if self.mitre_att:
                return self.mitre_att
            if key in self.MITRE_ATT_DEFAULTS:
                return self.MITRE_ATT_DEFAULTS[key]
            return None

        def _safe_split(comma_sep_list):
            if comma_sep_list is None:
                return []
            elif isinstance(comma_sep_list, list):
                return comma_sep_list
            return [e for e in comma_sep_list.split(",") if e]

        # Specifics about the category
        self.info = meta.get("info", None)
        self.technique = meta.get("technique", None)
        self.exploit = meta.get("exploit", None)
        self.tool = meta.get("tool", None)
        self.malware = meta.get("malware", meta.get("implant", []))

        if isinstance(self.info, list):
            self.info = ",".join(self.info)
        if isinstance(self.technique, list):
            self.technique = ",".join(self.technique)
        if isinstance(self.exploit, list):
            self.exploit = ",".join(self.exploit)
        if isinstance(self.tool, list):
            self.tool = ",".join(self.tool)
        if isinstance(self.malware, list):
            self.malware = ",".join(self.malware)

        self.actors = _safe_split(self.actor)
        self.behavior = set(_safe_split(meta.get("summary", None)))
        self.exploits = _safe_split(self.exploit)

        # Parse and populate tag list
        self.tags = []
        if self.al_tag:
            tags = self.al_tag.split(",") if isinstance(self.al_tag, str) else self.al_tag
            for tag in tags:
                tokens = tag.split(":")
                if len(tokens) == 2:
                    self.tags.append({"type": tokens[0], "value": tokens[1]})

        # Parse and populate malware list
        self.malwares = []
        if self.malware:
            malwares = self.malware.split(",") if isinstance(self.malware, str) else self.malware
            for malware in malwares:
                tokens = malware.split(":")
                malware_name = tokens[0]
                malware_family = tokens[1] if (len(tokens) == 2) else ""
                self.malwares.append((malware_name.strip().upper(), malware_family.strip().upper()))

        # Parse and populate technique info
        self.techniques = []
        if self.technique:
            if "," in self.technique:
                for technique in self.technique.split(","):
                    tokens = technique.split(":")
                    category = ""
                    if len(tokens) == 2:
                        category = tokens[0]
                        name = tokens[1]
                        self.mitre_att = _set_default_attack_id(category)
                    else:
                        name = tokens[0]
                    self.techniques.append((category.strip(), name.strip()))
            else:
                tokens = self.technique.split(":")
                category = ""
                if len(tokens) == 2:
                    category = tokens[0]
                    name = tokens[1]
                    self.mitre_att = _set_default_attack_id(category)
                else:
                    name = tokens[0]
                self.techniques.append((category.strip(), name.strip()))

        # Parse and populate info
        self.infos = []
        if self.info:
            if "," in self.info:
                for info in self.info.split(","):
                    tokens = info.split(":", 1)
                    if len(tokens) == 2:
                        # category, value
                        self.infos.append((tokens[0], tokens[1]))
                    else:
                        self.infos.append((None, tokens[0]))
            else:
                tokens = self.info.split(":", 1)
                if len(tokens) == 2:
                    # category, value
                    self.infos.append((tokens[0], tokens[1]))
                else:
                    self.infos.append((None, tokens[0]))
