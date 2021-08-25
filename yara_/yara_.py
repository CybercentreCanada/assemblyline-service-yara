import hashlib
import json
import os
import shutil
import threading
import time
import tempfile
import tarfile
from pathlib import Path
from typing import List

import yara
import requests

from assemblyline.common import forge
from assemblyline.common.digests import get_sha256_for_file
from assemblyline.common.str_utils import safe_str
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.result import Result, ResultSection, BODY_FORMAT

Classification = forge.get_classification()
FILE_UPDATE_DIRECTORY = os.environ.get('FILE_UPDATE_DIRECTORY', "/mount/updates/")
UPDATES_HOST = os.environ.get('updates_host')
UPDATES_PORT = os.environ.get('updates_port')
UPDATES_KEY = os.environ.get('updates_key')


class YaraMetadata(object):
    MITRE_ATT_DEFAULTS = dict(
        packer="T1045",
        cryptography="T1032",
        obfuscation="T1027",
        keylogger="T1056",
        shellcode="T1055"
    )

    def __init__(self, match):
        meta = match.meta
        self.name = match.rule
        self.id = meta.get('id', meta.get('rule_id', meta.get('signature_id', None)))
        self.category = meta.get('category', meta.get('rule_group', 'info')).lower()
        self.malware_type = meta.get('malware_type', None)
        self.version = meta.get('version', meta.get('rule_version', meta.get('revision', 1)))
        self.description = meta.get('description', None)
        self.classification = meta.get('classification', meta.get('sharing', Classification.UNRESTRICTED))
        self.source = meta.get('source', meta.get('organisation', None))
        self.summary = meta.get('summary', meta.get('behavior', None))
        self.author = meta.get('author', meta.get('poc', None))
        self.status = meta.get('status', None)  # Status assigned by the rule creator
        self.al_status = meta.get(self.status, meta.get('al_status', 'DEPLOYED'))
        self.actor_type = meta.get('actor_type', meta.get('ta_type', meta.get('family', None)))
        self.mitre_att = meta.get('mitre_att', meta.get("attack_id", None))
        self.actor = meta.get('used_by', meta.get('actor', meta.get('threat_actor', meta.get('mitre_group', None))))
        self.exploit = meta.get('exploit', None)
        self.al_tag = meta.get('al_tag', None)

        def _set_default_attack_id(key):
            if self.mitre_att:
                return self.mitre_att
            if key in self.MITRE_ATT_DEFAULTS:
                return self.MITRE_ATT_DEFAULTS[key]
            return None

        def _safe_split(comma_sep_list):
            if comma_sep_list is None:
                return []
            return [e for e in comma_sep_list.split(',') if e]

        # Specifics about the category
        self.info = meta.get('info', None)
        self.technique = meta.get('technique', None)
        self.exploit = meta.get('exploit', None)
        self.tool = meta.get('tool', None)
        self.malware = meta.get('malware', meta.get('implant', None))

        self.actors = _safe_split(self.actor)
        self.behavior = set(_safe_split(meta.get('summary', None)))
        self.exploits = _safe_split(self.exploit)

        # Parse and populate tag list
        self.tags = []
        if self.al_tag:
            if ',' in self.malware:
                for al_tag in self.al_tag.split(','):
                    tokens = al_tag.split(':')
                    if len(tokens) == 2:
                        self.tags.append({"type": tokens[0], 'value': tokens[1]})

            else:
                tokens = self.al_tag.split(':')
                if len(tokens) == 2:
                    self.tags.append({"type": tokens[0], 'value': tokens[1]})

        # Parse and populate malware list
        self.malwares = []
        if self.malware:
            if ',' in self.malware:
                for malware in self.malware.split(','):
                    tokens = malware.split(':')
                    malware_name = tokens[0]
                    malware_family = tokens[1] if (len(tokens) == 2) else ''
                    self.malwares.append((malware_name.strip().upper(), malware_family.strip().upper()))
            else:
                tokens = self.malware.split(':')
                malware_name = tokens[0]
                malware_family = tokens[1] if (len(tokens) == 2) else self.malware_type or ''
                self.malwares.append((malware_name.strip().upper(), malware_family.strip().upper()))

        # Parse and populate technique info
        self.techniques = []
        if self.technique:
            if ',' in self.technique:
                for technique in self.technique.split(','):
                    tokens = technique.split(':')
                    category = ''
                    if len(tokens) == 2:
                        category = tokens[0]
                        name = tokens[1]
                        self.mitre_att = _set_default_attack_id(category)
                    else:
                        name = tokens[0]
                    self.techniques.append((category.strip(), name.strip()))
            else:
                tokens = self.technique.split(':')
                category = ''
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
            if ',' in self.info:
                for info in self.info.split(','):
                    tokens = info.split(':', 1)
                    if len(tokens) == 2:
                        # category, value
                        self.infos.append((tokens[0], tokens[1]))
                    else:
                        self.infos.append((None, tokens[0]))
            else:
                tokens = self.info.split(':', 1)
                if len(tokens) == 2:
                    # category, value
                    self.infos.append((tokens[0], tokens[1]))
                else:
                    self.infos.append((None, tokens[0]))


class Yara(ServiceBase):
    TECHNIQUE_DESCRIPTORS = dict(
        shellcode=('technique.shellcode', 'Embedded shellcode'),
        packer=('technique.packer', 'Packed PE'),
        cryptography=('technique.crypto', 'Uses cryptography/compression'),
        obfuscation=('technique.obfuscation', 'Obfuscated'),
        keylogger=('technique.keylogger', 'Keylogging capability'),
        comms_routine=('technique.comms_routine', 'Does external comms'),
        persistance=('technique.persistence', 'Has persistence'),
    )

    INFO_DESCRIPTORS = dict(
        compiler=("file.compiler", "Compiled with known compiler"),
        libs=("file.lib", "Using known library"),
        lib=("file.lib", "Using known library")

    )

    YARA_HEURISTICS_MAP = dict(
        info=1,
        technique=2,
        exploit=3,
        tool=4,
        malware=5,
        safe=6,
        tl1=7,
        tl2=8,
        tl3=9,
        tl4=10,
        tl5=11,
        tl6=12,
        tl7=13,
        tl8=14,
        tl9=15,
        tl10=16,
    )

    def __init__(self, config=None, name=None, externals=None):
        super().__init__(config)

        if externals is None:
            externals = ['submitter', 'mime', 'file_type']

        if name is None:
            self.name = "Yara"
        else:
            self.name = name

        self.initialization_lock = threading.RLock()
        self.rules = None
        self.rules_list = []
        self.deep_scan = None

        # Load rules and externals
        self.rules_directory = None
        self.update_time = None
        self.rules_hash = ''
        self.yara_externals = {f'al_{x.replace(".", "_")}': "" for x in externals}

    def _download_rules(self):
        url_base = f'http://{UPDATES_HOST}:{UPDATES_PORT}/'
        headers = {
            'X_APIKEY': UPDATES_KEY
        }

        # Check if there are new        
        while True:
            resp = requests.get(url_base + 'status')
            resp.raise_for_status()
            status = resp.json()
            if self.update_time is not None and self.update_time >= status['local_update_time']:
                return False
            if status['download_available']:
                break
            self.log.warning('Waiting on update server availability...')
            time.sleep(10)

        # Download the current update
        temp_directory = tempfile.mkdtemp()
        buffer_handle, buffer_name = tempfile.mkstemp()
        try:
            with os.fdopen(buffer_handle, 'wb') as buffer:
                resp = requests.get(url_base + 'tar', headers=headers)
                resp.raise_for_status()
                for chunk in resp.iter_content(chunk_size=1024):
                    buffer.write(chunk)

            tar_handle = tarfile.open(buffer_name)
            tar_handle.extractall(temp_directory)
            self.update_time = status['local_update_time']
            self.rules_directory, temp_directory = temp_directory, self.rules_directory
            return True
        finally:
            os.unlink(buffer_name)
            if temp_directory is not None:
                shutil.rmtree(temp_directory, ignore_errors=True)

    def _update_rules(self):
        if self._download_rules():
            self.rules_hash = self._get_rules_hash()
            self._load_rules()

    def _add_resultinfo_for_match(self, result: Result, match):
        """
        Parse from Yara signature match and add information to the overall AL service result. This module determines
        result score and identifies any AL tags that should be added (i.e. IMPLANT_NAME, THREAT_ACTOR, etc.).

        Args:
            result: AL ResultSection object.
            match: Yara rules Match object item.

        Returns:
            None.
        """
        almeta = YaraMetadata(match)
        self._normalize_metadata(almeta)

        section = ResultSection('', classification=almeta.classification)
        if self.deep_scan or almeta.al_status != "NOISY":
            section.set_heuristic(self.YARA_HEURISTICS_MAP.get(almeta.category, 1),
                                  signature=f'{match.namespace}.{match.rule}', attack_id=almeta.mitre_att)
        section.add_tag(f'file.rule.{self.name.lower()}', f'{match.namespace}.{match.rule}')

        title_elements = [f"[{match.namespace}] {match.rule}", ]

        if almeta.actor_type:
            section.add_tag('attribution.actor', almeta.actor_type)

        for tag in almeta.tags:
            section.add_tag(tag['type'], tag['value'])

        # Malware Tags
        implant_title_elements = []
        for (implant_name, implant_family) in almeta.malwares:
            if implant_name:
                implant_title_elements.append(implant_name)
                section.add_tag('attribution.implant', implant_name)
            if implant_family:
                implant_title_elements.append(implant_family)
                section.add_tag('attribution.family', implant_family)
        if implant_title_elements:
            title_elements.append(f"- Implant(s): {', '.join(implant_title_elements)}")

        # Threat Actor metadata
        for actor in almeta.actors:
            title_elements.append(actor)
            section.add_tag('attribution.actor', actor)

        # Exploit / CVE metadata
        if almeta.exploits:
            title_elements.append(f"- Exploit(s): {', '.join(almeta.exploits)}")
        for exploit in almeta.exploits:
            section.add_tag('attribution.exploit', exploit)

        # Include technique descriptions in the section behavior
        for (category, name) in almeta.techniques:
            descriptor = self.TECHNIQUE_DESCRIPTORS.get(category, None)
            if descriptor:
                technique_type, technique_description = descriptor
                section.add_tag(technique_type, name)
                almeta.behavior.add(technique_description)

        for (category, name) in almeta.infos:
            descriptor = self.INFO_DESCRIPTORS.get(category, None)
            if descriptor:
                info_type, info_description = descriptor
                section.add_tag(info_type, name)
                almeta.behavior.add(info_description)

        # Summaries
        if almeta.behavior:
            title_elements.append(f"- Behavior: {', '.join(almeta.behavior)}")
        for element in almeta.behavior:
            section.add_tag('file.behavior', element)

        title = " ".join(title_elements)
        section.title_text = title

        json_body = dict(
            name=match.rule,
        )

        for item in ['id', 'version', 'author', 'description', 'source', 'malware', 'info',
                     'technique', 'tool', 'exploit', 'actor', 'category', 'mitre_att']:
            val = almeta.__dict__.get(item, None)
            if val:
                json_body[item] = val

        string_match_data = self._add_string_match_data(match)
        if string_match_data:
            json_body['string_hits'] = string_match_data

        section.set_body(json.dumps(json_body), body_format=BODY_FORMAT.KEY_VALUE)

        result.add_section(section)
        # result.order_results_by_score() TODO: should v4 support this?

    def _add_string_match_data(self, match) -> List[str]:
        """
        Parses and adds matching strings from a Yara match object to an AL ResultSection.

        Args:
            match: Yara match object.

        Returns:
            None.
        """
        string_hits = []
        strings = match.strings
        string_dict = {}
        for offset, identifier, data in strings:
            if data not in string_dict:
                string_dict[data] = []
            string_dict[data].append((offset, identifier))

        result_dict = {}
        for string_value, string_list in string_dict.items():
            if isinstance(string_value, bytes):
                string_value = safe_str(string_value)
            count = len(string_list)
            string_offset_list = []
            ident = ''
            for offset, ident in string_list[:5]:
                string_offset_list.append(str(hex(offset)).replace("L", ""))

            if ident == '$':
                string_name = ""
            else:
                string_name = f"{ident[1:]} "

            string_offset = ", ".join(string_offset_list)
            if len(string_list) > 5:
                string_offset += "..."

            is_wide_char = self._is_wide_char(string_value)
            if is_wide_char:
                string_value = self._get_non_wide_char(string_value)

            string_value = repr(string_value)
            if len(string_value) > 100:
                string_value = f"{string_value[:100]}..."

            wide_str = ""
            if is_wide_char:
                wide_str = " (wide)"

            entry_name = ''.join((string_name, wide_str))
            if string_name:
                result_list = result_dict.get(entry_name, [])
                result_list.append((string_value, string_offset, count))
                result_dict[entry_name] = result_list
                continue

            string_hit = f"{entry_name}: '{string_value} [@ {string_offset}]" \
                         f"{' (' + str(count) + 'x)' if count > 1 else ''}'"
            string_hits.append(string_hit)

        for entry_name, result_list in result_dict.items():
            for result in result_list[:5]:
                if isinstance(result[0], bytes):
                    result[0] = safe_str(result[0])
                string_hit = f"{entry_name}: '{result[0]}' [@ {result[1]}]"\
                             f"{' (' + str(result[2]) + 'x)' if result[2] > 1 else ''}"
                string_hits.append(string_hit)
            more = len(result_list[5:])
            if more:
                string_hits.append(f"{entry_name} x{more}")

        return string_hits

    def _extract_result_from_matches(self, matches):
        """
        Iterate through Yara match object and send to parser.

        Args:
            matches: Yara rules Match object (list).

        Returns:
            AL Result object.
        """
        result = Result()
        for match in matches:
            self._add_resultinfo_for_match(result, match)
        return result

    @staticmethod
    def _get_non_wide_char(string: str) -> str:
        """
        Convert wide string to regular string.

        Args:
            string: Wide-character string to convert.

        Returns:
            Converted string.
        """
        res = []
        for (i, c) in enumerate(string):
            if i % 2 == 0:
                res.append(str(c))

        return ''.join(res)

    @staticmethod
    def _is_wide_char(string):
        """
        Determine if string is a wide-character string.

        Args:
            string: Potential wide-character string.

        Returns:
            True if wide character, or False.
        """
        if len(string) >= 2 and len(string) % 2 == 0:
            is_wide_char = True
            for (i, c) in enumerate(string):
                if ((i % 2 == 0 and c == 0) or
                        (i % 2 == 1 and c != 0)):
                    is_wide_char = False
                    break
        else:
            is_wide_char = False

        return is_wide_char

    @staticmethod
    def _normalize_metadata(almeta):
        """Convert classification to uppercase."""
        almeta.classification = almeta.classification.upper()

    def _get_rules_hash(self):
        self.rules_list = [str(f) for f in Path(self.rules_directory).rglob("*") if os.path.isfile(str(f))]
        all_sha256s = [get_sha256_for_file(f) for f in self.rules_list]

        self.log.info(f"{self.name} will load the following rule files: {self.rules_list}")

        if len(all_sha256s) == 1:
            return all_sha256s[0][:7]

        return hashlib.sha256(' '.join(sorted(all_sha256s)).encode('utf-8')).hexdigest()[:7]

    def _load_rules(self):
        """
        Load Yara rules files. This function will check the updates directory and try to load the latest set of
        Yara rules files. If not successful, it will try older versions of the Yara rules files.
        """
        if not self.rules_list:
            raise Exception(f"No valid {self.name} rules files found")

        yar_files = {os.path.splitext(os.path.basename(yf))[0]: yf for yf in self.rules_list}

        if not yar_files:
            raise Exception(f"No valid {self.name} rules files found")

        rules = yara.compile(filepaths=yar_files, externals=self.yara_externals)

        if rules:
            with self.initialization_lock:
                self.rules = rules
                return
        raise Exception(f"No valid {self.name} rules files found")

    # noinspection PyBroadException
    def execute(self, request):
        """Main Module. See README for details."""
        if not self.rules:
            return

        request.set_service_context(f"{self.name} version: {self.get_tool_version()}")

        self.deep_scan = request.task.deep_scan
        local_filename = request.file_path
        tags = {f"al_{k.replace('.', '_')}": i for k, i in request.task.tags.items()}

        yara_externals = {}
        for k in self.yara_externals.keys():
            # Check default request.task fields
            sval = request.task.__dict__.get(k, None)

            # if not sval:
            #     # Check metadata dictionary
            #     sval = request.task.metadata.get(k, None)

            if not sval:
                # Check params dictionary
                sval = request.task.service_config.get(k, None)

            if not sval:
                # Check tags list
                val_list = tags.get(k, None)
                if val_list:
                    sval = " | ".join(val_list)

            if not sval:
                # Check temp submission data
                sval = request.task.temp_submission_data.get(k, None)

            # Normalize unicode with safe_str and make sure everything else is a string
            if sval:
                yara_externals[k] = safe_str(sval)

        with self.initialization_lock:
            try:
                matches = self.rules.match(local_filename, externals=yara_externals)
                request.result = self._extract_result_from_matches(matches)
            except Exception as e:
                # Internal error 30 == exceeded max string matches on rule
                if "internal error: 30" not in str(e):
                    raise
                else:
                    try:
                        # Fast mode == Yara skips strings already found
                        matches = self.rules.match(local_filename, externals=yara_externals, fast=True)
                        result = self._extract_result_from_matches(matches)
                        section = ResultSection("Service Warnings", parent=result)
                        section.add_line("Too many matches detected with current ruleset. "
                                         f"{self.name} forced to scan in fast mode.")
                        request.result = result
                    except Exception:
                        self.log.warning(f"YARA internal error 30 detected on submission {request.task.sid}")
                        result = Result()
                        section = ResultSection(f"{self.name} scan not completed.", parent=result)
                        section.add_line("File returned too many matches with current rule set and YARA exited.")
                        request.result = result

    def get_tool_version(self):
        """
        Return the version of yara used for processing
        :return:
        """
        return yara.YARA_VERSION

    def get_service_version(self):
        basic_version = super().get_service_version()
        if self.rules_hash and self.rules_hash not in basic_version:
            return f'{basic_version}.r{self.rules_hash}'
        else:
            return basic_version

    def start(self):
        # Set configuration flags to 4 times the default
        yara.set_config(max_strings_per_rule=40000, stack_size=65536)

        try:
            # Load the rules
            self._update_rules()
        except Exception as e:
            raise Exception(f"Something went wrong while trying to load {self.name} rules: {str(e)}")

        self.log.info(f"{self.name} started with service version: {self.get_service_version()}")

    def _cleanup(self) -> None:
        super()._cleanup()
        try: 
            self._update_rules()
        except Exception as e:
            raise Exception(f"Something went wrong while trying to load {self.name} rules: {str(e)}")
