import json
import os
import threading
from typing import List

import yara

from assemblyline.common.str_utils import safe_str
from assemblyline.odm.models.ontology.results import Signature
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.result import Heuristic, Result, ResultSection, BODY_FORMAT
from yara_.helper import YaraMetadata, YARA_EXTERNALS


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

    def __init__(self, config=None, externals=None):
        super().__init__(config)

        if externals is None:
            externals = YARA_EXTERNALS

        self.initialization_lock = threading.RLock()
        self.deep_scan = None
        self.sha256 = None

        # Load externals
        self.yara_externals = {f'al_{x.replace(".", "_")}': "" for x in externals}

        # Set configuration flags to 4 times the default
        yara.set_config(max_strings_per_rule=40000, stack_size=65536)

    def start(self):
        self.log.info(f"{self.name} started with service version: {self.get_service_version()}")

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
        actors = []
        attacks = []
        malware_families = []

        if almeta.mitre_att:
            attacks = almeta.mitre_att if isinstance(almeta.mitre_att, list) else [almeta.mitre_att]

        section = ResultSection('', classification=almeta.classification)
        # Allow the al_score meta in a YARA rule to override default scoring
        sig = f'{match.namespace}.{match.rule}'
        score_map = {sig: almeta.al_score} if almeta.al_score else None
        heur = Heuristic(self.YARA_HEURISTICS_MAP.get(almeta.category, 1), score_map=score_map)

        # Barebones of YARA signature ontology
        ont_data = {'type': 'YARA', 'name': sig, 'attributes': [{'file_hash': self.sha256}]}

        if self.deep_scan or almeta.al_status != "NOISY":
            section.set_heuristic(heur, signature=sig, attack_id=almeta.mitre_att)
        section.add_tag(f'file.rule.{self.name.lower()}', sig)

        title_elements = [f"[{match.namespace}] {match.rule}", ]

        if almeta.actor_type:
            actors.append(almeta.actor_type)

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
                malware_families.append(implant_family)
        if implant_title_elements:
            title_elements.append(f"- Implant(s): {', '.join(implant_title_elements)}")

        # Threat Actor metadata
        title_elements.extend(almeta.actors)
        actors.extend(almeta.actors)

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

        [section.add_tag('attribution.actor', actor) for actor in actors]

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

        # Update Signature ontology data and append to collection
        ont_data.update(dict(attack=attacks or None, actor=actors or None, malware_family=malware_families or None))
        self.ontology.add_result_part(Signature, ont_data)
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

    def _load_rules(self) -> None:
        """
        Load Yara rules files. This function will check the updates directory and try to load the latest set of
        Yara rules files. If not successful, it will try older versions of the Yara rules files.
        """
        try:
            rules = yara.compile(filepaths={os.path.splitext(os.path.basename(yf))[0]: yf for yf in self.rules_list},
                                 externals=self.yara_externals)

            if rules:
                with self.initialization_lock:
                    self.rules = rules
            else:
                raise Exception("yara.compile() didn't output any rules. Check if service can reach the updater.")
        except Exception as e:
            raise Exception(f"No valid {self.name} rules files found. Reason: {e}")

    # noinspection PyBroadException
    def execute(self, request):
        """Main Module. See README for details."""
        if not self.rules:
            return

        self.sha256 = request.sha256

        request.set_service_context(f"{self.name} version: {self.get_yara_version()}")

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
                matches = self.rules.match(local_filename, externals=yara_externals, allow_duplicate_metadata=True)
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
        self.sha256 = None

    def get_yara_version(self):
        return yara.YARA_VERSION

    def get_tool_version(self):
        """
        Return the version of yara used for processing
        :return:
        """
        return f'{self.get_yara_version()}.r{self.rules_hash}'
