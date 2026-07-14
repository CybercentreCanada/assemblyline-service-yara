import json
import os
from collections import defaultdict
from typing import Dict, List

import yara_x
from assemblyline.common.attack_map import attack_map, software_map
from assemblyline.common.str_utils import safe_str
from assemblyline.odm.models.ontology.results import Signature
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import (
    BODY_FORMAT,
    Heuristic,
    Result,
    ResultSection,
)

from yara_.helper import YARA_EXTERNALS, YaraMetadata, YaraValidator, externals_to_dict


class Yara(ServiceBase):
    TECHNIQUE_DESCRIPTORS = dict(
        shellcode=("technique.shellcode", "Embedded shellcode"),
        packer=("technique.packer", "Packed PE"),
        cryptography=("technique.crypto", "Uses cryptography/compression"),
        obfuscation=("technique.obfuscation", "Obfuscated"),
        keylogger=("technique.keylogger", "Keylogging capability"),
        comms_routine=("technique.comms_routine", "Does external comms"),
        persistance=("technique.persistence", "Has persistence"),
    )

    INFO_DESCRIPTORS = dict(
        compiler=("file.compiler", "Compiled with known compiler"),
        libs=("file.lib", "Using known library"),
        lib=("file.lib", "Using known library"),
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

        # Load externals
        self.yara_externals = externals_to_dict(externals)

        # Read relaxed_re_syntax config (default True for smooth upgrade from yara-python)
        self.relaxed_re_syntax = self.config.get("relaxed_re_syntax", True)

    def start(self):
        self.log.info(f"{self.name} started with service version: {self.get_service_version()}")

    def _add_resultinfo_for_match(self, request: ServiceRequest, result: Result, match, file_data: bytes = b""):
        """
        Parse from Yara signature match and add information to the overall AL service result. This module determines
        result score and identifies any AL tags that should be added (i.e. IMPLANT_NAME, THREAT_ACTOR, etc.).

        Args:
            request: ServiceRequest object.
            result: AL ResultSection object.
            match: Yara rules Match object item.
            file_data: Raw bytes of the scanned file (used to extract string match content).

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

        # The signature metakey should be the derived signature ID of parsing the match
        sig_meta_key = almeta.id
        signature_meta = self.signatures_meta[f"{match.namespace}.{sig_meta_key}"]

        section = ResultSection("", classification=signature_meta["classification"])
        # Allow the al_score meta in a YARA rule to override default scoring
        sig = f"{match.namespace}.{match.identifier}"
        try:
            if almeta.al_score is None:
                score_map = None
            else:
                score_map = {sig: int(almeta.al_score)}
        except ValueError:
            self.log.error(f"Invalid al_score value on rule '{sig}': {almeta.al_score}. Continuing without override..")
            score_map = None

        # If there's multiple categories, assign the highest for scoring
        heur = Heuristic(1, score_map=score_map)
        if isinstance(almeta.category, list):
            for category in almeta.category:
                category = category.lower()
                if Heuristic(self.YARA_HEURISTICS_MAP.get(category, 1)).score > heur.score:
                    heur = Heuristic(self.YARA_HEURISTICS_MAP.get(category, 1), score_map=score_map)
        elif isinstance(almeta.category, str):
            heur = Heuristic(self.YARA_HEURISTICS_MAP.get(almeta.category.lower(), 1), score_map=score_map)
        elif any(
            [
                term.lower().startswith("susp") or term.lower().startswith("hunting")
                for term in almeta.name.split("_") + list(match.tags)
            ]
        ):
            # If the rule name indicates suspiciousness about the match, then score accordingly
            heur = Heuristic(17, score_map=score_map)

        # Skeleton of YARA signature ontology
        ont_data = {
            "type": "YARA",
            "name": sig,
            "attributes": [
                {
                    "file_hash": request.sha256,
                    "source": {
                        "tag": sig,
                        "service_name": self.__class__.__name__,
                    },
                }
            ],
            "signature_id": sig_meta_key,
            "classification": signature_meta["classification"],
        }

        ont_data["attributes"][0]["source"]["ontology_id"] = Signature.get_oid(ont_data)

        if request.deep_scan or signature_meta["status"] != "NOISY":
            heur.add_signature_id(sig)
            [heur.add_attack_id(attack_id=attack_id) for attack_id in attacks]
            section.set_heuristic(heur)
        section.add_tag(f"file.rule.{self.name.lower()}", sig)

        title_elements = [
            f"[{match.namespace}] {match.identifier}",
        ]

        if almeta.actor_type:
            actors.append(almeta.actor_type)

        for tag in almeta.tags:
            section.add_tag(tag["type"], tag["value"])

        # Malware Tags
        implant_title_elements = []
        for implant_name, implant_family in almeta.malwares:
            if implant_name:
                implant_title_elements.append(implant_name)
                section.add_tag("attribution.implant", implant_name)
            if implant_family:
                implant_title_elements.append(implant_family)
                section.add_tag("attribution.family", implant_family)
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
            section.add_tag("attribution.exploit", exploit)

        # Include technique descriptions in the section behavior
        for category, name in almeta.techniques:
            descriptor = self.TECHNIQUE_DESCRIPTORS.get(category, None)
            if descriptor:
                technique_type, technique_description = descriptor
                section.add_tag(technique_type, name)
                almeta.behavior.add(technique_description)

        for category, name in almeta.infos:
            descriptor = self.INFO_DESCRIPTORS.get(category, None)
            if descriptor:
                info_type, info_description = descriptor
                section.add_tag(info_type, name)
                almeta.behavior.add(info_description)

        # Summaries
        if almeta.behavior:
            title_elements.append(f"- Behavior: {', '.join(almeta.behavior)}")
        for element in almeta.behavior:
            section.add_tag("file.behavior", element)

        [section.add_tag("attribution.actor", actor) for actor in actors]

        title = " ".join(title_elements)
        section.title_text = title

        json_body = dict(
            name=match.identifier,
        )

        for item in [
            "id",
            "version",
            "author",
            "description",
            "source",
            "malware",
            "info",
            "technique",
            "tool",
            "exploit",
            "actor",
            "category",
            "mitre_att",
        ]:
            val = almeta.__dict__.get(item, None)
            if val:
                json_body[item] = val

        section.set_body(json.dumps(json_body), body_format=BODY_FORMAT.KEY_VALUE)

        string_match_data = self._add_string_match_data(match, file_data)
        if string_match_data:
            string_section = ResultSection(
                "String Matches",
                classification=signature_meta["classification"],
                body=json.dumps(string_match_data),
                body_format=BODY_FORMAT.KEY_VALUE,
            )
            section.add_subsection(string_section)

        # Update Signature ontology data and append to collection
        ont_attacks = []
        for attack_id in attacks:
            attack = attack_map.get(attack_id)
            software = software_map.get(attack_id)
            if attack:
                ont_attacks.append(
                    {"attack_id": attack["attack_id"], "pattern": attack["name"], "categories": attack["categories"]}
                )
            elif software:
                for att_id in software["attack_ids"]:
                    attack = attack_map.get(att_id)
                    if attack:
                        ont_attacks.append(
                            {
                                "attack_id": attack["attack_id"],
                                "pattern": attack["name"],
                                "categories": attack["categories"],
                            }
                        )
            else:
                self.log.warning(f"AttackID {attack_id} not known to Assemblyline.")
        ont_data.update(
            dict(attacks=ont_attacks or None, actors=actors or None, malware_families=malware_families or None)
        )
        self.ontology.add_result_part(Signature, ont_data)
        result.add_section(section)
        # result.order_results_by_score() TODO: should v4 support this?

    def _add_string_match_data(self, match, file_data: bytes = b"") -> Dict[str, str]:
        """
        Parses matching strings from a Yara match object into a key-value dict.

        Each key is the YARA string identifier (e.g. ``$str1`` or ``$str1 (wide)``),
        and each value is the matched content together with its file offset(s) and
        an optional hit-count.  When a single identifier matches multiple distinct
        byte sequences the entries are indexed (e.g. ``$str1[0]``, ``$str1[1]``).

        Args:
            match: Yara match object.
            file_data: Raw bytes of the scanned file, used to extract matched string content.

        Returns:
            Ordered dict mapping string identifier keys to formatted match strings.
        """
        # Map (identifier, matched_bytes) -> list of file offsets
        id_data_dict: Dict[tuple, list] = defaultdict(list)

        for pattern in match.patterns:
            identifier = pattern.identifier
            for m in pattern.matches:
                offset = m.offset
                matched_data = file_data[offset : offset + m.length] if file_data else b""
                id_data_dict[(identifier, matched_data)].append(offset)

        # Group formatted entries by their base key (identifier [+ wide flag])
        id_to_entries: Dict[str, list] = defaultdict(list)

        for (identifier, matched_data), offsets in id_data_dict.items():
            string_value = safe_str(matched_data) if isinstance(matched_data, bytes) else matched_data

            count = len(offsets)
            offset_strs = [hex(o) for o in offsets[:5]]
            offset_str = ", ".join(offset_strs)
            if count > 5:
                offset_str += "..."

            is_wide_char = self._is_wide_char(string_value)
            if is_wide_char:
                string_value = self._get_non_wide_char(string_value)

            string_value_repr = repr(string_value)
            if len(string_value_repr) > 100:
                string_value_repr = f"{string_value_repr[:100]}..."

            wide_str = " (wide)" if is_wide_char else ""
            base_key = "(anonymous)" + wide_str if identifier == "$" else identifier + wide_str

            entry_value = f"{string_value_repr} @ [{offset_str}]"
            if count > 1:
                entry_value += f" ({count}x)"

            id_to_entries[base_key].append(entry_value)

        # Flatten to a final {key: value} dict
        result: Dict[str, str] = {}
        for key, entries in id_to_entries.items():
            if len(entries) == 1:
                result[key] = entries[0]
            else:
                for i, entry in enumerate(entries[:5]):
                    result[f"{key}[{i}]"] = entry
                remaining = len(entries) - 5
                if remaining > 0:
                    result[f"{key}[...]"] = f"({remaining} more)"

        return result

    def _extract_result_from_matches(self, request: ServiceRequest, matches, file_data: bytes = b""):
        """
        Iterate through Yara match object and send to parser.

        Args:
            request: ServiceRequest object.
            matches: Yara rules Match object (list).
            file_data: Raw bytes of the scanned file.

        Returns:
            AL Result object.
        """
        result = Result()
        for match in matches:
            self._add_resultinfo_for_match(request, result, match, file_data)
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
        for i, c in enumerate(string):
            if i % 2 == 0:
                res.append(str(c))

        return "".join(res)

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
            for i, c in enumerate(string):
                if (i % 2 == 0 and c == 0) or (i % 2 == 1 and c != 0):
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
            # Validate rules using the validator
            self.rules_list = [yf for yf in self.rules_list if os.path.isfile(yf)]
            validator = YaraValidator(
                externals=self.yara_externals, logger=self.log, relaxed_re_syntax=self.relaxed_re_syntax
            )
            [validator.validate_rules(yf) for yf in self.rules_list]

            compiler = yara_x.Compiler(relaxed_re_syntax=self.relaxed_re_syntax)
            for k, v in self.yara_externals.items():
                compiler.define_global(k, v)
            for yf in self.rules_list:
                namespace = os.path.splitext(os.path.basename(yf))[0]
                compiler.new_namespace(namespace)
                with open(yf, "r", errors="surrogateescape") as f:
                    compiler.add_source(f.read())
            rules = compiler.build()

            if rules:
                self.rules = rules
            else:
                raise Exception("yara_x.Compiler.build() didn't output any rules. Check if service can reach the updater.")
        except Exception as e:
            raise Exception(f"No valid {self.name} rules files found. Reason: {e}")

    # noinspection PyBroadException
    def execute(self, request):
        """Main Module. See README for details."""
        if not self.rules:
            return

        request.set_service_context(f"yara-x version: {self.get_yara_version()}")

        tags = {f"al_{k.replace('.', '_')}": i for k, i in request.task.tags.items()}

        yara_externals = {}
        for k in self.yara_externals.keys():
            # Externals are always prepended with al_
            clean_key = k[3:]

            # Check default request.task fields
            sval = getattr(request.task, clean_key, None)

            # if not sval:
            #     # Check metadata dictionary
            #     sval = request.task.metadata.get(k, None)

            if not sval:
                # Check params dictionary
                sval = request.task.service_config.get(clean_key, None)

            if not sval:
                # Check tags list
                val_list = tags.get(k, None)
                if val_list:
                    sval = " | ".join(val_list)

            if not sval:
                # Check temp submission data
                sval = request.task.temp_submission_data.get(clean_key, None)

            # Normalize unicode with safe_str and make sure everything else is a string
            if sval:
                yara_externals[k] = safe_str(sval)

        # Assume no file data by default for TagCheck compatibility
        file_data = b""

        # If the service is YARA, read the file data for scanning
        if self.name == "yara":
            with open(request.file_path, "rb") as f:
                file_data = f.read()

        scanner = yara_x.Scanner(self.rules)
        # Set globals: start with defaults then override with request-specific values
        for k, v in self.yara_externals.items():
            scanner.set_global(k, v)
        for k, v in yara_externals.items():
            scanner.set_global(k, v)

        results = scanner.scan(file_data)
        request.result = self._extract_result_from_matches(request, results.matching_rules, file_data)

    def get_yara_version(self):
        from importlib.metadata import version as pkg_version
        return pkg_version("yara-x")

    def get_tool_version(self):
        """
        Return the version of yara used for processing
        :return:
        """
        return f"{self.get_yara_version()}.r{self.rules_hash}"
