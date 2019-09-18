# from __future__ import absolute_import

import hashlib
import os
import shutil
import tempfile
import threading
from io import StringIO

import yara
from assemblyline.al.common.transport.local import TransportLocal
from assemblyline.common.yara.YaraValidator import YaraValidator
from assemblyline_client import Client

from assemblyline.common.exceptions import ConfigException
from assemblyline.common.isotime import now_as_iso
from assemblyline.common.str_utils import safe_str
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.result import Result, ResultSection


class YaraMetadata(object):
    def __init__(self, match):
        meta = match.meta
        self.rule_name = match.rule
        self.rule_id = match.meta.get('id', None)
        self.rule_group = match.meta.get('rule_group', None)
        self.rule_version = match.meta.get('rule_version', 1)
        self.description = match.meta.get('description', None)
        self.classification = match.meta.get('classification', Classification.UNRESTRICTED)
        self.organisation = meta.get('organisation', None)
        self.summary = meta.get('summary', None)
        self.description = meta.get('description', None)
        self.score_override = meta.get('al_score', None)
        self.poc = meta.get('poc', None)
        self.weight = meta.get('weight', 0)  # legacy rule format
        self.al_status = meta.get('al_status', "DEPLOYED")

        self.ta_type = meta.get('ta_type', None)

        def _safe_split(comma_sep_list):
            return [e for e in comma_sep_list.split(',') if e]

        self.actors = _safe_split(match.meta.get('used_by', ''))
        self.summary = _safe_split(match.meta.get('summary', ''))
        self.exploits = _safe_split(match.meta.get('exploit', ''))

        # parse and populate implant list
        self.implants = []
        for implant in match.meta.get('implant', '').split(','):
            if not implant:
                continue
            tokens = implant.split(':')
            implant_name = tokens[0]
            implant_family = tokens[1] if (len(tokens) == 2) else ''
            self.implants.append((implant_name.strip().upper(),
                                  implant_family.strip().upper()))

        # parse and populate technique info
        self.techniques = []
        for technique in meta.get('technique', '').split(','):
            if not technique:
                continue
            tokens = technique.split(':')
            category = ''
            if len(tokens) == 2:
                category = tokens[0]
                name = tokens[1]
            else:
                name = tokens[0]
            self.techniques.append((category.strip(), name.strip()))

        self.info = []
        for info in meta.get('info', '').split(','):
            if not info:
                continue
            tokens = info.split(':', 1)
            if len(tokens) == 2:
                # category, value
                self.info.append((tokens[0], tokens[1]))
            else:
                self.info.append((None, tokens[0]))


NUM_RULES = 'yara.num_rules'
RULE_HITS = 'yara.total_rule_hits'


class Yara(ServiceBase):

    YARA_SCORE_MAP = {
        'implant': 1000,
        'tool': 500,
        'exploit': 500,
        'technique': 100,
        'info': 0,
    }

    TYPE = 0
    DESCRIPTION = 1
    TECHNIQUE_DESCRIPTORS = dict(
        shellcode=('technique.shellcode', 'Embedded shellcode'),
        packer=('technique.packer', 'Packed PE'),
        cryptography=('technique.crypto', 'Uses cryptography/compression'),
        obfuscation=('technique.obfuscation', 'Obfuscated'),
        keylogger=('technique.keylogger', 'Keylogging capability'),
        comms_routine=('technique.comms_routine', 'Does external comms'),
        persistance=('technique.persistence', 'Has persistence'),
    )

    def __init__(self, config=None):
        super(Yara, self).__init__(config)
        self.last_update = "1970-01-01T00:00:00.000000Z"
        self.rules = None
        self.rules_md5 = None
        self.initialization_lock = threading.RLock()
        self.signature_cache = TransportLocal(
            base=os.path.join(config.system.root, 'var', 'cache', 'signatures')
        )
        self.task = None

        self.rule_path = self.config.get('RULE_PATH', 'rules.yar')
        self.signature_user = self.config.get('SIGNATURE_USER')
        self.signature_pass = self.config.get('SIGNATURE_PASS')
        self.signature_url = self.config.get('SIGNATURE_URL', 'https://localhost:443')
        self.signature_query = self.config.get('SIGNATURE_QUERY',
                                               'meta.al_status:DEPLOYED OR '
                                               'meta.al_status:NOISY')
        self.verify = self.config.get('VERIFY', False)
        self.get_yara_externals = {"al_%s" % i: i for i in config.system.yara.externals}
        self.update_client = None
        self.yara_version = "3.8.1"

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

        if not self.task.deep_scan and almeta.al_status == "NOISY":
            almeta.score_override = 0

        # determine an overall score for this match
        score = self.YARA_SCORE_MAP.get(almeta.rule_group, 0)
        if almeta.implants:
            score = max(score, 500)
        if almeta.actors:
            score = max(score, 500)
        if almeta.score_override is not None:
            score = int(almeta.score_override)

        section = ResultSection('', score=score, classification=almeta.classification)

        section.add_tag('file.rule.yara', match.rule)

        title_elements = [match.rule, ]

        if almeta.ta_type:
            section.add_tag('attribution.actor', almeta.ta_type)

        # Implant Tags
        implant_title_elements = []
        for (implant_name, implant_family) in almeta.implants:
            if implant_name:
                implant_title_elements.append(implant_name)
                section.add_tag('attribution.implant', implant_name)
            if implant_family:
                implant_title_elements.append(implant_family)
                section.add_tag('attribution.family', implant_family)
        if implant_title_elements:
            title_elements.append(f"implant: {','.join(implant_title_elements)}")

        # Threat Actor metadata
        for actor in almeta.actors:
            title_elements.append(actor)
            section.add_tag('attribution.actor', actor)

        # Exploit / CVE metadata
        if almeta.exploits:
            title_elements.append(f" [Exploits(s): {','.join(almeta.exploits)}] ")
        for exploit in almeta.exploits:
            section.add_tag('attribution.exploit', exploit)

        # Include technique descriptions in the section summary
        summary_elements = set()
        for (category, name) in almeta.techniques:
            descriptor = self.TECHNIQUE_DESCRIPTORS.get(category, None)
            if not descriptor:
                continue
            technique_type, technique_description = descriptor
            section.add_tag(technique_type, name)
            summary_elements.add(technique_description)

        for (category, value) in almeta.info:
            if category == 'compiler':
                section.add_tag('file.compiler', value)
            elif category == 'libs':
                section.add_tag('file.lib', value)

        if summary_elements:
            title_elements.append(f" (Summary: {', '.join(summary_elements)})")
        for element in summary_elements:
            section.add_tag('file.behavior', element)

        title = " ".join(title_elements)
        section.title_text = title

        if almeta.rule_id and almeta.rule_version and almeta.poc:
            section.add_line(f"Rule Info : {almeta.rule_id} r.{almeta.rule_version} by {almeta.poc}")

        if almeta.description:
            section.add_line(f"Description: {almeta.description}")

        self._add_string_match_data(match, section)

        result.add_section(section)
        # result.order_results_by_score() TODO: should v4 support this?

    def _add_string_match_data(self, match, section: ResultSection) -> None:
        """
        Parses and adds matching strings from a Yara match object to an AL ResultSection.

        Args:
            match: Yara match object.
            section: AL ResultSection object.

        Returns:
            None.
        """
        strings = match.strings
        string_dict = {}
        for offset, identifier, data in strings:
            if data not in string_dict:
                string_dict[data] = []
            string_dict[data].append((offset, identifier))

        result_dict = {}
        for string_value, string_list in string_dict.items():
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

            string_hit = f"Found {entry_name} string: '{string_value} [@ {string_offset}]" \
                         f"{' (' + str(count) + 'x)' if count > 1 else ''}'"
            section.add_line(string_hit)

        for entry_name, result_list in result_dict.items():
            for result in result_list[:5]:
                string_hit = f"Found {entry_name} string: '{result[0]}' [@ {result[1]}]"\
                             f"{' (' + str(result[2]) + 'x)' if result[2] > 1 else ''}"
                section.add_line(string_hit)
            more = len(result_list[5:])
            if more:
                section.add_line(f"Found {entry_name} string {more} more time{'s' if more > 1 else ''}")

    def _compile_rules(self, rules_txt):
        """
        Saves Yara rule content to file, validates the content with Yara Validator, and uses Yara python to compile
        the rule set.

        Args:
            rules_txt: Yara rule file content.

        Returns:
            Last update time, compiled rules, compiled rules md5.
        """
        tmp_dir = tempfile.mkdtemp(dir='/tmp')
        try:
            # Extract the first line of the rules which should look like this:
            # // Signatures last updated: LAST_UPDATE_IN_ISO_FORMAT
            first_line, clean_data = rules_txt.split('\n', 1)
            prefix = '// Signatures last updated: '

            if first_line.startswith(prefix):
                last_update = first_line.replace(prefix, '')
            else:
                self.log.warning(f"Couldn't read last update time from {rules_txt[:40]}")
                last_update = now_as_iso()
                clean_data = rules_txt

            rules_file = os.path.join(tmp_dir, 'rules.yar')
            with open(rules_file, 'w') as f:
                f.write(rules_txt)
            try:
                validate = YaraValidator(externals=self.get_yara_externals, logger=self.log)
                edited = validate.validate_rules(rules_file, datastore=True)
            except Exception as e:
                raise e
            # Grab the final output if Yara Validator found problem rules
            if edited:
                with open(rules_file, 'r') as f:
                    sdata = f.read()
                first_line, clean_data = sdata.split('\n', 1)
                if first_line.startswith(prefix):
                    last_update = first_line.replace(prefix, '')
                else:
                    last_update = now_as_iso()
                    clean_data = sdata

            rules = yara.compile(rules_file, externals=self.get_yara_externals)
            rules_md5 = hashlib.md5(clean_data).hexdigest()
            return last_update, rules, rules_md5
        except Exception as e:
            raise e
        finally:
            shutil.rmtree(tmp_dir)

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
                res.append(c)

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
                if ((i % 2 == 0 and ord(c) == 0) or
                        (i % 2 == 1 and ord(c) != 0)):
                    is_wide_char = False
                    break
        else:
            is_wide_char = False

        return is_wide_char

    @staticmethod
    def _normalize_metadata(almeta):
        """Convert classification to uppercase."""
        almeta.classification = almeta.classification.upper()

    def _update_rules(self, **_):
        """
        Update yara rules file. This module will use the AL client to see if the signature set in datastore has been
        modified since self.last_update. If there is an update available, the new signature set will be downloaded
        and saved to a new rules cache file.
        """
        self.log.info("Starting Yara's rule updater...")

        if not self.update_client:
            try:
                # AL_Client 3.4+
                self.update_client = Client(self.signature_url,
                                            auth=(self.signature_user, self.signature_pass),
                                            verify=self.verify)
            except TypeError:
                # AL_Client 3.3-
                self.update_client = Client(self.signature_url, auth=(self.signature_user, self.signature_pass))

        if self.signature_cache.exists(self.rule_path):
            api_response = self.update_client.signature.update_available(self.last_update)
            update_available = api_response.get('update_available', False)
            if not update_available:
                self.log.info("No update available. Stopping...")
                return

        self.log.info(f"Downloading signatures with query: {self.signature_query} ({str(self.last_update)})")

        signature_data = StringIO()
        self.update_client.signature.download(output=signature_data, query=self.signature_query, safe=True)

        rules_txt = signature_data.getvalue()
        if not rules_txt:
            errormsg = f"No rules to compile:\n{rules_txt}"
            self.log.error("{}/api/v3/signature/download/?query={} - {}:{}".format(
                self.signature_url, self.signature_query, self.signature_user, self.signature_pass)
            )
            self.log.error(errormsg)
            raise ConfigException(errormsg)

        self.signature_cache.save(self.rule_path, rules_txt)

        last_update, rules, rules_md5 = self._compile_rules(rules_txt)
        if rules:
            with self.initialization_lock:
                self.last_update = last_update
                self.rules = rules
                self.rules_md5 = rules_md5

    # noinspection PyBroadException
    def execute(self, request):
        """Main Module. See README for details."""
        if not self.rules:
            return

        self.task = request.task
        local_filename = request.file_path

        yara_externals = {}
        for k, i in self.get_yara_externals.items():
            # Check default request.task fields
            try:
                sval = self.task.get(i)
            except Exception:
                sval = None
            if not sval:
                # Check metadata dictionary
                smeta = self.task.metadata
                if isinstance(smeta, dict):
                    sval = smeta.get(i, None)
            if not sval:
                # Check params dictionary
                smeta = self.task.params
                if isinstance(smeta, dict):
                    sval = smeta.get(i, None)
            # Create dummy value if item not found
            if not sval:
                sval = i

            # Normalize unicode with safe_str and make sure everything else is a string
            yara_externals[k] = str(safe_str(sval))

        with self.initialization_lock:
            try:
                matches = self.rules.match(local_filename, externals=yara_externals)
                self.counters[RULE_HITS] += len(matches)
                request.result = self._extract_result_from_matches(matches)
            except Exception as e:
                # Internal error 30 == exceeded max string matches on rule
                if e.message != "internal error: 30":
                    raise
                else:
                    try:
                        # Fast mode == Yara skips strings already found
                        matches = self.rules.match(local_filename, externals=yara_externals, fast=True)
                        self.counters[RULE_HITS] += len(matches)
                        result = self._extract_result_from_matches(matches)
                        section = ResultSection(title_text="Service Warnings")
                        section.add_line("Too many matches detected with current ruleset. "
                                         "Yara forced to scan in fast mode.")
                        request.result = result
                        result.add_result(section)

                    except:
                        self.log.warning(f"Yara internal error 30 detected on submission {self.task.sid}")
                        section = ResultSection(title_text="Yara scan not completed.")
                        section.add_line("File returned too many matches with current rule set and Yara exited.")
                        result = Result()
                        request.result = result
                        result.add_result(section)

    def get_service_version(self):
        basic_version = super(Yara, self).get_service_version()
        return f'{basic_version}.r{self.rules_md5 or "0"}'

    def start(self):
        # Set configuration flags to 4 times the default
        yara.set_config(max_strings_per_rule=40000, stack_size=65536)

        force_rule_download = False
        try:
            # Even if we are using riak for rules we may have a saved copy
            # of the rules. Try to load and compile them first.
            self.signature_cache.makedirs(os.path.dirname(self.rule_path))
            rules_txt = self.signature_cache.get(self.rule_path)
            if rules_txt:
                self.log.info(f"Yara loaded rules from cached file: {self.rule_path}")
                self.last_update, self.rules, self.rules_md5 = \
                    self._compile_rules(rules_txt)
            else:
                self.log.info("No cached Yara rules found.")
                force_rule_download = True

        except Exception as e:
            self.log.warning(f"Something went wrong while trying to load cached rules: {e}")
            force_rule_download = True

        self.log.info(f"Yara started with service version: {self.get_service_version()}")
