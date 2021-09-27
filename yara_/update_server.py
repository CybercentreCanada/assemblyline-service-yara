from __future__ import annotations
import logging
import os
import re
import tempfile
import time
from typing import Any, Optional

from assemblyline.common import forge
from assemblyline.common.digests import get_sha256_for_file
from assemblyline.common import log as al_log
from assemblyline.odm.models.service import Service, UpdateSource
from assemblyline_v4_service.updater.updater import ServiceUpdater, temporary_api_key
from assemblyline_v4_service.updater.helper import git_clone_repo, url_download, SkipSource

from assemblyline_client import get_client
from plyara import Plyara, utils

from yara_.yara_importer import YaraImporter
from yara_.yara_validator import YaraValidator

al_log.init_logging('updater.yara', log_level=os.environ.get('LOG_LEVEL', "WARNING"))
LOGGER = logging.getLogger('assemblyline.updater.yara')

classification = forge.get_classification()

UI_SERVER = os.getenv('UI_SERVER', 'https://nginx')

YARA_EXTERNALS = {f'al_{x}': x for x in ['submitter', 'mime', 'tag']}


def _compile_rules(rules_file, externals, logger: logging.Logger):
    """
    Saves Yara rule content to file, validates the content with Yara Validator, and uses Yara python to compile
    the rule set.

    Args:
        rules_file: Yara rule file content.

    Returns:
        Compiled rules, compiled rules md5.
    """
    try:
        validate = YaraValidator(externals=externals, logger=logger)
        validate.validate_rules(rules_file)
    except Exception as e:
        raise e
    return True


def guess_category(rule_file_name: str) -> Optional[str]:
    cat_map = {
        "technique": ["antidebug", "antivm", "capabilities"],
        "info": ["info", "deprecated", "crypto", "packer"],
        "tool": ["webshell"],
        "exploit": ["cve", "exploit"],
        "malware": ["malware", "maldoc", "implant"]
    }

    for cat, items in cat_map.items():
        for item in items:
            if item in rule_file_name:
                return cat

    return None


def replace_include(include, dirname, processed_files: set[str], cur_logger: logging.Logger):
    include_path = re.match(r"include [\'\"](.{4,})[\'\"]", include).group(1)
    full_include_path = os.path.normpath(os.path.join(dirname, include_path))
    if not os.path.exists(full_include_path):
        cur_logger.info(f"File doesn't exist: {full_include_path}")
        return [], processed_files

    temp_lines = ['\n']  # Start with a new line to separate rules
    if full_include_path not in processed_files:
        processed_files.add(full_include_path)
        with open(full_include_path, 'r') as include_f:
            lines = include_f.readlines()

        for i, line in enumerate(lines):
            if line.startswith("include"):
                new_dirname = os.path.dirname(full_include_path)
                lines, processed_files = replace_include(line, new_dirname, processed_files, cur_logger)
                temp_lines.extend(lines)
            else:
                temp_lines.append(line)

    return temp_lines, processed_files


class YaraUpdateServer(ServiceUpdater):
    def __init__(self, *args, updater_type: str, externals: dict[str, str], **kwargs):
        super().__init__(*args, **kwargs)
        self.updater_type = updater_type
        self.externals = externals

    def do_source_update(self, service: Service) -> None:
        self.log.info(f"Connecting to Assemblyline API: {UI_SERVER}...")
        run_time = time.time()
        username = self.ensure_service_account()
        with temporary_api_key(self.datastore, username) as api_key:
            al_client = get_client(UI_SERVER, apikey=(username, api_key), verify=False)
            old_update_time = self.get_source_update_time()

            self.log.info("Connected!")

            # Parse updater configuration
            previous_hashes: dict[str, str] = self.get_source_extra()
            sources: dict[str, UpdateSource] = {_s['name']: _s for _s in service.update_config.sources}
            files_sha256: dict[str, str] = {}
            changed_files: list[str] = []
            files_default_classification = {}

            # Go through each source and download file
            with tempfile.TemporaryDirectory() as updater_working_dir:
                with tempfile.TemporaryDirectory() as download_directory:
                    for source_name, source_obj in sources.items():
                        source = source_obj.as_primitives()
                        os.makedirs(os.path.join(updater_working_dir, source_name))
                        # 1. Download signatures
                        self.log.info(f"Downloading files from: {source['uri']}")
                        uri: str = source['uri']
                        cache_name = f"{source_name}.yar"

                        try:
                            if uri.endswith('.git'):
                                files = git_clone_repo(source, old_update_time, "*.yar*", self.log, download_directory)
                            else:
                                files = url_download(source, old_update_time, self.log, download_directory)
                        except SkipSource:
                            if cache_name in previous_hashes:
                                files_sha256[cache_name] = previous_hashes[cache_name]
                            continue

                        processed_files: set[str] = set()

                        # 2. Aggregate files
                        file_name = os.path.join(updater_working_dir, cache_name)
                        mode = "w"
                        for file, _ in files:
                            # File has already been processed before, skip it to avoid duplication of rules
                            if file in processed_files:
                                continue

                            self.log.info(f"Processing file: {file}")

                            file_dirname = os.path.dirname(file)
                            processed_files.add(os.path.normpath(file))
                            with open(file, 'r') as f:
                                f_lines = f.readlines()

                            temp_lines: list[str] = []
                            for _, f_line in enumerate(f_lines):
                                if f_line.startswith("include"):
                                    lines, processed_files = replace_include(
                                        f_line, file_dirname, processed_files, self.log)
                                    temp_lines.extend(lines)
                                else:
                                    temp_lines.append(f_line)

                            # guess the type of files that we have in the current file
                            guessed_category = guess_category(file)
                            parser = Plyara()
                            # Try parsing the ruleset; on fail, move onto next set
                            try:
                                signatures: list[dict[str, Any]] = parser.parse_string("\n".join(temp_lines))

                                # Ignore "cuckoo" rules
                                if "cuckoo" in parser.imports:
                                    parser.imports.remove("cuckoo")

                                # Guess category
                                if guessed_category:
                                    for s in signatures:
                                        s.setdefault('metadata', [])

                                        # Do not override category with guessed category if it already exists
                                        for meta in s['metadata']:
                                            if 'category' in meta:
                                                continue

                                        s['metadata'].append({'category': guessed_category})
                                        s['metadata'].append({guessed_category: s.get('rule_name')})

                                # Save all rules from source into single file
                                with open(file_name, mode) as f:
                                    for s in signatures:
                                        # Fix imports and remove cuckoo
                                        s['imports'] = utils.detect_imports(s)
                                        if "cuckoo" not in s['imports']:
                                            f.write(utils.rebuild_yara_rule(s))

                                if mode == "w":
                                    mode = "a"
                            except Exception as e:
                                self.log.error(f"Problem parsing {file}: {e}")
                                continue

                        # Check if the file is the same as the last run
                        if os.path.exists(file_name):
                            sha256 = get_sha256_for_file(file_name)
                            if sha256 != previous_hashes.get(cache_name, None):
                                files_sha256[cache_name] = sha256
                                changed_files.append(cache_name)
                                files_default_classification[cache_name] = source.get(
                                    'default_classification', classification.UNRESTRICTED)
                            else:
                                self.log.info(f'File {cache_name} has not changed since last run. Skipping it...')

                    if changed_files:
                        self.log.info(f"Found new {self.updater_type.upper()} rules files to process!")

                        yara_importer = YaraImporter(self.updater_type, al_client, logger=self.log)

                        # Validating and importing the different signatures
                        for base_file in changed_files:
                            self.log.info(f"Validating output file: {base_file}")
                            cur_file = os.path.join(updater_working_dir, base_file)
                            source_name = os.path.splitext(os.path.basename(cur_file))[0]
                            default_classification = files_default_classification.get(
                                base_file, classification.UNRESTRICTED)

                            try:
                                _compile_rules(cur_file, self.externals, self.log)
                                yara_importer.import_file(cur_file, source_name,
                                                          default_classification=default_classification)
                            except Exception as e:
                                raise e
                    else:
                        self.log.info(f'No new {self.updater_type.upper()} rules files to process...')

        self.set_source_update_time(run_time)
        self.set_source_extra(files_sha256)
        self.set_active_config_hash(self.config_hash(service))
        self.local_update_flag.set()


if __name__ == '__main__':
    with YaraUpdateServer(updater_type='yara', externals=YARA_EXTERNALS, logger=LOGGER) as server:
        server.serve_forever()
