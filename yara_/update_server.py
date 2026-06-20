from __future__ import annotations

import json
import logging
import os
import re
import shutil
import tarfile
import tempfile
import time
from typing import Any, Optional

from assemblyline.common import forge
from assemblyline_v4_service.updater.updater import (
    SIGNATURES_META_FILENAME,
    STATUS_FILE,
    UPDATER_DIR,
    ServiceUpdater,
)
from plyara import Plyara, utils

from yara_.helper import YARA_EXTERNALS, YaraImporter, YaraValidator, externals_to_dict

classification = forge.get_classification()


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
        "malware": ["malware", "maldoc", "implant"],
    }

    for cat, items in cat_map.items():
        for item in items:
            if item in rule_file_name:
                return cat

    return None


def replace_include(include, dirname, processed_files: set[str], cur_logger: logging.Logger):
    include_path = re.match(r"include [\'\"](.{4,})[\'\"]", include)
    if not include_path:
        return [], processed_files
    include_path = include_path.group(1)
    full_include_path = os.path.normpath(os.path.join(dirname, include_path))
    if not os.path.exists(full_include_path):
        cur_logger.info(f"File doesn't exist: {full_include_path}")
        return [], processed_files

    temp_lines = ["\n"]  # Start with a new line to separate rules
    if full_include_path not in processed_files:
        processed_files.add(full_include_path)
        with open(full_include_path, "r") as include_f:
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
    externals = externals_to_dict(YARA_EXTERNALS)

    # A sanity check to make sure we do in fact have things to send to services
    def _inventory_check(self) -> bool:
        yara_validator = YaraValidator(externals=self.externals, logger=self.log)
        check_passed = False
        missing_sources = [_s.name for _s in self._service.update_config.sources]
        if not self._update_dir:
            return check_passed
        for root, dirs, files in os.walk(self._update_dir):
            # Walk through update directory (account for sources being nested)
            for path in dirs + files:
                remove_source = None
                for source in missing_sources:
                    if source in path:
                        # We have at least one source we can pass to the service for now
                        # BUT let's make sure this source can be compiled with yara
                        yara_validator.validate_rules(os.path.join(root, path), self.client)
                        remove_source = source
                        check_passed = True
                        break
                if remove_source:
                    missing_sources.remove(source)

            if not missing_sources:
                break

        if missing_sources:
            # If sources are missing, then clear caching from Redis and trigger source updates
            for source in missing_sources:
                self.set_source_update_time(source, 0)
            self.trigger_update()

        return check_passed

    def import_update(
        self, files_sha256, source_name: str, default_classification=classification.UNRESTRICTED, *args, **kwargs
    ):
        processed_files: set[str] = set()

        with tempfile.NamedTemporaryFile(mode="a+", suffix=source_name) as compiled_file:
            # Aggregate files into one major source file
            for file, _ in files_sha256:
                # File has already been processed before, skip it to avoid duplication of rules
                if file in processed_files:
                    continue

                self.log.info(f"Processing file: {file}")

                file_dirname = os.path.dirname(file)
                processed_files.add(os.path.normpath(file))
                with open(file, "r", errors="surrogateescape") as f:
                    f_lines = f.readlines()

                temp_lines: list[str] = []
                for _, f_line in enumerate(f_lines):
                    if f_line.startswith("include"):
                        lines, processed_files = replace_include(f_line, file_dirname, processed_files, self.log)
                        temp_lines.extend(lines)
                    else:
                        temp_lines.append(f_line)

                # guess the type of files that we have in the current file
                guessed_category = guess_category(file)
                parser = Plyara()
                parser.STRING_ESCAPE_CHARS.add("r")
                # Try parsing the ruleset; on fail, move onto next set
                try:
                    signatures: list[dict[str, Any]] = parser.parse_string("\n".join(temp_lines))

                    # Ignore "cuckoo" rules
                    if "cuckoo" in parser.imports:
                        parser.imports.remove("cuckoo")

                    # Guess category
                    if guessed_category:
                        for s in signatures:
                            s.setdefault("metadata", [])

                            # Do not override category with guessed category if it already exists
                            for meta in s["metadata"]:
                                if "category" in meta:
                                    continue

                            s["metadata"].append({"category": guessed_category})
                            s["metadata"].append({guessed_category: s.get("rule_name")})

                    # Save all rules from source into single file
                    for s in signatures:
                        # Fix imports and remove cuckoo
                        s["imports"] = utils.detect_imports(s)
                        if "cuckoo" not in s["imports"]:
                            compiled_file.write(utils.rebuild_yara_rule(s))
                except Exception as e:
                    self.log.error(f"Problem parsing {file}: {e}")
                    continue
            yara_importer = YaraImporter(self.updater_type, self.client, logger=self.log)
            try:
                compiled_file.seek(0)
                _compile_rules(compiled_file.name, self.externals, self.log)
                yara_importer.import_file(
                    compiled_file.name, source_name, default_classification=default_classification
                )
            except Exception as e:
                raise e

    def serve_directory(self, new_directory: str, new_time: str):
        self.log.info("Update finished with new data.")
        new_tar = ''

        # Before serving directory, let's maintain a map of the different signatures and their current deployment state
        # This map allows the service to be more responsive to changes made locally to the system such as
        # classification changes.
        # This also avoids the need to have to insert this kind of metadata into the signature itself

        # Pull signature metadata from the API
        signature_map = {}
        signature_map = {
            f"{item['source']}.{item['signature_id']}": item
            for item in self.datastore.signature.stream_search(query=self.signatures_query,
                                                                fl="classification,source,status,signature_id,name",
                                                                as_obj=False)
        }

        with open(os.path.join(new_directory, SIGNATURES_META_FILENAME), 'w') as meta_file:
            meta_file.write(json.dumps(signature_map, indent=2))

        try:
            # Tar update directory
            new_tar = tempfile.NamedTemporaryFile(prefix="signatures_", dir=UPDATER_DIR, suffix='.tar.bz2',
                                                  delete=False)
            new_tar.close()
            new_tar = new_tar.name
            tar_handle = tarfile.open(new_tar, 'w:bz2')
            tar_handle.add(new_directory, '/')
            tar_handle.close()

            # swap update directory with old one
            self._update_dir, new_directory = new_directory, self._update_dir
            self._update_tar, new_tar = new_tar, self._update_tar
            self._time_keeper, new_time = new_time, self._time_keeper

            # Write the new status file
            temp_status = tempfile.NamedTemporaryFile('w+', delete=False, dir='/tmp')
            json.dump(self.status(), temp_status.file)
            os.rename(temp_status.name, STATUS_FILE)

            self.log.info(f"Now serving: {self._update_dir} and {self._update_tar} ({self.get_local_update_time()})")
        finally:
            if new_tar and os.path.exists(new_tar):
                self.log.info(f"Remove old tar file: {new_tar}")
                time.sleep(3)
                os.unlink(new_tar)
            if new_directory and os.path.exists(new_directory):
                self.log.info(f"Remove old directory: {new_directory}")
                shutil.rmtree(new_directory, ignore_errors=True)
            if new_time and os.path.exists(new_time):
                self.log.info(f"Remove old time keeper file: {new_time}")
                os.unlink(new_time)

            # Cleanup old timekeepers/tars from unexpected termination(s) on persistent storage
            for file in os.listdir(UPDATER_DIR):
                file_path = os.path.join(UPDATER_DIR, file)
                if (file.startswith('signatures_') and file_path != self._update_tar) or \
                    (file.startswith('time_keeper_') and file_path != self._time_keeper) or \
                        (file.startswith('update_dir_') and file_path != self._update_dir):
                    try:
                        # Attempt to cleanup file from directory
                        os.unlink(file_path)
                    except IsADirectoryError:
                        # Remove directory using
                        shutil.rmtree(file_path, ignore_errors=True)
                    except FileNotFoundError:
                        # File has already been removed
                        pass

if __name__ == "__main__":
    with YaraUpdateServer() as server:
        server.serve_forever()
