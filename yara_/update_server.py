from __future__ import annotations
import logging
import os
import re
import tempfile
from typing import Any, Optional

from assemblyline.common import forge
from assemblyline_v4_service.updater.updater import ServiceUpdater

from plyara import Plyara, utils
from yara_.helper import YaraImporter, YaraValidator, YARA_EXTERNALS

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
    def __init__(self, *args, externals: dict[str, str], **kwargs):
        super().__init__(*args, **kwargs)
        self.externals = externals

    def import_update(self, files_sha256, client, source_name: str, default_classification=classification.UNRESTRICTED):
        processed_files: set[str] = set()

        with tempfile.NamedTemporaryFile(mode='a+', suffix=source_name) as compiled_file:
            # Aggregate files into one major source file
            for file, _ in files_sha256:
                # File has already been processed before, skip it to avoid duplication of rules
                if file in processed_files:
                    continue

                self.log.info(f"Processing file: {file}")

                file_dirname = os.path.dirname(file)
                processed_files.add(os.path.normpath(file))
                with open(file, 'r', errors="surrogateescape") as f:
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
                    for s in signatures:
                        # Fix imports and remove cuckoo
                        s['imports'] = utils.detect_imports(s)
                        if "cuckoo" not in s['imports']:
                            compiled_file.write(utils.rebuild_yara_rule(s))
                except Exception as e:
                    self.log.error(f"Problem parsing {file}: {e}")
                    continue
            yara_importer = YaraImporter(self.updater_type, client, logger=self.log)
            try:
                compiled_file.seek(0)
                _compile_rules(compiled_file.name, self.externals, self.log)
                yara_importer.import_file(compiled_file.name, source_name,
                                          default_classification=default_classification)
            except Exception as e:
                raise e


if __name__ == '__main__':
    with YaraUpdateServer(externals=YARA_EXTERNALS, default_pattern="*.yar*") as server:
        server.serve_forever()
