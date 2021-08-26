from __future__ import annotations
import glob
import logging
import os
import re
import shutil
import tempfile
import time
from typing import Any, Optional
from zipfile import ZipFile

import certifi
import requests

from assemblyline.common import forge
from assemblyline.common.isotime import iso_to_epoch, epoch_to_iso
from assemblyline.common.digests import get_sha256_for_file
from assemblyline.odm.models.service import Service, UpdateSource
from assemblyline_v4_service.updater.updater import ServiceUpdater, temporary_api_key
from assemblyline_client import get_client
from git import Repo, GitCommandError
from plyara import Plyara, utils

from yara_.yara_importer import YaraImporter
from yara_.yara_validator import YaraValidator

classification = forge.get_classification()

UPDATE_CONFIGURATION_PATH = os.environ.get('UPDATE_CONFIGURATION_PATH', "/tmp/yara_updater_config.yaml")
UPDATE_OUTPUT_PATH = os.environ.get('UPDATE_OUTPUT_PATH', "/tmp/yara_updater_output")
UPDATE_DIR = os.path.join(tempfile.gettempdir(), 'yara_updates')
UI_SERVER = os.getenv('UI_SERVER', 'https://nginx')

YARA_EXTERNALS = {f'al_{x}': x for x in ['submitter', 'mime', 'tag']}


class SkipSource(RuntimeError):
    pass


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


def add_cacert(cert: str):
    # Add certificate to requests
    cafile = certifi.where()
    with open(cafile, 'a') as ca_editor:
        ca_editor.write(f"\n{cert}")


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


def url_download(download_directory: str, source: dict[str, Any], cur_logger, previous_update=None) -> list[str]:
    if os.path.exists(download_directory):
        shutil.rmtree(download_directory)
    os.makedirs(download_directory)

    name = source['name']
    uri = source['uri']
    username = source.get('username', None)
    password = source.get('password', None)
    ca_cert = source.get('ca_cert', None)
    ignore_ssl_errors = source.get('ssl_ignore_errors', False)
    auth = (username, password) if username and password else None

    proxy = source.get('proxy', None)
    headers = source.get('headers', None)

    cur_logger.info(f"{name} source is configured to {'ignore SSL errors' if ignore_ssl_errors else 'verify SSL'}.")
    if ca_cert:
        cur_logger.info("A CA certificate has been provided with this source.")
        add_cacert(ca_cert)

    # Create a requests session
    session = requests.Session()
    session.verify = not ignore_ssl_errors

    # Let https requests go through proxy
    if proxy:
        os.environ['https_proxy'] = proxy

    try:
        if isinstance(previous_update, str):
            previous_update = iso_to_epoch(previous_update)

        # Check the response header for the last modified date
        response = session.head(uri, auth=auth, headers=headers)
        last_modified = response.headers.get('Last-Modified', None)
        if last_modified:
            # Convert the last modified time to epoch
            last_modified = time.mktime(time.strptime(last_modified, "%a, %d %b %Y %H:%M:%S %Z"))

            # Compare the last modified time with the last updated time
            if previous_update and last_modified <= previous_update:
                # File has not been modified since last update, do nothing
                cur_logger.info("The file has not been modified since last run, skipping...")
                raise SkipSource()

        if previous_update:
            previous_update = time.strftime("%a, %d %b %Y %H:%M:%S %Z", time.gmtime(previous_update))
            if headers:
                headers['If-Modified-Since'] = previous_update
            else:
                headers = {'If-Modified-Since': previous_update}

        response = session.get(uri, auth=auth, headers=headers)

        # Check the response code
        if response.status_code == requests.codes['not_modified']:
            # File has not been modified since last update, do nothing
            cur_logger.info("The file has not been modified since last run, skipping...")
            raise SkipSource()
        elif response.ok:
            file_name = os.path.basename(f"{name}.yar")  # TODO: make filename as source name with extension .yar
            file_path = os.path.join(download_directory, file_name)
            with open(file_path, 'wb') as f:
                f.write(response.content)

            # Clear proxy setting
            if proxy:
                del os.environ['https_proxy']

            # Return file_path
            return [file_path]
    except requests.Timeout:
        # TODO: should we retry?
        pass
    except Exception as e:
        # Catch all other types of exceptions such as ConnectionError, ProxyError, etc.
        cur_logger.info(str(e))
    finally:
        # Close the requests session
        session.close()
    raise SkipSource()


def git_clone_repo(download_directory: str, source: dict[str, Any], cur_logger,
                   previous_update=None, branch=None) -> list[str]:
    name = source['name']
    url = source['uri']
    pattern = source.get('pattern', None)
    key = source.get('private_key', None)
    username = source.get('username', None)
    password = source.get('password', None)

    ignore_ssl_errors = source.get("ssl_ignore_errors", False)
    ca_cert = source.get("ca_cert")
    proxy = source.get('proxy', None)

    auth = f'{username}:{password}@' if username and password else None

    git_config = None
    git_env = {}
    git_options = ['--single-branch']

    if branch:
        git_options.append(f'--branch {branch}')

    # Let https requests go through proxy
    if proxy:
        os.environ['https_proxy'] = proxy

    if ignore_ssl_errors:
        git_env['GIT_SSL_NO_VERIFY'] = '1'

    if ca_cert:
        cur_logger.info(f"A CA certificate has been provided with this source.")
        add_cacert(ca_cert)
        git_env['GIT_SSL_CAINFO'] = certifi.where()

    if key:
        cur_logger.info(f"key found for {url}")
        # Save the key to a file
        git_ssh_identity_file = os.path.join(tempfile.gettempdir(), 'id_rsa')
        if os.path.exists(git_ssh_identity_file):
            os.unlink(git_ssh_identity_file)
        with open(git_ssh_identity_file, 'w') as key_fh:
            key_fh.write(key)
        os.chmod(git_ssh_identity_file, 0o0400)

        git_ssh_cmd = f"ssh -oStrictHostKeyChecking=no -i {git_ssh_identity_file}"
        git_env['GIT_SSH_COMMAND'] = git_ssh_cmd

    if auth:
        cur_logger.info("Credentials provided for auth..")
        url = re.sub(r'^(?P<scheme>https?://)', fr'\g<scheme>{auth}', url)

    clone_dir = os.path.join(download_directory, name)
    if os.path.exists(clone_dir):
        shutil.rmtree(clone_dir)
    os.makedirs(clone_dir)

    repo = None
    try:
        repo = Repo.clone_from(url, clone_dir, env=git_env, multi_options=git_options, config=git_config)

        if not isinstance(repo, Repo):
            cur_logger.warning("Could not clone repository")
            raise SkipSource()
    except GitCommandError as e:
        cur_logger.error(f"Problem cloning repo: {e}")
        raise SkipSource()

    # Check repo last commit
    if previous_update:
        if isinstance(previous_update, str):
            previous_update = iso_to_epoch(previous_update)
        for c in repo.iter_commits():
            if c.committed_date < previous_update:
                cur_logger.info("There are no new commits, skipping repository...")
                raise SkipSource()
            break

    if pattern:
        files = [os.path.join(dp, f)
                 for dp, dn, filenames in os.walk(clone_dir)
                 for f in filenames if re.match(pattern, f)]
    else:
        files = glob.glob(os.path.join(clone_dir, '*.yar*'))

    if not files:
        cur_logger.warning(f"Could not find any yara file matching pattern: {pattern or '*.yar*'}")

    # Clear proxy setting
    if proxy:
        del os.environ['https_proxy']

    return files


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
    def __init__(self, *args, updater_type:str, externals:dict[str, str], **kwargs):
        super().__init__(*args, **kwargs)
        self.updater_type = updater_type
        self.externals = externals

    def do_local_update(self) -> None:
        old_update_time = self.get_local_update_time()
        run_time = time.time()
        output_directory = tempfile.mkdtemp()

        self.log.info(f"Setup service account.")
        username = self.ensure_service_account()
        self.log.info(f"Create temporary API key.")
        with temporary_api_key(self.datastore, username) as api_key:
            self.log.info(f"Connecting to Assemblyline API: {UI_SERVER}")
            al_client = get_client(UI_SERVER, apikey=(username, api_key), verify=False)

            # Check if new signatures have been added
            self.log.info(f"Check for new signatures.")
            if al_client.signature.update_available(since=epoch_to_iso(old_update_time) or '', sig_type=self.updater_type)['update_available']:
                self.log.info("An update is available for download from the datastore")

                extracted_zip = False
                attempt = 0

                # Sometimes a zip file isn't always returned, will affect service's use of signature source. Patience..
                while not extracted_zip and attempt < 5:
                    temp_zip_file = os.path.join(output_directory, 'temp.zip')
                    al_client.signature.download(output=temp_zip_file,
                                                    query=f"type:{self.updater_type} AND (status:NOISY OR status:DEPLOYED)")

                    if os.path.exists(temp_zip_file):
                        try:
                            with ZipFile(temp_zip_file, 'r') as zip_f:
                                zip_f.extractall(output_directory)
                                extracted_zip = True
                                self.log.info("Zip extracted.")
                        except:
                            attempt += 1
                            self.log.warning(f"[{attempt}/5] Bad zip. Trying again after 30s...")
                            time.sleep(30)

                        os.remove(temp_zip_file)

                if attempt == 5:
                    self.log.error("Signatures aren't saved to disk. Check sources..")
                    shutil.rmtree(output_directory, ignore_errors=True)
                else:
                    self.log.info(f"New ruleset successfully downloaded and ready to use")
                    self.serve_directory(output_directory)
                    self.set_local_update_time(run_time)

    def do_source_update(self, service: Service) -> None:
        self.log.info(f"Connecting to Assemblyline API: {UI_SERVER}...")
        run_time = time.time()
        username = self.ensure_service_account()
        with temporary_api_key(self.datastore, username) as api_key:
            al_client = get_client(UI_SERVER, apikey=(username, api_key), verify=False)
            old_update_time = self.get_source_update_time()

            self.log.info(f"Connected!")

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
                                files = git_clone_repo(download_directory, source, self.log, previous_update=old_update_time)
                            else:
                                files = url_download(download_directory, source, self.log, previous_update=old_update_time)
                        except SkipSource:
                            if cache_name in previous_hashes:
                                files_sha256[cache_name] = previous_hashes[cache_name]
                            continue

                        processed_files: set[str] = set()

                        # 2. Aggregate files
                        file_name = os.path.join(updater_working_dir, cache_name)
                        mode = "w"
                        for file in files:
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
                                    lines, processed_files = replace_include(f_line, file_dirname, processed_files, self.log)
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
                                files_default_classification[cache_name] = source.get('default_classification', classification.UNRESTRICTED)
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
                            default_classification = files_default_classification.get(base_file, classification.UNRESTRICTED)

                            try:
                                _compile_rules(cur_file, self.externals, self.log)
                                yara_importer.import_file(cur_file, source_name, default_classification=default_classification)
                            except Exception as e:
                                raise e
                    else:
                        self.log.info(f'No new {self.updater_type.upper()} rules files to process...')

        self.set_source_update_time(run_time)
        self.set_source_extra(files_sha256)
        self.set_active_config_hash(self.config_hash(service))
        self.local_update_flag.set()


if __name__ == '__main__':
    with YaraUpdateServer(updater_type='yara', externals=YARA_EXTERNALS) as server:
        server.serve_forever()
