import glob
import json
import logging
import os
import re
import shutil
import tempfile
import time
from typing import List, Dict, Any, Optional, Set
from zipfile import ZipFile

import certifi
import requests
import yaml
from assemblyline.common import forge
from assemblyline.common.isotime import iso_to_epoch
from assemblyline_client import get_client
from git import Repo
from plyara import Plyara, utils

from assemblyline.common import log as al_log
from assemblyline.common.digests import get_sha256_for_file
from yara_.yara_importer import YaraImporter
from yara_.yara_validator import YaraValidator

classification = forge.get_classification()

UPDATE_CONFIGURATION_PATH = os.environ.get('UPDATE_CONFIGURATION_PATH', "/tmp/yara_updater_config.yaml")
UPDATE_OUTPUT_PATH = os.environ.get('UPDATE_OUTPUT_PATH', "/tmp/yara_updater_output")
UPDATE_DIR = os.path.join(tempfile.gettempdir(), 'yara_updates')

YARA_EXTERNALS = {f'al_{x}': x for x in ['submitter', 'mime', 'tag']}


def _compile_rules(rules_file, externals, cur_logger):
    """
    Saves Yara rule content to file, validates the content with Yara Validator, and uses Yara python to compile
    the rule set.

    Args:
        rules_file: Yara rule file content.

    Returns:
        Compiled rules, compiled rules md5.
    """
    try:
        validate = YaraValidator(externals=externals, logger=cur_logger)
        validate.validate_rules(rules_file)
    except Exception as e:
        raise e
    return True


def add_cacert(cert: str):
    # Add certificate to requests
    cafile = certifi.where()
    with open(cafile, 'a') as ca_editor:
        ca_editor.write(f"\n{cert}")


def guess_category(rule_file_name):
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


def url_download(download_directory: str, source: Dict[str, Any], cur_logger, previous_update=None) -> Optional[str]:
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
        cur_logger.info(f"A CA certificate has been provided with this source.")
        add_cacert(ca_cert)

    # Create a requests session
    session = requests.Session()
    session.verify = not ignore_ssl_errors

    proxies = None
    if proxy:
        proxies = {'https': proxy} if "https" in proxy else {'http': proxy}

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
                return []

        if previous_update:
            previous_update = time.strftime("%a, %d %b %Y %H:%M:%S %Z", time.gmtime(previous_update))
            if headers:
                headers['If-Modified-Since'] = previous_update
            else:
                headers = {'If-Modified-Since': previous_update}

        response = session.get(uri, auth=auth, headers=headers, proxies=proxies)

        # Check the response code
        if response.status_code == requests.codes['not_modified']:
            # File has not been modified since last update, do nothing
            cur_logger.info("The file has not been modified since last run, skipping...")
            return []
        elif response.ok:
            file_name = os.path.basename(f"{name}.yar")  # TODO: make filename as source name with extension .yar
            file_path = os.path.join(download_directory, file_name)
            with open(file_path, 'wb') as f:
                f.write(response.content)

            # Return file_path
            return [file_path]
    except requests.Timeout:
        # TODO: should we retry?
        pass
    except Exception as e:
        # Catch all other types of exceptions such as ConnectionError, ProxyError, etc.
        cur_logger.info(str(e))
        exit()
        # TODO: Should we exit even if one file fails to download? Or should we continue downloading other files?
    finally:
        # Close the requests session
        session.close()


def git_clone_repo(download_directory: str, source: Dict[str, Any], cur_logger,
                   previous_update=None, branch=None) -> List[str] and List[str]:
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

    if proxy:
        git_config = f"https.proxy='{proxy}'" if 'https' in proxy else f"http.proxy='{proxy}'"

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

    repo = Repo.clone_from(url, clone_dir, env=git_env, multi_options=git_options, config=git_config)

    if not isinstance(repo, Repo):
        cur_logger.warning(f"Could not clone repository")
        return []

    # Check repo last commit
    if previous_update:
        if isinstance(previous_update, str):
            previous_update = iso_to_epoch(previous_update)
        for c in repo.iter_commits():
            if c.committed_date < previous_update:
                cur_logger.info("There are no new commits, skipping repository...")
                return []
            break

    if pattern:
        files = [os.path.join(dp, f)
                 for dp, dn, filenames in os.walk(clone_dir)
                 for f in filenames if re.match(pattern, f)]
    else:
        files = glob.glob(os.path.join(clone_dir, '*.yar*'))

    if not files:
        cur_logger.warning(f"Could not find any yara file matching pattern: {pattern or '*.yar*'}")

    return files


def replace_include(include, dirname, processed_files: Set[str], cur_logger):
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


def yara_update(updater_type, update_config_path, update_output_path,
                download_directory, externals, cur_logger) -> None:
    """
    Using an update configuration file as an input, which contains a list of sources, download all the file(s).
    """
    # noinspection PyBroadException
    try:
        # Load updater configuration
        update_config = {}
        if update_config_path and os.path.exists(update_config_path):
            with open(update_config_path, 'r') as yml_fh:
                update_config = yaml.safe_load(yml_fh)
        else:
            cur_logger.error(f"Update configuration file doesn't exist: {update_config_path}")
            exit()

        # Exit if no update sources given
        if 'sources' not in update_config.keys() or not update_config['sources']:
            cur_logger.error(f"Update configuration does not contain any source to update from")
            exit()

        # Initialise al_client
        server = update_config['ui_server']
        user = update_config['api_user']
        api_key = update_config['api_key']
        cur_logger.info(f"Connecting to Assemblyline API: {server}...")
        al_client = get_client(server, apikey=(user, api_key), verify=False)
        cur_logger.info(f"Connected!")

        # Parse updater configuration
        previous_update = update_config.get('previous_update', None)
        previous_hash = json.loads(update_config.get('previous_hash', None) or "{}")
        sources = {source['name']: source for source in update_config['sources']}
        files_sha256 = {}
        files_default_classification = {}

        # Create working directory
        updater_working_dir = os.path.join(tempfile.gettempdir(), 'updater_working_dir')
        if os.path.exists(updater_working_dir):
            shutil.rmtree(updater_working_dir)
        os.makedirs(updater_working_dir)

        # Go through each source and download file
        for source_name, source in sources.items():
            os.makedirs(os.path.join(updater_working_dir, source_name))
            # 1. Download signatures
            cur_logger.info(f"Downloading files from: {source['uri']}")
            uri: str = source['uri']

            if uri.endswith('.git'):
                files = git_clone_repo(download_directory, source, cur_logger, previous_update=previous_update)
            else:
                files = url_download(download_directory, source, cur_logger, previous_update=previous_update)

            processed_files = set()

            # 2. Aggregate files
            file_name = os.path.join(updater_working_dir, f"{source_name}.yar")
            mode = "w"
            for file in files:
                # File has already been processed before, skip it to avoid duplication of rules
                if file in processed_files:
                    continue

                cur_logger.info(f"Processing file: {file}")

                file_dirname = os.path.dirname(file)
                processed_files.add(os.path.normpath(file))
                with open(file, 'r') as f:
                    f_lines = f.readlines()

                temp_lines = []
                for i, f_line in enumerate(f_lines):
                    if f_line.startswith("include"):
                        lines, processed_files = replace_include(f_line, file_dirname, processed_files, cur_logger)
                        temp_lines.extend(lines)
                    else:
                        temp_lines.append(f_line)

                # guess the type of files that we have in the current file
                guessed_category = guess_category(file)
                parser = Plyara()
                signatures = parser.parse_string("\n".join(temp_lines))

                # Ignore "cuckoo" rules
                if "cuckoo" in parser.imports:
                    parser.imports.remove("cuckoo")

                # Guess category
                if guessed_category:
                    for s in signatures:
                        if 'metadata' not in s:
                            s['metadata'] = []

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

            # Check if the file is the same as the last run
            if os.path.exists(file_name):
                cache_name = os.path.basename(file_name)
                sha256 = get_sha256_for_file(file_name)
                if sha256 != previous_hash.get(cache_name, None):
                    files_sha256[cache_name] = sha256
                    files_default_classification[cache_name] = source.get('default_classification',
                                                                          classification.UNRESTRICTED)
                else:
                    cur_logger.info(f'File {cache_name} has not changed since last run. Skipping it...')

        if files_sha256:
            cur_logger.info(f"Found new {updater_type.upper()} rules files to process!")

            yara_importer = YaraImporter(updater_type, al_client, logger=cur_logger)

            # Validating and importing the different signatures
            for base_file in files_sha256:
                cur_logger.info(f"Validating output file: {base_file}")
                cur_file = os.path.join(updater_working_dir, base_file)
                source_name = os.path.splitext(os.path.basename(cur_file))[0]
                default_classification = files_default_classification.get(base_file, classification.UNRESTRICTED)

                try:
                    _compile_rules(cur_file, externals, cur_logger)
                    yara_importer.import_file(cur_file, source_name, default_classification=default_classification)
                except Exception as e:
                    raise e
        else:
            cur_logger.info(f'No new {updater_type.upper()} rules files to process...')

        # Check if new signatures have been added
        if al_client.signature.update_available(since=previous_update or '', sig_type=updater_type)['update_available']:
            cur_logger.info("An update is available for download from the datastore")

            if not os.path.exists(update_output_path):
                os.makedirs(update_output_path)

            extracted_zip = False
            attempt = 0

            # Sometimes a zip file isn't always returned, will affect service's use of signature source. Patience..
            while not extracted_zip and attempt < 5:
                temp_zip_file = os.path.join(update_output_path, 'temp.zip')
                al_client.signature.download(output=temp_zip_file,
                                             query=f"type:{updater_type} AND (status:NOISY OR status:DEPLOYED)")

                if os.path.exists(temp_zip_file):
                    try:
                        with ZipFile(temp_zip_file, 'r') as zip_f:
                            zip_f.extractall(update_output_path)
                            extracted_zip = True
                            cur_logger.info("Zip extracted.")
                    except:
                        attempt += 1
                        cur_logger.warning(f"[{attempt}/5] Bad zip. Trying again after 30s...")
                        time.sleep(30)

                    os.remove(temp_zip_file)

            cur_logger.error("Signatures aren't saved to disk. Check sources..") if attempt == 5 else None
            # Create the response yaml
            with open(os.path.join(update_output_path, 'response.yaml'), 'w') as yml_fh:
                yaml.safe_dump(dict(hash=json.dumps(files_sha256)), yml_fh)

            cur_logger.info(f"New ruleset successfully downloaded and ready to use")

        cur_logger.info(f"{updater_type.upper()} updater completed successfully")
    except Exception:
        cur_logger.exception("Updater ended with an exception!")


if __name__ == '__main__':
    al_log.init_logging('updater.yara')
    logger = logging.getLogger('assemblyline.updater.yara')
    yara_update("yara", UPDATE_CONFIGURATION_PATH, UPDATE_OUTPUT_PATH, UPDATE_DIR, YARA_EXTERNALS, logger)
