import glob
import hashlib
import logging
import os
import re
import shutil
import tempfile
import time
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse
from git import Repo
from io import StringIO
import fnmatch

import requests
import yaml

from assemblyline.common import log as al_log
from assemblyline.common.digests import get_sha256_for_file
from assemblyline.common.isotime import now_as_iso
from yara_.yara_importer import YaraImporter

al_log.init_logging('service_updater')

LOGGER = logging.getLogger('assemblyline.service_updater')


UPDATE_CONFIGURATION_PATH = os.environ.get('UPDATE_CONFIGURATION_PATH', None)
UPDATE_OUTPUT_PATH = os.environ.get('UPDATE_OUTPUT_PATH', None)


def _compile_rules(self, rules_files: List[str]):
    """
    Saves Yara rule content to file, validates the content with Yara Validator, and uses Yara python to compile
    the rule set.

    Args:
        rules_txt: Yara rule file content.

    Returns:
        Compiled rules, compiled rules md5.
    """
    filepaths = dict()
    try:
        for rules_file in rules_files:
            # Extract the first line of the rules which should look like this:
            # // Signatures last updated: LAST_UPDATE_IN_ISO_FORMAT
            first_line, clean_data = rules_txt.split('\n', 1)
            prefix = '// Signatures last updated: '

            if first_line.startswith(prefix):
                last_update = first_line.replace(prefix, '')
            else:
                self.log.warning(f"Couldn't read last update time from {rules_txt[:40]}")
                # last_update = now_as_iso()
                clean_data = rules_txt

            temp_rules_file = os.path.join(tempfile.gettempdir(), 'yara_rules', os.path.basename(rules_file))
            shutil.copy(rules_file, temp_rules_file)

            try:
                validate = YaraValidator(externals=self.get_yara_externals, logger=self.log)
                edited = validate.validate_rules(temp_rules_file, datastore=True)
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

        rules = yara.compile(filepaths=filepaths, externals=self.get_yara_externals)
        rules_md5 = hashlib.md5(clean_data).hexdigest()
        return rules, rules_md5
    except Exception as e:
        raise e
    finally:
        shutil.rmtree(tmp_dir)


def url_download(source: Dict[str, Any], previous_update: Optional[float] = None) -> Optional[str]:
    """

    :param source:
    :param previous_update:
    :return:
    """
    name = source['name']
    uri = source['uri']
    username = source.get('username', None)
    password = source.get('password', None)
    auth = (username, password) if username and password else None

    headers = source.get('headers', None)

    # Create a requests session
    session = requests.Session()

    try:
        # Check the response header for the last modified date
        response = session.head(uri, auth=auth, headers=headers)
        last_modified = response.headers.get('Last-Modified', None)
        if last_modified:
            # Convert the last modified time to epoch
            last_modified = time.mktime(time.strptime(last_modified, "%a, %d %b %Y %H:%M:%S %Z"))

            # Compare the last modified time with the last updated time
            if previous_update and last_modified > previous_update:
                # File has not been modified since last update, do nothing
                return

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
            return
        elif response.ok:
            file_name = os.path.basename(urlparse(uri).path) # TODO: make filename as source name with extension .yar
            file_path = os.path.join(tempfile.gettempdir(), file_name)
            with open(file_path, 'wb') as f:
                f.write(response.content)

            # Return the SHA256 of the downloaded file
            return get_sha256_for_file(file_path)
    except requests.Timeout:
        # TODO: should we retry?
        pass
    except Exception as e:
        # Catch all other types of exceptions such as ConnectionError, ProxyError, etc.
        LOGGER.info(str(e))
        exit()  # TODO: Should we exit even if one file fails to download? Or should we continue downloading other files?
    finally:
        # Close the requests session
        session.close()


def git_clone_repo(source: Dict[str, Any]) -> List[str] and List[str]:
    name = source['name']
    url = source['uri']
    pattern = source.get('pattern', None)

    clone_dir = os.path.join(tempfile.gettempdir(), name)
    if os.path.exists(clone_dir):
        shutil.rmtree(clone_dir)

    repo = Repo.clone_from(url, clone_dir)

    if pattern:
        files = [f for f in os.listdir(clone_dir) if re.match(pattern, f)]
    else:
        files = glob.glob(os.path.join(clone_dir, '*.yar'))

    files_sha256 = [get_sha256_for_file(x) for x in files]

    return files, files_sha256


def yara_update() -> None:
    """
    Using an update configuration file as an input, which contains a list of sources, download all the file(s).
    """
    if os.path.exists(UPDATE_CONFIGURATION_PATH):
        with open(UPDATE_CONFIGURATION_PATH, 'r') as yml_fh:
            update_config = yaml.safe_load(yml_fh)

    sources = update_config.get('sources', None)

    # Exit if no update sources given
    if 'sources' not in update_config.keys():
        exit()

    sources = {source['name']: source for source in update_config['sources']}

    files_sha256 = []

    # Go through each source and download file
    for source_name, source in sources.items():
        uri: str = source['uri']

        if uri.endswith('.git'):
            sha256 = git_clone_repo(source)
            if sha256:
                files_sha256.extend(sha256)
        else:
            previous_update = update_config.get('previous_update', None)
            sha256 = url_download(source, previous_update=previous_update)
            if sha256:
                files_sha256.append(sha256)

    if not files_sha256:
        LOGGER.info('No YARA rule file(s) downloaded')
        exit()

    new_hash = hashlib.md5(' '.join(sorted(files_sha256)).encode('utf-8')).hexdigest()

    # Check if the new update hash matches the previous update hash
    if new_hash == update_config.get('previous_hash', None):
        # Update file(s) not changed, delete the downloaded files and exit
        shutil.rmtree(UPDATE_OUTPUT_PATH, ignore_errors=True)
        exit()

    # Create the response yaml
    with open(os.path.join(UPDATE_OUTPUT_PATH, 'response.yaml'), 'w') as yml_fh:
        yaml.safe_dump(dict(
            previous_update=now_as_iso(),
            previous_hash=new_hash,
        ), yml_fh)

    LOGGER.info("YARA rule(s) file(s) successfully downloaded")

    yar_files = []
    yara_importer = YaraImporter()

    for x in os.listdir(tempfile.gettempdir()):
        source_name = os.path.splitext(os.path.basename(x))[0]
        if os.path.isdir(os.path.join(tempfile.gettempdir(), x)):
            source = sources[source_name]

            # Build a master yar file which includes all child files
            index_yar = StringIO()
            yar_files = glob.glob(os.path.join(x, '*.yar'))
            for yar_file in yar_files:
                pattern = source.get('pattern', None)
                if pattern:
                    if fnmatch.fnmatch(yar_file, pattern):
                        index_yar.write(f'include "{yar_file}"\n')
                else:
                    index_yar.write(f'include "{yar_file}"\n')

            yar_file = os.path.join(tempfile.gettempdir(), f'{source_name}.yar')
            with open('file.xml', 'w') as fh:
                index_yar.seek(0)
                shutil.copyfileobj(index_yar, fh)
        else:
            yar_file = x

        # TODO: validate/compile single yar file by cleaning up any invalid signatures

        # Save the YARA rules into datastore through AL client
        yara_importer.import_file(yar_file, source_name)

    # TODO: Download all signatures matching query and unzip received file to UPDATE_OUTPUT_PATH


if __name__ == '__main__':
    yara_update()
