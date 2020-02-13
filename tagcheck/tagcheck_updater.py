from assemblyline.odm.models.tagging import Tagging

from yara_.yara_updater import *

al_log.init_logging('service_updater')
LOGGER = logging.getLogger('assemblyline.service_updater')

UPDATE_CONFIGURATION_PATH = os.environ.get('UPDATE_CONFIGURATION_PATH', "/tmp/tagcheck_updater_config.yaml")
UPDATE_OUTPUT_PATH = os.environ.get('UPDATE_OUTPUT_PATH', "/tmp/tagcheck_updater_output")
UPDATE_DIR = os.path.join(tempfile.gettempdir(), 'tagcheck_updates')

YARA_EXTERNALS = {f'al_{x}': x for x in list(Tagging.flat_fields().keys())}


if __name__ == '__main__':
    yara_update(UPDATE_CONFIGURATION_PATH, UPDATE_OUTPUT_PATH, UPDATE_DIR, YARA_EXTERNALS)
