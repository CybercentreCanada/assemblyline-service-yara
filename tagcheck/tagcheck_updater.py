from assemblyline.odm.models.tagging import Tagging

from yara_.yara_updater import *

UPDATE_CONFIGURATION_PATH = os.environ.get('UPDATE_CONFIGURATION_PATH', "/tmp/tagcheck_updater_config.yaml")
UPDATE_OUTPUT_PATH = os.environ.get('UPDATE_OUTPUT_PATH', "/tmp/tagcheck_updater_output")
UPDATE_DIR = os.path.join(tempfile.gettempdir(), 'tagcheck_updates')

YARA_EXTERNALS = {f'al_{x.replace(".", "_")}': '' for x in list(Tagging.flat_fields().keys())}
al_log.init_logging('updater.tagcheck')
logger = logging.getLogger('assemblyline.updater.tagcheck')


def update_tagcheck():
    update("tagcheck", UPDATE_CONFIGURATION_PATH, UPDATE_OUTPUT_PATH, UPDATE_DIR, YARA_EXTERNALS, logger)


if __name__ == '__main__':
    update_tagcheck()
