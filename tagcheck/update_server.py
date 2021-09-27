import os
import logging

import assemblyline.common.log as al_log
from assemblyline.odm.models.tagging import Tagging
from yara_.update_server import YaraUpdateServer

YARA_EXTERNALS = {f'al_{x.replace(".", "_")}': '' for x in list(Tagging.flat_fields().keys())}
al_log.init_logging('updater.tagcheck', log_level=os.environ.get('LOG_LEVEL', "WARNING"))
LOGGER = logging.getLogger('assemblyline.updater.tagcheck')

if __name__ == '__main__':
    with YaraUpdateServer(updater_type='tagcheck', externals=YARA_EXTERNALS, logger=LOGGER) as server:
        server.serve_forever()
