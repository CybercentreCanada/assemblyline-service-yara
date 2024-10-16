from assemblyline.odm.models.tagging import Tagging

from yara_.helper import YARA_EXTERNALS
from yara_.yara_ import Yara

tags_ext = list(Tagging.flat_fields().keys())
TAGCHECK_EXTERNALS = [*tags_ext, *YARA_EXTERNALS]


class TagCheck(Yara):
    def __init__(self, config=None):
        super().__init__(config, externals=TAGCHECK_EXTERNALS)
