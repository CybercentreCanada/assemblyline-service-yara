from assemblyline.odm.models.tagging import Tagging

from yara_.yara_ import Yara


class TagCheck(Yara):
    def __init__(self, config=None):
        externals = list(Tagging.flat_fields().keys())
        super().__init__(config, name="TagCheck", externals=externals)
