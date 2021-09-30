from assemblyline.odm.models.tagging import Tagging
from yara_.update_server import YaraUpdateServer

YARA_EXTERNALS = {f'al_{x.replace(".", "_")}': '' for x in list(Tagging.flat_fields().keys())}

if __name__ == '__main__':
    with YaraUpdateServer(externals=YARA_EXTERNALS, default_pattern="*.rules") as server:
        server.serve_forever()
