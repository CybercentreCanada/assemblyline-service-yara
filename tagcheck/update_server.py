from tagcheck.tagcheck import TAGCHECK_EXTERNALS
from yara_.update_server import YaraUpdateServer, externals_to_dict


class TagCheckUpdateServer(YaraUpdateServer):
    externals = externals_to_dict(TAGCHECK_EXTERNALS)

if __name__ == "__main__":
    with TagCheckUpdateServer() as server:
        server.serve_forever()
