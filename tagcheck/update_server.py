from tagcheck.tagcheck import TAGCHECK_EXTERNALS
from yara_.update_server import YaraUpdateServer

if __name__ == "__main__":
    with YaraUpdateServer(
        externals=TAGCHECK_EXTERNALS, default_pattern=".*\.rules"
    ) as server:
        server.serve_forever()
