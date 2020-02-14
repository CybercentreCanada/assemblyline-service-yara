import json
import sys
import yara

rule_file, externals_file = sys.argv[1:]

try:
    with open(externals_file, 'rb') as f:
        externals = json.load(f)
    yara.compile(rule_file, externals=externals).match(data='')
    print("--==Rules_validated++__")
except yara.SyntaxError as e:
    print('yara.SyntaxError.{}'.format(str(e)))
