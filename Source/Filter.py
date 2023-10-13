#!/usr/bin/python3

import subprocess
import sys


exclude = sys.argv[1]
stable = sys.argv[0]


lines = exclude     \
    .strip()        \
    .splitlines()


filters = []

for line in lines :
    filters.append( "':!" + line + "'" )


subprocess.run([
    'git' ,
    'checkout' ,
    stable ,
    '--' ,
    'config/settings_schema.json' ,
    'layout/password.liquid' ,
    'templates' ,
    'snippets' ,
    'sections' ,
    'assets' ,
    *filters
])