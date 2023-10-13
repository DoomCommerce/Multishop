#!/usr/bin/python3

import subprocess
import sys


print('Starting filter')


exclude = sys.argv[1]
stable = sys.argv[0]


print('After arguments')


lines = exclude     \
    .strip()        \
    .splitlines()


print('After lines')


filters = []

for line in lines :
    filters.append( "':!" + line + "'" )


print('After filters')


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


print('After subprocess')