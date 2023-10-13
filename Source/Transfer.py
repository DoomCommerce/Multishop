#!/usr/bin/python3

import subprocess
import sys


print('Starting filter')


exclude = sys.argv[1]
stable = sys.argv[0]

print((stable,exclude))


print('After arguments')


lines = exclude     \
    .strip()        \
    .splitlines()


print('After lines')
print(lines)


filters = []

for line in lines :
    filters.append( "':!" + line + "'" )


print('After filters')
print(filters)


command = [
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
]

if command.count() > 0 :

    command = command   \
        .extend(filters)

subprocess.call(command)


print('After subprocess')