#!/usr/bin/python3

import subprocess
import sys


print('Starting filter')


exclude = sys.argv[2]
stable = sys.argv[1]

print(stable)
print(exclude)


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
    'templates' ,
    'snippets' ,
    'sections' ,
    'assets' ,
    'layout/password.liquid' ,
    'config/settings_schema.json'
]

if len(command) > 0 :
    command.extend(filters)
    
print('Command')
print(command)

process = subprocess.Popen(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE)

out = process.communicate()
print(out)

print('After subprocess')