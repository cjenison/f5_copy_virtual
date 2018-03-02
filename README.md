# f5_copy_virtual

This script's intent is to copy a virtual server and all referenced dependencies (e.g. pools, iRules, profiles) to a destination.

it supports online operation where configuration is copied from source to destination BIG-IP during a single execution
it also supports offline operation where configuration is written to a JSON file and can then be read and applied to a destination BIG-IP later

It uses iControl REST (available in BIG-IP 11.5.x+) to accomplish this
