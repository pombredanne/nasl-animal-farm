#!/usr/bin/python3

import argparse
from lib.file.plugin import Plugin

parser = argparse.ArgumentParser()
parser.add_argument('-f', dest='plugin_file', type=str, help='A nasl source file', required=True)
args = parser.parse_args()

plugin = Plugin(args.plugin_file)
fn_defs = plugin.get_function_defs()
for fn in fn_defs:
  print(fn)
