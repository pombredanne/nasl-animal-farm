#!/usr/bin/python3

import argparse
from lib.file.plugin import Plugin

parser = argparse.ArgumentParser()
parser.add_argument('-f', dest='plugin_file', type=str, help='A nasl source file', required=True)
args = parser.parse_args()

plugin = Plugin(args.plugin_file)
fn_calls = plugin.get_function_calls()
for fn in fn_calls:
  print(fn)
