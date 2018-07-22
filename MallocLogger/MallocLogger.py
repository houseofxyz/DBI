#!/usr/bin/env python
import frida
import sys

pid = frida.spawn(['ExercisePin.exe'])
session = frida.attach(pid)

contents = open('mallocTracer.js').read()
script = session.create_script(contents)
script.load()
frida.resume(pid)
sys.stdin.read()