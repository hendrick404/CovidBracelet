#!/bin/bash

west build -p always -b pinetime_devkit0 . -- -DCMAKE_C_FLAGS="-I../../include/tls_config -DDISPLAY" -DPINETIME=1