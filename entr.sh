#!/bin/sh
ls NCC-FreeRDP-pyparser/* | entr ./NCC-FreeRDP-pyparser/nccfreerdppyparser.py 1579514838 >[2=1] | sed -u -e 's/", line /:/' -e 's/^ *File "//'
