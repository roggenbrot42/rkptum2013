#!/bin/bash
# declare system map file path
FILEPATH="/boot/System.map-$(uname -r)"
# declare output header file name
HFILE="sysmap.h"
# create a header file with preprocessor
echo "$HFILE" | awk '{ gsub("\.","_"); print "#ifndef "toupper($0)"\n#define "toupper($0) }' > $HFILE
awk '/^(.*) (D|R|T) (.*)$/ { print "#define "$3"_"$2" 0x"$1 }' $FILEPATH >> $HFILE 
echo "#endif" >> $HFILE
