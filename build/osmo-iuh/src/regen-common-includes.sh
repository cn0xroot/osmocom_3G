#!/bin/sh
#for f in `(cd ../asn1/hnbap/asn1c && ls --color=none -1 *.h)`; do echo "#include \"$f\""; done
for f in ranap/*.h; do echo "#include \"$f\""; done
