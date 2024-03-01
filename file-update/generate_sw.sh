#!/bin/bash

CONTAINER_VER="1.0"
PRODUCT_NAME="rasues-file-update"
FILES="sw-description rasues OS_VERSION.txt"
openssl dgst -sha256 -sign priv.pem sw-description > sw-description.sig

for i in $FILES;do
        echo $i;done | cpio -ov -H crc >  ${PRODUCT_NAME}_${CONTAINER_VER}.swu
