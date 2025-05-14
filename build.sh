#!/usr/bin/env bash

go install

for distro in $(go tool dist list)
do
    arrIN=(${distro//\// })

    if [[ ${arrIN[0]} == 'linux' || ${arrIN[0]} == 'darwin' ]]; then
      echo "Building $distro..."
      GOOS=${arrIN[0]} GOARCH=${arrIN[1]} go build --ldflags="-X 'github.com/siteworxpro/rsa-file-encryption/printer.Version=$(git describe --tags --abbrev=0)'" -o dist/rsa-file-encryption_${arrIN[0]}_${arrIN[1]}
      gpg --detach-sign "dist/rsa-file-encryption_${arrIN[0]}_${arrIN[1]}"
    fi
done