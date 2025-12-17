#!/bin/bash

mkdir simple -p
mkdir simple_filter -p

for file in ZoneFiles/*.txt; do
    if grep -qE "DNAME" "$file"; then
        echo "${file} skipped"
        continue
    fi

    filename=$(basename "$file" .txt)
    
    domain=$(head -n 1 "$file" | awk '{print $1}')
    
    zonefile="[[zones]]
zone = \"${domain}\"
zone_type = \"Primary\"
file = \"${filename}.txt\""

    echo "$zonefile" > zone.toml
    
    ../target/release/hickory-dns -c ./zone.toml -z ./ZoneFiles/ -p 24141 > /dev/null &
    sleep 0.2
    
    dig @127.0.0.1 -p 24141 ${domain} SOA > /dev/null &
    sleep 0.2
    
    mkdir "simple/${filename}" -p
    
    if ! grep -qE "CNAME|DNAME" "$file"; then
        mkdir "simple_filter/${filename}" -p
        cp ctx.json "./simple_filter/${filename}/ctx.json" 
    fi

    mv ctx.json "./simple/${filename}/ctx.json"
    echo "${file} complete"
    
    pkill hickory-dns
    sleep 0.2
done