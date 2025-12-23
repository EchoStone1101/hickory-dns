#!/bin/bash

base_dir="$1"
mkdir "$base_dir" -p
mkdir "${base_dir}_filter" -p

for file in "${base_dir}_zone"/*.txt; do
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
    
    ../target/release/hickory-dns -c ./zone.toml -z "./${base_dir}_zone/" -p 24141 > /dev/null &
    sleep 0.2
    
    dig @127.0.0.1 -p 24141 ${domain} SOA > /dev/null &
    sleep 0.2
    
    mkdir "$base_dir/${filename}" -p
    
    if ! grep -qE "CNAME|DNAME" "$file"; then
        mkdir "${base_dir}_filter/${filename}" -p
        cp ctx.json "./${base_dir}_filter/${filename}/ctx.json" 
    fi

    mv ctx.json "./$base_dir/${filename}/ctx.json"
    echo "${file} complete"
    
    pkill hickory-dns
    sleep 0.2
done