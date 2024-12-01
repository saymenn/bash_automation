#!/bin/bash

name=$1
roots=$2
bruteforce=$3
scan=$4

subfinder_path=$name".all.subfinder"
resolved_path=$name".all.resolved"
bruteforced_path=$name".all.bruteforced"
final_list=$name".all.final_list"
webservers_path=$name".all.webservers"

subfinder -dL $roots -all -o $subfinder_path;
cat $subfinder_path | puredns resolve --write $resolved_path

if [ $bruteforce = brute]; then
    puredns bruteforce /opt/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -d $resolved_path --write $bruteforced_path
    cat $resolved_path $bruteforced_path | sort -u | tee $final_list
else
    cat $resolved_path | sort -u | tee $final_list
fi

# webservers
cat $final_list | httprobe -p http:80 -p https:443 -p http:8080 -p https:9443 -p https:8443 -p http:8081 -p http:8000 -p http:3000 -p http:10000 | tee $webservers_path
