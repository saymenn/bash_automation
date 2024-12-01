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
webscreenshots_path=$name".all.screenshots"
katana_path=$name".all.katana"
gau_path=$name".all.gau"
js_subdomains_path=$name".all.js_subdomains"
forbidden_path=$name".all.forbidden"
vhost_path=$name".all.vhost_support"

subfinder -dL $roots -all -o $subfinder_path;
cat $subfinder_path | puredns resolve --write $resolved_path;

if [ $bruteforce = brute ]; then
    puredns bruteforce /opt/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -d $resolved_path --write $bruteforced_path;
    cat $resolved_path $bruteforced_path | sort -u | tee $final_list;
else
    cat $resolved_path | sort -u | tee $final_list;
fi

# webservers
cat $final_list | httprobe -p http:80 -p https:443 -p http:8080 -p https:9443 -p https:8443 -p http:8081 -p http:8000 -p http:3000 -p http:10000 | tee $webservers_path;

# screenshots
cat $webservers_path | httpx -st 30 -timeout 30 -ss -o $webscreenshots_path;

# crawling
katana -list $webservers_path -duc -silent -nc -jc -jsl -kf -fx -xhr -ef woff,css,png,svg,jpg,woff2,jpeg,gif,svg -o $katana_path;

# sub list of subdomains found in js files
cat $katana_path | grep -oP 'https?://[a-zA-Z0-9.-]+(:[0-9]+)?/' | sort -u | tee $js_subdomains_path;

# archive links
cat $webservers_path | gau --o $gau_path;

# get 403 401 webservers ( used on later stages )

cat $webservers_path | httpx -timeout 30 -mc 401,403 -o $forbidden_path;

# vhost support
cat $webservers_path | httpx -timeout 30 -vhost -o $vhost_path;