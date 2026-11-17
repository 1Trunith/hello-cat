"""Small bundled table of well-known, commonly-seen-on-THM-boxes
software versions mapped to their headline CVE and exploit note.

Matching is done by substring on the "product version" string built
from Server/X-Powered-By headers (see cve_match.py). This is
intentionally tiny and curated, not a full NVD mirror - it's a fast
path for the handful of CVEs that show up over and over on
TryHackMe/HTB-style boxes. searchsploit (if installed) covers the
long tail.
"""

KNOWN_CVES = [
    {"match": "vsftpd 2.3.4", "cve": "CVE-2011-2523",
     "note": "vsftpd 2.3.4 backdoor - smiley face in username triggers a bind shell on port 6200",
     "exploit": "exploit/unix/ftp/vsftpd_234_backdoor"},
    {"match": "proftpd 1.3.5", "cve": "CVE-2015-3306",
     "note": "mod_copy arbitrary file read/write - use SITE CPFR/CPTO to write a webshell",
     "exploit": "exploit/unix/ftp/proftpd_modcopy_exec"},
    {"match": "samba 3.5", "cve": "CVE-2017-7494",
     "note": "SambaCry - remote code execution via writable share + shared library load",
     "exploit": "exploit/linux/samba/is_known_pipename"},
    {"match": "samba 3.0", "cve": "CVE-2007-2447",
     "note": "usermap_script - command injection via username field",
     "exploit": "exploit/multi/samba/usermap_script"},
    {"match": "apache struts 2.3.5", "cve": "CVE-2017-5638",
     "note": "Struts2 Content-Type OGNL injection RCE (Equifax breach bug)",
     "exploit": "exploit/multi/http/struts2_content_type_ognl"},
    {"match": "drupal 7", "cve": "CVE-2018-7600",
     "note": "Drupalgeddon2 - unauthenticated RCE via form API",
     "exploit": "exploit/unix/webapp/drupal_drupalgeddon2"},
    {"match": "elasticsearch 1.", "cve": "CVE-2015-1427",
     "note": "Groovy scripting engine sandbox bypass -> RCE",
     "exploit": "exploit/multi/elasticsearch/script_mvel_rce"},
    {"match": "jenkins", "cve": "CVE-2017-1000353",
     "note": "Jenkins CLI deserialization RCE - check version against this advisory",
     "exploit": "exploit/multi/http/jenkins_cli_rmi"},
    {"match": "openssl 1.0.1", "cve": "CVE-2014-0160",
     "note": "Heartbleed - memory disclosure, often leaks session tokens/keys",
     "exploit": "auxiliary/scanner/ssl/openssl_heartbleed"},
    {"match": "microsoft-iis/6.0", "cve": "CVE-2017-7269",
     "note": "IIS 6.0 WebDAV ScStoragePathFromUrl buffer overflow RCE",
     "exploit": "exploit/windows/iis/iis_webdav_scstoragepathfromurl"},
    {"match": "exim 4.87", "cve": "CVE-2016-1531",
     "note": "Exim local privilege escalation via Perl environment variable",
     "exploit": "manual - see exploit-db 39702"},
    {"match": "bash 4.3", "cve": "CVE-2014-6271",
     "note": "Shellshock - environment-variable function injection via CGI",
     "exploit": "exploit/multi/http/apache_mod_cgi_bash_env_exec"},
    {"match": "php 5.", "cve": "CVE-2012-1823",
     "note": "PHP-CGI query-string argument injection RCE",
     "exploit": "exploit/multi/http/php_cgi_arg_injection"},
    {"match": "wordpress 4.7", "cve": "CVE-2017-1001000",
     "note": "WordPress REST API content injection (privilege escalation via posts)",
     "exploit": "exploit/multi/http/wp_rest_api"},
    {"match": "coldfusion", "cve": "CVE-2010-2861",
     "note": "ColdFusion directory traversal -> password.properties disclosure",
     "exploit": "auxiliary/scanner/http/coldfusion_traversal"},
]


def match(product_version_string):
    lowered = (product_version_string or "").lower()
    return [entry for entry in KNOWN_CVES if entry["match"] in lowered]
