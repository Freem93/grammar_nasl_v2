#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(39469);
 script_version ("$Revision: 1.20 $");

 script_name(english: "CGI Generic Remote File Inclusion");
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code may be run on the remote server." );
 script_set_attribute(attribute:"description", value:
"The remote web server hosts CGI scripts that fail to adequately sanitize 
request strings.  By leveraging this issue, an attacker may be able 
to include a remote file from a remote server and execute arbitrary 
commands on the target host." );
 script_set_attribute(attribute:"see_also", value:"http://en.wikipedia.org/wiki/Remote_File_Inclusion" );
 script_set_attribute(attribute:"see_also", value:"http://projects.webappsec.org/Remote-File-Inclusion");
 script_set_attribute(attribute:"solution", value:
"Restrict access to the vulnerable application. Contact the vendor 
for a patch or upgrade." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_cwe_id(
  73,  # External Control of File Name or Path
  78,  # Improper Neutralization of Special Elements used in an OS Command 'OS Command Injection'
  98,  # Improper Control of Filename for Include/Require Statement in PHP Program 'PHP File Inclusion'
  434, # Unrestricted Upload of File with Dangerous Type
  473, # PHP External Variable Modification
  632, # Weaknesses that Affect Files or Directories
  714, # OWASP Top Ten 2007 Category A3 - Malicious File Execution
  727, # OWASP Top Ten 2004 Category A6 - Injection Flaws
  801, # 2010 Top 25 - Insecure Interaction Between Components
  928, # Weaknesses in OWASP Top Ten 2013
  929  # OWASP Top Ten 2013 Category A1 - Injection
 );
 script_set_attribute(attribute:"plugin_publication_date", value: "2009/06/19");
 script_cvs_date("$Date: 2017/01/05 15:28:31 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_summary(english: "Tortures the arguments of the remote CGIs (remote file inclusion)");
 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2009-2017 Tenable Network Security, Inc.");
 script_family(english: "CGI abuses");
 script_dependencie("http_version.nasl", "webmirror.nasl", "web_app_test_settings.nasl", "torture_cgi_load_estimation1.nasl");
 script_require_ports("Services/www", 80);
 script_timeout(43200);	# Timeout is managed by the script itself
 script_require_keys("Settings/enable_web_app_tests");
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("torture_cgi.inc");

function torture_cgi_response_post_check(resp) { return 0; }	# stub

####

i = 0; 
s = rand_str();
host = strcat(s, ".example.com");
patt = strcat(s, "\.example\.com");

flaws_and_patterns = make_array(
"http://"+host+"/",	"RE:(inclu[ds]|[fF]ail(ed)? ).*[^/]http://"+patt+"/.*([fF]fail|inclu[sd])"
);
# php_network_getaddresses: getaddrinfo failed: Name or service not known

url = get_kb_item("Settings/HTTP/remote_file_inclusion_URL");
if (strlen(url) > 0)
  if (!get_kb_item("Settings/PCI_DSS") && report_paranoia > 1)
    flaws_and_patterns[url] = "RE:Nessus(CodeExec|FileInclude)Test";
  else
    flaws_and_patterns[url] = "ST:NessusCodeExecTest";

port = torture_cgi_init(vul:'WR');

report = torture_cgis(port: port, vul: "WR");

if (strlen(report) > 0)
{
  security_hole(port:port, extra: report);
}
