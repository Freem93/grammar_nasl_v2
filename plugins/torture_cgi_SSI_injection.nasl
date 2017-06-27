#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(42054);
 script_version ("$Revision: 1.13 $");


 script_name(english:"CGI Generic SSI Injection");
 script_summary(english: "Tortures the arguments of the remote CGIs (SSI injection)");
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code may be run on the remote server." );
 script_set_attribute(attribute:"description", value:
"The remote web server hosts CGI scripts that fail to adequately
sanitize request strings.  They seem to be vulnerable to an 'SSI
injection' attack.  By leveraging this issue, an attacker may be able
to execute arbitrary commands on the remote host.");
 script_set_attribute(attribute:"see_also", value:"http://en.wikipedia.org/wiki/Server_Side_Includes" );
 script_set_attribute(attribute:"see_also", value:"http://www.owasp.org/index.php/Server-Side_Includes_(SSI)_Injection");
 script_set_attribute(attribute:"see_also", value:"http://projects.webappsec.org/SSI-Injection");
 script_set_attribute(attribute:"solution", value:
"Disable Server Side Includes if you do not use them.  Otherwise,
restrict access to any vulnerable scripts and contact the vendor for a
patch or upgrade.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_cwe_id(
   97,	# Improper Neutralization of Server-Side Includes SSI Within a Web Page
   96,	# Improper Neutralization of Directives in Statically Saved Code 'Static Code Injection'
   94,	# Failure to Control Generation of Code 'Code Injection'
   74,	# Improper Neutralization of Special Elements in Output Used by a Downstream Component 'Injection'
   727,	# OWASP Top Ten 2004 Category A6 - Injection Flaws
   632,	# Weaknesses that Affect Files or Directories
   75,	# Failure to Sanitize Special Elements into a Different Plane Special Element Injection
   752,	# 2009 Top 25 - Risky Resource Management
   713	# OWASP Top Ten 2007 Category A2 - Injection Flaws
 );
 script_set_attribute(attribute:"plugin_publication_date", value:"2009/10/07");
 script_cvs_date("$Date: 2017/01/05 15:28:31 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2009-2017 Tenable Network Security, Inc.");
 script_family(english: "CGI abuses");
 script_dependencie("webmirror.nasl", "http_version.nasl", "web_app_test_settings.nasl", "torture_cgi_load_estimation1.nasl");
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

nosuchfile = strcat("nessus", rand(), ".html");
i = 0; 
flaws_and_patterns = make_array(
# Error messages from thttpd and Apache2
'<!--#include file="'+nosuchfile+'"-->',
	"RE:(The filename requested in a include file directive)|(\[an error occurred while processing this directive\])",
'<!--#exec cmd="cat /etc/passwd"-->', "RE:root:.*:0:[01]:",
'<!--#exec cmd="dir"-->',	"ST:<DIR>"
);


port = torture_cgi_init(vul:'II');


report = torture_cgis(port: port, vul: "II", exclude_cgi: "\.(php[3-5]?|pl|aspx?)$");

if (strlen(report) > 0)
{
  security_hole(port:port, extra: report);
}
