#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(39468);
 script_version ("$Revision: 1.21 $");

 script_name(english: "CGI Generic Header Injection");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is prone to HTTP headers injections attacks." );
 script_set_attribute(attribute:"description", value:
"The remote web server hosts CGIs that are vulnerable to 'header
injection'.  By leveraging this issue, an attacker may be able to poison
a proxy cache, or trigger a cross-site scripting flaws and cause 
arbitrary HTML and  script code to be executed in a user's browser 
within the security context of the affected site.
Privilege escalation may be possible too, depending on the application." );
 script_set_attribute(attribute:"see_also", value:"http://en.wikipedia.org/wiki/HTTP_header_injection" );
 script_set_attribute(attribute:"see_also", value:"http://projects.webappsec.org/HTTP-Response-Splitting");
 script_set_attribute(attribute:"see_also", value:"http://cwe.mitre.org/data/definitions/113.html");
 script_set_attribute(attribute:"solution", value:
"Restrict access to the vulnerable application. Contact the vendor 
for a patch or upgrade." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_cwe_id(
   113,	# Improper Neutralization of CRLF Sequences in HTTP Headers 'HTTP Response Splitting'
   93	# Improper Neutralization of CRLF Sequences 'CRLF Injection'
 );
 script_set_attribute(attribute:"plugin_publication_date", value: "2009/06/19");
 script_cvs_date("$Date: 2017/01/05 15:28:31 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_summary(english: "Tortures the arguments of the remote CGIs (header injection)");
 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2009-2017 Tenable Network Security, Inc.");
 script_family(english: "CGI abuses");
 script_dependencie("http_version.nasl", "webmirror.nasl", "cross_site_scripting.nasl", "web_app_test_settings.nasl", "torture_cgi_injectable_param.nasl", "torture_cgi_load_estimation2.nasl");
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
flaws_and_patterns = make_array(
"%0D%0AX-foo:%20bar",		"PI:X-foo:*",
"%00%0D%0AX-foo:%20bar",	"PI:X-foo:*"
);

port = torture_cgi_init(vul:'HI');


# No need to follow redirections here
report = torture_cgis(port: port, vul: "HI", injectable_only: INJECTABLE_TEXT);

if (strlen(report) > 0)
{
  security_warning(port:port, extra: report);
}
