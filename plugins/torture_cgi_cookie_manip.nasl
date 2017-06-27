#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(44136);
 script_version("$Revision: 1.15 $");

 script_name(english: "CGI Generic Cookie Injection Scripting");
 script_summary(english: "Tortures the arguments of the remote CGIs (cookie injection)");


 script_set_attribute(attribute:"synopsis", value:
"The remote web server is prone to cookie injection attacks." );
 script_set_attribute(attribute:"description", value:
"The remote web server hosts at least one CGI script that fails to
adequately sanitize request strings with malicious JavaScript. 

By leveraging this issue, an attacker may be able to inject arbitrary
cookies.  Depending on the structure of the web application, it may be
possible to launch a 'session fixation' attack using this mechanism. 

Please note that :

  - Nessus did not check if the session fixation attack is
    feasible.

  - This is not the only vector of session fixation." );
 script_set_attribute(attribute:"see_also", value:"http://en.wikipedia.org/wiki/Session_fixation" );
 script_set_attribute(attribute:"see_also", value:"http://www.owasp.org/index.php/Session_Fixation" );
 script_set_attribute(attribute:"see_also", value:"http://www.acros.si/papers/session_fixation.pdf" );
 script_set_attribute(attribute:"see_also", value:"http://projects.webappsec.org/Session-Fixation");
 script_set_attribute(attribute:"solution", value:
"Restrict access to the vulnerable application.  Contact the vendor
for a patch or upgrade." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_cwe_id(
   472,	# External Control of Assumed-Immutable Web Parameter
   642,	# External Control of Critical State Data
   715,	# OWASP Top Ten 2007 Category A4 - Insecure Direct Object Reference
   722	# OWASP Top Ten 2004 Category A1 - Unvalidated Input
 );
 script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/25");
 script_cvs_date("$Date: 2017/01/05 15:28:31 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2010-2017 Tenable Network Security, Inc.");
 script_family(english: "CGI abuses");

 script_dependencie("http_version.nasl", "webmirror.nasl", "cookie_manipulation.nasl", "torture_cgi_inject_html.nasl", "web_app_test_settings.nasl", "torture_cgi_load_estimation3.nasl");
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
cookie_name = "test"+rand_str(charset: "abcdefghijklmnopqrstuvwxyz", length: 4);
cookie_val  = rand() % 10000 + 1;	# No 0

flaws_and_patterns = make_array(
  '<script>document.cookie="'+cookie_name+'='+cookie_val+';"</script>',
  'ST:<script>document.cookie="'+cookie_name+'='+cookie_val+';"</script>',

  '<meta http-equiv=Set-Cookie content="'+cookie_name+'='+cookie_val+'">',
  'ST:<meta http-equiv=Set-Cookie content="'+cookie_name+'='+cookie_val+'">'
);

#
port = torture_cgi_init(vul:'CM');


if (get_kb_item(strcat("www/", port, "/generic_xss")))
  exit(0, 'The web server is vulnerable to generic cross-site scripting');
# if (stop_at_first_flaw == "port" && ! thorough_tests && get_kb_item(strcat("www/", port, "/XSS"))) exit(0);

report = torture_cgis(port: port, vul: "CM", injectable_only: INJECTABLE_HTML, follow_redirect: 2);

if (strlen(report) > 0)
{
  security_warning(port:port, extra: report);
}
