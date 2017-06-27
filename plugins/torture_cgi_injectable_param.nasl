#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(47830);
 script_version("$Revision: 1.14 $");
 script_cvs_date("$Date: 2017/01/05 15:28:31 $");

 script_cwe_id(86);	# Improper Neutralization of Invalid Characters in Identifiers in Web Pages

 script_name(english:"CGI Generic Injectable Parameter");

 script_set_attribute(attribute:"synopsis", value:
"Some CGIs are candidate for extended injection tests.");
 script_set_attribute(attribute:"description", value:
"Nessus was able to to inject innocuous strings into CGI parameters
and read them back in the HTTP response.

The affected parameters are candidates for extended injection tests
like cross-site scripting attacks.

This is not a weakness per se, the main purpose of this test is to speed
up other scripts.  The results may be useful for a human pen-tester.");
 script_set_attribute(attribute:"solution", value:"n/a");
 script_set_attribute(attribute:"risk_factor", value: "None");
 script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/26");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_summary(english:"Tortures the arguments of the remote CGIs (injection)");
 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2010-2017 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
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

str = rand_str(length: 6, charset: "abcdefghijklmnopqrstuvwxyz");

flaws_and_patterns = make_array(
 str,		"EX",
 "%00"+str,	"EX"
);

i = 0;
body_patterns[i++] = "ST:"+str;
headers_patterns[i++] = "ST:"+str;
body_patterns[i++] = "PI:*"+str+"*";
headers_patterns[i++] = "PI:*"+str+"*";

stop_at_first_flaw = "param";	# This is a special script

port = torture_cgi_init(vul:'YY');

report = torture_cgis(port: port, vul: "YY", follow_redirect: 2);

if (strlen(report) > 0)
{
  security_note(port:port, extra: report);
}
