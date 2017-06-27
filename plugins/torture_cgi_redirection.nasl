#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(47834);
 script_version ("$Revision: 1.16 $");
 script_cvs_date("$Date: 2017/01/05 15:28:31 $");

 script_name(english: "CGI Generic Open Redirection");


 script_set_attribute(attribute:"synopsis", value:
"A web application is potentially vulnerable to uncontrolled
redirection." );
 script_set_attribute(attribute:"description", value:
"By providing specially crafted parameters to CGIs, Nessus was able to
redirect to a third-party website.

As redirections are commonly used, it is possible that users will be
unaware that something abnormal is happening.

This kind of attack can be used to steal confidential data, typically
credentials (phishing)." );
 script_set_attribute(attribute:"see_also", value:"http://en.wikipedia.org/wiki/URL_redirection#Manipulating_visitors");
 script_set_attribute(attribute:"see_also", value:"http://www.owasp.org/index.php/Open_redirect");
 script_set_attribute(attribute:"solution", value:
"Modify the relevant CGIs so that they properly escape arguments." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
 script_cwe_id(
   601, # URL Redirection to Untrusted Site 'Open Redirect'
   722, # OWASP Top Ten 2004 Category A1 - Unvalidated Input
   801, # 2010 Top 25 - Insecure Interaction Between Components
   819,  # OWASP Top Ten 2010 Category A10 - Unvalidated Redirects and Forwards
   928, # Weaknesses in OWASP Top Ten 2013
   938  # OWASP Top Ten 2013 Category A10 - Unvalidated Redirects and Forwards
  );
 script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/26");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_summary(english: "Redirection attack");
 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2010-2017 Tenable Network Security, Inc.");
 script_family(english: "CGI abuses");
 script_dependencie("http_version.nasl", "webmirror.nasl", "web_app_test_settings.nasl", "torture_cgi_injectable_param.nasl", "torture_cgi_load_estimation2.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("Settings/enable_web_app_tests");
 script_timeout(43200);	# Timeout is managed by the script itself
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("torture_cgi.inc");

function torture_cgi_response_post_check(resp) { return 0; }	# stub

####

url_re = "https?://[a-z0-9.-]*www\.example\.com/";

i = 0;
headers_patterns[i++] = "RE:^Location: *" + url_re;
headers_patterns[i++] = "RE:^Refresh: *[0-9]+; *url="+url_re;
body_patterns[i++] = 'RE:<meta +http-equiv="refresh" content="[0-9]+;url='+url_re+'">';
body_patterns[i++] = 'RE:(window|document)\\.location="'+url_re+'"';

flaws_and_patterns = make_array(
  ".example.com",				"EX",
  "%00http://www.example.com",			"EX",
  "HtTp://www.example.com",			"EX",
  "%68%74%74%70%3a%2f%2fwww.example.com",	"EX",
  "%2568%2574%2574%2570%253a%252f%252fwww.example.com",	"EX",
  " http://www.example.com",			"EX",
  "https://www.example.com",			"EX",
  "www.example.com",				"EX",
  "http://www.example.com",			"EX"
);

####

port = torture_cgi_init(vul:'RD');


report = torture_cgis(port: port, vul: "RD", injectable_only: INJECTABLE_TEXT);

if (strlen(report) > 0)
{
  security_warning(port:port, extra: report);
}
