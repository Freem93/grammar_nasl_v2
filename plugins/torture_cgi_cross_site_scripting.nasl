#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(39466);
 script_version ("$Revision: 1.39 $");


 script_name(english: "CGI Generic XSS (quick test)");


 script_set_attribute(attribute:"synopsis", value:
"The remote web server is prone to cross-site scripting attacks." );
 script_set_attribute(attribute:"description", value:
"The remote web server hosts CGI scripts that fail to adequately sanitize 
request strings with malicious JavaScript.  By leveraging this issue, 
an attacker may be able to cause arbitrary HTML and script code
to be executed in a user's browser within the security context of the
affected site.
These XSS are likely to be 'non persistent' or 'reflected'." );
 script_set_attribute(attribute:"see_also", value:"http://en.wikipedia.org/wiki/Cross_site_scripting#Non-persistent" );
 # http://jeremiahgrossman.blogspot.com/2009/06/results-unicode-leftright-pointing.html
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9717ad85");
 script_set_attribute(attribute:"see_also", value:"http://projects.webappsec.org/Cross-Site+Scripting");
 script_set_attribute(attribute:"solution", value:
"Restrict access to the vulnerable application. Contact the vendor 
for a patch or upgrade." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_cwe_id(
  20,  # Improper Input Validation
  74,  # Improper Neutralization of Special Elements in Output Used by a Downstream Component 'Injection'
  79,  # Cross-Site Scripting
  80,  # Improper Neutralization of Script-Related HTML Tags in a Web Page Basic XSS
  81,  # Improper Neutralization of Script in an Error Message Web Page
  83,  # Improper Neutralization of Script in Attributes in a Web Page
  86,  # Improper Neutralization of Invalid Characters in Identifiers in Web Pages
  116, # Improper Encoding or Escaping of Output
  442, # Web problems
  692, # Incomplete Blacklist to Cross-Site Scripting
  712, # OWASP Top Ten 2007 Category A1 - Cross-Site Scripting XSS
  722, # OWASP Top Ten 2004 Category A1 - Unvalidated Input
  725, # OWASP Top Ten 2004 Category A4 - Cross-Site Scripting XSS Flaws
  751, # 2009 Top 25 - Insecure Interaction Between Components
  801, # 2010 Top 25 - Insecure Interaction Between Components
  811, # OWASP Top Ten 2010 Category A2 - Cross-Site Scripting XSS
  928, # Weaknesses in OWASP Top Ten 2013
  931  # OWASP Top Ten 2013 Category A3 - Cross-Site Scripting XSS
 );
 script_set_attribute(attribute:"plugin_publication_date", value: "2009/06/19");
 script_cvs_date("$Date: 2017/01/05 15:28:31 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_summary(english: "Tortures the arguments of the remote CGIs (XSS)");
 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2009-2017 Tenable Network Security, Inc.");
 script_family(english: "CGI abuses : XSS");
 script_dependencie("http_version.nasl", "webmirror.nasl", "cross_site_scripting.nasl", "web_app_test_settings.nasl", "torture_cgi_load_estimation3.nasl", "torture_cgi_inject_html.nasl");
 script_require_ports("Services/www", 80);
 script_timeout(43200);	# Timeout is managed by the script itself
 script_require_keys("Settings/enable_web_app_tests");
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("torture_cgi.inc");

function torture_cgi_response_post_check(resp) { return 0; } # stub

####


i = 0; 
flaws_and_patterns = make_array(
# "<script>alert(101);</script>",   "ST:<script>alert(101);</script>",
  '<script>alert(102);</script>',   'RE:^([^"]|"([^"\\]|\\[\\"])*")*<script>alert\\(102\\);</script>',
  '"><script>alert(103);</script>', 'RE:[^\\\\]"><script>alert\\(103\\);</script>',
  '"><object type="text/html" data="http://www.example.com/include.html"></object>', 'RE:[^\\\\]"><object type="text/html" data="http://www.example.com/include.html"></object>',
 # This works with IE6, not Firefox
 '<IMG SRC="javascript:alert(104);">', 'ST:<IMG SRC="javascript:alert(104);">',

 "<BODY ONLOAD=alert(107)>",	 "ST:<BODY ONLOAD=alert(107)>",
  "<script > alert(108); </script >",   "RE:<script *> *alert\(108\); *</script *>",
  '%00"><script>alert(109)</script>', 'ST:"><script>alert(109)</script>"',
 '<script\n>alert(110);</script\n>', 'ST:<script\n>alert(110);</script\n>',
  '\'><script>alert(111);</script>', 'RE:[^\\\\]\'><script>alert\\(111\\);</script>',
# '--><script>alert(112)</script>',   'ST:--><script>alert(112)</script>',
  '"><frame name=frame113 id=frame113 src="javascript:alert(113);', 'RE:<[^>]*"[^">]*"><frame name=frame113 id=frame113 src="javascript:alert\\(113\\);.*".*>'
);

port = torture_cgi_init(vul: 'XS');


if (get_kb_item(strcat("www/", port, "/generic_xss")))
  exit(0, 'The web server is vulnerable to generic cross-site scripting');
# if (stop_at_first_flaw == "port" && ! thorough_tests && get_kb_item(strcat("www/", port, "/XSS"))) exit(0);

if (get_kb_item("Settings/PCI_DSS") || report_paranoia < 2)
  ct = "text/(xml|html)";
else
  ct = NULL;
report = torture_cgis(port: port, vul: "XS", only_content: ct, injectable_only: INJECTABLE_HTML, follow_redirect: 2);

if (strlen(report) > 0)
{
  security_warning(port:port, extra: report);
}
