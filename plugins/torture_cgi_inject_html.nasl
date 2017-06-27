#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(49067);
 script_version ("$Revision: 1.13 $");
 script_cvs_date("$Date: 2017/01/05 15:28:31 $");


 script_name(english: "CGI Generic HTML Injections (quick test)");
 script_summary(english: "Tortures the arguments of the remote CGIs (HTML injection)");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server may be prone to HTML injections." );
 script_set_attribute(attribute:"description", value:
"The remote web server hosts CGI scripts that fail to adequately sanitize 
request strings with malicious JavaScript.  By leveraging this issue, 
an attacker may be able to cause arbitrary HTML to be executed in a 
user's browser within the security context of the affected site.

The remote web server may be vulnerable to IFRAME injections or 
cross-site scripting attacks :

  - IFRAME injections allow 'virtual defacement' that 
    might scare or anger gullible users. Such injections 
    are sometimes implemented for 'phishing' attacks. 

  - XSS are extensively tested by four other scripts.

  - Some applications (e.g. web forums) authorize a subset
    of HTML without any ill effect. In this case, ignore 
    this warning." ); 
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f8fdd645");
 script_set_attribute(attribute:"solution", value:
"Either restrict access to the vulnerable application or contact the
vendor for an update." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_cwe_id(
   80,	# Improper Neutralization of Script-Related HTML Tags in a Web Page Basic XSS
   86	# Improper Neutralization of Invalid Characters in Identifiers in Web Pages
 );
 script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/01");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2010-2017 Tenable Network Security, Inc.");
 script_family(english: "CGI abuses : XSS");
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

function torture_cgi_response_post_check(resp)  { return 0; }   # stub

####

i = 0; 
str = '<"'+rand_str(length: 6, charset: "abcdefghijklmnopqrstuvwxyz");
flaws_and_patterns = make_array(
 "%00"+str+" >",	"EX",
 "<<<"+str+"%20>>>",	"EX",
 "%00<<<"+str+"%20>>>",	"EX",
 str+'%0A>',		"EX",
 str+"%20>",		"EX"
);

# i++ is needed at all lines, this is not a bug! See extract_pattern_from_resp()
i = 0; 
body_patterns[i++] = "ST:"+str;
headers_patterns[i++] = "ST:"+str;
body_patterns[i++] = "PI:*"+str+"*";
headers_patterns[i++] = "PI:*"+str+"*";

if (get_kb_item("Settings/PCI_DSS") || report_paranoia < 2)
  ct = "text/(xml|html)";
else
  ct = NULL;

port = torture_cgi_init(vul:'YZ');
stop_at_first_flaw = "param";	# This is a special script


report = torture_cgis(port: port, vul: "YZ", only_content: ct, injectable_only: INJECTABLE_TEXT, follow_redirect: 2);

if (strlen(report) > 0)
{
  security_warning(port:port, extra: report);
}
