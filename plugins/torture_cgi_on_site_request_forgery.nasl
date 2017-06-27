#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(47832);
 script_version ("$Revision: 1.17 $");
 script_cvs_date("$Date: 2017/01/05 15:28:31 $");

 script_name(english: "CGI Generic On Site Request Forgery (OSRF)");


 script_set_attribute(attribute:"synopsis", value:
"The remote web server may be prone to On Site Request Forgery
attacks." );
 script_set_attribute(attribute:"description", value:
"The remote web server hosts CGI scripts that fail to adequately
sanitize request strings with special characters like dots, slashes,
backslashes, equal signs, question marks, etc.

By leveraging this issue, an attacker may be able to cause arbitrary
GET requests to be executed by a user when he visits the vulnerable
pages.

On Site Request Forgery (OSRF) is a variant of the wider Cross-Site
Request Forgery (CSRF) attack class.

** The web application will not be affected by this weakness if the
** sensitive operations are all performed through POST or if some common
** defenses against Cross-Site Request Forgery are implemented.
** Even if this weakness cannot be exploited in the current state of the
** web application, allowing users to inject arbitrary characters in
** pages is definitely dangerous." );

 script_set_attribute(attribute:"see_also", value:"http://en.wikipedia.org/wiki/Cross-site_request_forgery");
 # https://www.owasp.org/index.php/Cross-Site_Request_Forgery_%28CSRF%29
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ca62f8d0");
 script_set_attribute(attribute:"see_also", value:"http://blog.portswigger.net/2007/05/on-site-request-forgery.html");

 script_set_attribute(attribute:"solution", value:
"Restrict access to the vulnerable application.  Contact the vendor
for a patch or upgrade." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_cwe_id(
  345, # Insufficient Verification of Data Authenticity
  346, # Origin Validation Error
  352, # Cross-Site Request Forgery CSRF
  # 441, # Unintended Proxy/Intermediary
  # 613, # Insufficient session expiration
  # 642, # External Control of Critical State Data
  928, # Weaknesses in OWASP Top Ten 2013
  936 # OWASP Top Ten 2013 Category A8 - Cross-Site Request Forgery CSRF
 );
 script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/26");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_summary(english: "Tortures the arguments of the remote CGIs (OSRF)");
 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2010-2017 Tenable Network Security, Inc.");
 script_family(english: "CGI abuses");
 script_dependencie("http_version.nasl", "webmirror.nasl", "web_app_test_settings.nasl", "torture_cgi_injectable_param.nasl", "torture_cgi_load_estimation2.nasl");
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
 "../admin/noop.cgi?foo=bar&test=blah#",
 'RE:[ \t]src="[^"]*/admin/noop\\.cgi\\?foo=bar&test=blah#.*"'
);

port = torture_cgi_init(vul:'QO');


report = torture_cgis(port: port, vul: "QO", injectable_only: INJECTABLE_TEXT, follow_redirect: 2);

if (strlen(report) > 0)
{
  security_warning(port:port, extra: report);
}
