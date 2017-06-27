#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(24278);
  script_version("$Revision: 1.23 $");
  script_cvs_date("$Date: 2016/05/23 21:23:02 $");

  script_cve_id("CVE-2007-0817");
  script_bugtraq_id(22401);
  script_osvdb_id(32120);
  script_xref(name:"EDB-ID", value:"29567");

  script_name(english:"ColdFusion Web Server User-Agent HTTP Header Error Message XSS");
  script_summary(english:"Checks for an XSS flaw in ColdFusion.");

  script_set_attribute(attribute:"synopsis", value:
"An application running on the remote web server is affected by a
cross-site scripting vulnerability.");
 script_set_attribute(attribute:"description", value:
"The version of Adobe ColdFusion running on the remote host fails to
properly sanitize user-supplied input to the User-Agent header before
using it to generate dynamic content in an error page. A remote,
unauthenticated attacker can exploit this issue to inject arbitrary
HTML or script code into a user's browser to be executed within the
security context of the affected site.");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/459178/30/0/threaded" );
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb07-04.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch as described in the vendor advisory above.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/02/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/02/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/02/06");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:adobe:coldfusion");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");

  script_dependencies("coldfusion_detect.nasl");
  script_require_keys("installed_sw/ColdFusion");
  script_require_ports("Services/www", 80, 8500);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");
include("install_func.inc");

app = 'ColdFusion';
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80);

install = get_single_install(
  app_name : app,
  port     : port
);

dir = install['path'];
install_url = build_url(port:port, qs:dir);

# Send a request to exploit the flaw.
xss = "<script>alert("+SCRIPT_NAME -".nasl"+"-"+unixtime()+")</script>";
url = "/CFIDE/administrator/nessus-" + unixtime()+".cfm";
r = http_send_recv3(method:"GET", item:dir+url, port:port, exit_on_fail: TRUE,
  add_headers: make_array("User-Agent", xss));
res = r[2];

# There's a problem if our exploit appears as the user agent.
browser = strstr(res, ">Browser&nbsp;&nbsp;</");
if (browser)
{
  browser = browser - strstr(browser, "</tr>");
  browser = strstr(browser, "<td>");
  browser = browser - strstr(browser, "</td>");
  # nb: browser includes some extra markup.
  if (">"+ xss >< browser)
  {
    security_report_v4(
     port       : port,
     severity   : SECURITY_WARNING,
     generic    : TRUE,
     xss        : TRUE,  # XSS KB key
     request    : make_list(http_last_sent_request()),
     output     : chomp(browser)
    );
    exit(0);
  }
}
else
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);
