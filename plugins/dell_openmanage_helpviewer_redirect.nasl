#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(46738);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/09/24 21:08:38 $");

  script_bugtraq_id(40247);
  script_osvdb_id(64728);
  script_xref(name:"Secunia", value:"39879");

  script_name(english:"Dell OpenManage Server Administrator 'HelpViewer' Redirect");
  script_summary(english:"Tries to exploit the redirect weakness");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts an application with an open redirect.");
  script_set_attribute(attribute:"description", value:
"Dell OpenManage Server Administrator appears to be installed on the
remote host.  The installed version fails to validate input passed to
the 'file' parameter in '/servlet/HelpViewer' before redirecting an
unauthenticated user to the location it specifies.

An attacker may be able to exploit this issue to conduct phishing
attacks by tricking users into visiting malicious websites.");
  script_set_attribute(attribute:"solution", value:"Unknown at this time.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/05/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/05/26");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:dell:openmanage");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");

  script_dependencies("dell_openmanage.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www",1311);
  script_require_keys("www/dell_omsa");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");
include("audit.inc");

port = get_http_port(default:1311, embedded:TRUE);
install = get_install_from_kb(appname:"dell_omsa", port:port, exit_on_fail:TRUE);
base_url = build_url(qs:install['dir'], port:port);
	
# Try to exploit the issue.
redirect = "http://www.nessus.org";
url = install["dir"] + "/servlet/HelpViewer?" + "file=" + redirect;

res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);

hdrs = parse_http_headers(status_line:res[0], headers:res[1]);
if (isnull(hdrs['$code'])) code = 0;
else code = hdrs['$code'];

if (isnull(hdrs['location'])) location = "";
else location = hdrs['location'];

# There's a problem if ...
if (
  # we're redirected and ...
  code == 302 &&
  # it's to the location we specified
  redirect == location
)
{
  if (report_verbosity > 0)
  {
    report = '\n' +
      'Nessus was able to verify the issue using the following URL :' + '\n' +
      '\n' +
      ' ' + build_url(port:port, qs:url) + '\n';
    
    security_warning(port:port, extra:report);
  }
  else security_warning(port);

  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, 'Dell OpenManage Server Administrator', base_url);
