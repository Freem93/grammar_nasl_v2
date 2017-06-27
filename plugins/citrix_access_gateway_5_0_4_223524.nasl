#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65952);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/11/17 21:12:12 $");

  script_cve_id("CVE-2013-2263");
  script_bugtraq_id(58317);
  script_osvdb_id(90905);

  script_name(english:"Citrix Access Gateway 5.x < 5.0.4.223524 Unspecified Security Bypass");
  script_summary(english:"Examines the HTTP response reason phrase of a login failure");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a Java application that is affected by a
security bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Citrix Access Gateway hosted on the remote web server
contains an unspecified security bypass vulnerability.");
  script_set_attribute(attribute:"solution", value:"Update to version 5.0.4.223524 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"see_also", value:"http://support.citrix.com/article/CTX136623");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/03/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:citrix:access_gateway");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("citrix_access_gateway_admin_detect.nasl", "citrix_access_gateway_user_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("www/citrix_access_gateway_admin", "www/citrix_access_gateway_user");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http.inc");
include("misc_func.inc");
include("webapp_func.inc");

app = "Citrix Access Gateway Web Interface";

# Get the ports that webservers have been found on, defaulting to
# CAG's default HTTPS port for the user interface.
port = get_http_port(default:443);

# Get details of the CAG install. The issue is in the shared
# admin/user login endpoint, but we may not have been able to detect
# the one side of the interface, either because the admin side is on
# another interface, or if for the user side there was no default 'lp'
# (login point) configured.
kb = "citrix_access_gateway_";
install = get_install_from_kb(appname:kb + "admin", port:port, exit_on_fail:FALSE);
if (isnull(install))
  install = get_install_from_kb(appname:kb + "user", port:port, exit_on_fail:TRUE);
dir = install["dir"];

# Affected versions of CAG let an exception get to the response reason
# phrase due to not checking for NULL.
url = dir + "/u/LoginAuth.do";
res = http_send_recv3(
  port         : port,
  method       : "GET",
  item         : url,
  exit_on_fail : TRUE
);

if ("java.lang.NullPointerException" >!< res[0]) audit(AUDIT_WEB_APP_NOT_AFFECTED, app, build_url(port:port, qs:dir));

# Report our findings.
report = NULL;

if (report_verbosity > 0)
{
  report =
    '\nNessus was able to trigger the issue by sending a GET request to :' +
    '\n' +
    '\n  ' + build_url(port:port, qs:url) +
    '\n' +
    '\nWhich caused the server to respond with the HTTP status line :' +
    '\n' +
    '\n  ' + res[0] +
    '\n';
}

security_warning(port:port, extra:report);
