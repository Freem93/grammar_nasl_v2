#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(35580);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/11/23 20:42:23 $");

  script_name(english:"Profense Web Application Firewall Default Credentials");
  script_summary(english:"Attempts to login with default credentials");

  script_set_attribute(attribute:"synopsis", value:"The remote web application can be accessed with default credentials.");
  script_set_attribute(attribute:"description", value:
"Armorlogic Profense Web Application Firewall is installed on the remote
host. It is possible to log into the web management interface using
default credentials.");
  script_set_attribute(attribute:"see_also", value:"http://www.armorlogic.com/manual/index.htm");
  script_set_attribute(attribute:"solution", value:
"Refer to the documentation and follow the steps to change the default
password." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:ND/RC:ND");

  script_set_attribute(attribute:"plugin_publication_date", value:"2009/02/03");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_ports("Services/www", 2000);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:2000);
if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

url = "/auth.html?mode=login";

res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);

if ("Profense management login" >< res[2])
{
  install_url = build_url(port:port, qs:url);
  res = http_send_recv3(
    method:"POST",
    item:url,
    port:port,
    add_headers: make_array("Content-Type", "application/x-www-form-urlencoded"),
    data:"username=admin&passwd=admin123",
    exit_on_fail:TRUE
  );

  if (
    "Set-Cookie:" >< res[1] &&
    'system.html?action=updates' >< res[1]
  )
  {
    if (report_verbosity > 0)
    {
      report =
        '\n' +
        'Nessus could log into the web management interface using the \n' +
        'following credentials :\n' +
        '\n' +
        'User     : admin' + '\n' +
        'Password : admin123' + '\n' +
        'URL      : ' + install_url + '\n';
      security_hole(port:port,extra:report);
    }
    else security_hole(port);
  }
  else audit(AUDIT_WEB_APP_NOT_AFFECTED, "Profense Web Application Firewall", install_url);
}
else audit(AUDIT_WEB_APP_NOT_INST, "Profense Web Application Firewall", port);
