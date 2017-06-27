#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(50987);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/11/23 20:42:23 $");

  script_name(english:"Pandora FMS Console Default Credentials");
  script_summary(english:"Tries to login as admin");

  script_set_attribute(attribute:"synopsis", value:"The remote web application uses default credentials.");
  script_set_attribute(
    attribute:"description",
    value:
"It is possible to log into the remote Pandora FMS console by providing
the default credentials (admin / pandora). A remote attacker can
exploit this to gain administrative control of the Pandora FMS
installation."
  );
  script_set_attribute(attribute:"solution", value:"Secure the admin account with a strong password.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:ND/RC:ND");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/12/06");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:artica:pandora_fms");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("pandora_fms_console_detect.nasl");
  script_require_keys("installed_sw/Pandora FMS");
  script_exclude_keys("Settings/disable_cgi_scanning", "global_settings/supplied_logins_only");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

app = 'Pandora FMS';
get_install_count(app_name:app, exit_if_zero:TRUE);
port = get_http_port(default:80, php:TRUE);
install = get_single_install(app_name:app, port:port);

url = install['path'] + '/index.php?login=1';
login_url = build_url(qs:url, port:port);

user = 'admin';
pass = 'pandora';

postdata = 'nick=' + user + '&pass=' + pass + '&unnamed=Login';
res = http_send_recv3(
  method:'POST',
  content_type:'application/x-www-form-urlencoded',
  data:postdata,
  item:url,
  port:port,
  exit_on_fail:TRUE
);

if (
  '[<b>' + user + '</b>]</a>' >< res[2] &&
  'Welcome to Pandora FMS Web Console</ul>' >< res[2] &&
  'Access to this page is restricted to authorized users only' >!< res[2]
)
{
  if (report_verbosity > 0)
  {
    report = '
Nessus was able to gain access using the following information :

  URL      : '+login_url+'
  User     : '+user+'
  Password : '+pass + '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, login_url);
