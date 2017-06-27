#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77114);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/11/18 20:40:52 $");

  script_name(english:"Halon Security Router User Interface Default Credentials");
  script_summary(english:"Attempts to login with default credentials.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web service is protected using a default set of known
credentials.");
  script_set_attribute(attribute:"description", value:
"The remote Halon Security Router user interface uses a known set of
default credentials. An attacker with access to the service can gain
administrative access to the device.

Additionally, these credentials allow SSH (if enabled) access to the
device with root privileges.");
  # http://sr.wiki.halon.se/wiki/Getting_started#Default_configuration
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bdbd2080");
  script_set_attribute(attribute:"solution", value:"Change the default admin login credentials.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:ND/RC:ND");

  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/11");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:halon:security_router");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("halon_sr_detect.nbin");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_keys("installed_sw/Halon Security Router");
  script_require_ports("Services/www", 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

app_name = "Halon Security Router";
get_install_count(app_name:app_name, exit_if_zero:TRUE);
if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

port = get_http_port(default:443);
install = get_single_install(app_name:app_name, port:port);

url = install['path'];
report_url = build_url(port:port, qs:url);

# Get Session cookie first.
init_cookiejar();

res = http_send_recv3(
  method:'GET',
  item:url,
  port:port,
  exit_on_fail:TRUE
);

username = 'admin';
password = 'admin';

postdata =
  'username=' + username + '&password=' + password;

res = http_send_recv3(
  method:'POST',
  item:url,
  data:postdata,
  port:port,
  content_type:'application/x-www-form-urlencoded',
  exit_on_fail:TRUE
);

# If login is successful, you get redirected, otherwise you're back
# at the login page with an invalid creds message.
if ("302" >< res[0] && "200" >!< res[0] && "Invalid credentials" >!< res[2])
{
  if (report_verbosity > 0)
  {
    header = 'Nessus was able to gain access using the following URL';
    trailer =
      'and the following set of credentials :' +
      '\n' +
      '\n' + '  User name : ' + username +
      '\n' + '  Password  : ' + password;

    report = get_vuln_report(
      items   : url,
      port    : port,
      header  : header,
      trailer : trailer
    );

    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app_name, report_url);
