#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(43005);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/12/09 20:54:57 $");

  script_name(english:"Request Tracker Default Credentials");
  script_summary(english:"Attempts to login as root / password.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is running a Perl application that uses default
credentials.");
  script_set_attribute(attribute:"description", value:
"It is possible to log into the Best Practical Solutions Request
Tracker (RT) application by providing default credentials. A remote
attacker can exploit this to gain administrative control.");
  script_set_attribute(attribute:"solution", value:
"Secure the root account with a strong password.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:ND/RC:ND");

  script_set_attribute(attribute:"plugin_publication_date", value:"2009/12/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:bestpractical:rt");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("rt_detect.nasl");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_ports("Services/www", 80);
  script_require_keys("installed_sw/RT");
  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

user = 'root';
pass = 'password';

app = 'RT';
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80);
install = get_single_install(app_name:app, port:port);

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

# Make sure the page exists before POSTing
url = install['path'] + '/index.html';
res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);
if ('<title>Login</title>' >!< res[2]) exit(1, 'Error requesting login page.');

# Then try to login
postdata = 'user='+user+'&pass='+pass;
res = http_send_recv3(
  method:'POST',
  item:url,
  data:postdata,
  content_type: 'application/x-www-form-urlencoded',
  port:port,
  exit_on_fail:TRUE
);

login_url = build_url(qs:url, port:port);

if ('Logged in as <span>'+user+'</span>' >< res[2])
{
  if (report_verbosity > 0)
  {
    report = '
Nessus was able to gain access using the following information :

URL      : '+login_url+'
User     : '+user+'
Password : '+pass;
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, login_url);
