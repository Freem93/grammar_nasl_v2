#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81384);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/09/24 21:08:39 $");

  script_name(english:"Fortinet FortiAuthenticator Default Credentials");
  script_summary(english:"Checks for default credentials.");

  script_set_attribute(attribute:"synopsis", value:"The remote host is using a known set of default credentials.");
  script_set_attribute(attribute:"description", value:
"Nessus was able to login to the remote FortiAuthenticator device using
the default password for the 'admin' account. A remote attacker can
exploit this to gain administrative control of the device.");
  # http://docs.fortinet.com/uploaded/files/1281/fortiauthenticator-admin-12.pdf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b80b7064");
  script_set_attribute(attribute:"solution", value:
"Change the password for the default 'admin' account.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_publication_date", value:"2015/02/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:fortinet:fortiauthenticator");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("fortiauthenticator_webapp_detect.nbin");
  script_require_keys("installed_sw/Fortinet FortiAuthenticator");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_ports("Services/www", 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

app = 'Fortinet FortiAuthenticator';
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:443);
install = get_single_install(app_name:app, port:port);

login_url = build_url(qs:'/login/', port:port);

user = 'admin';
pass = '';

res = http_send_recv3(
  method:'GET',
  item:'/login/',
  port:port,
  exit_on_fail:TRUE
);

# name='csrfmiddlewaretoken' value='fphn9FdLw8Jn7myWnB00YrWAm1nuNT29'
item = eregmatch(pattern:"name\s*=\s*'csrfmiddlewaretoken'\s*value\s*=\s*'([^']+)'",
                 string:res[2]);

if(isnull(item) && isnull(item[1]))
  exit(0, 'Unable to parse anti-CSRF token on login page for web server on port ' + port + '.');

token = item[1];

postdata = 'username=' + user + '&password=' + pass + '&csrfmiddlewaretoken=' + token;

res = http_send_recv3(
  method:'POST',
  content_type:'application/x-www-form-urlencoded',
  add_headers:make_array('referer', build_url(port:port, qs:'/login/')),
  data:postdata,
  item:'/login/',
  follow_redirect:1,
  port:port,
  exit_on_fail:TRUE
);

if (
  'FortiAuthenticator' >< res[2] &&
  '<span>Administration</span>' >< res[2])
{
  if (report_verbosity > 0)
  {
    report = '
Nessus was able to gain access using the following information :

  URL      : '+login_url+'
  User     : '+user+'
  Password : <blank>\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, login_url);
