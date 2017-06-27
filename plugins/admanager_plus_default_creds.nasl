#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(46786);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/11/11 19:58:27 $");

  script_name(english:"ManageEngine ADManager Plus Default Credentials");
  script_summary(english:"Tries to login as admin");

  script_set_attribute(attribute:"synopsis", value:"The remote web application uses default credentials.");
  script_set_attribute(
    attribute:"description",
    value:
"It is possible to log into the remote ADManager Plus installation by
providing the default credentials.  A remote attacker could exploit
this to gain administrative control of the ADManager Plus
installation."
  );
  script_set_attribute(attribute:"solution", value:"Secure the admin account with a strong password.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:ND/RC:ND");

  script_set_attribute(attribute:"plugin_publication_date",value:"2010/06/02");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("admanager_plus_detect.nasl");
  script_require_ports("Services/www", 8080);
  script_require_keys("www/admanager_plus");
  script_exclude_keys("global_settings/supplied_logins_only");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");


user = 'admin';
pass = 'admin';

port = get_http_port(default:8080);

install = get_install_from_kb(appname:'admanager_plus', port:port, exit_on_fail:TRUE);

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

# We need to request the login page before the POST, even though they're
# different pages
url1 = install['dir'] + '/home.do';
res1 = http_send_recv3(method:"GET", item:url1, port:port);
if ('<title>ManageEngine - ADManager Plus</title>' >!< res1[2])
  exit(1, 'Error retrieving login page: '+build_url(qs:url1, port:port));

url2 = install['dir'] + '/j_security_check';
postdata = 'j_username='+user+'&'+'j_password='+pass;
res2 = http_send_recv3(
  method:'POST',
  item:url2,
  data:postdata,
  content_type:'application/x-www-form-urlencoded',
  port:port,
  follow_redirect:1,
  exit_on_fail:TRUE
);

# The actual POST is sent to j_security_check, but the login page is
# at /home.do
login_url = build_url(qs:url1, port:port);

# Look for evidence that the login was successful
if ('>Sign Out</a>' >< res2[2] && 'Invalid loginName/password' >!< res2[2])
{
  if (report_verbosity > 0)
  {
    report =
      '\n' +
      'Nessus was able to gain access using the following information :\n' +
      '\n' +
      '  URL      : ' + login_url +
      '  User     : ' + user + '\n' +
      '  Password : ' + pass + '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, "ADManager Plus", login_url);

