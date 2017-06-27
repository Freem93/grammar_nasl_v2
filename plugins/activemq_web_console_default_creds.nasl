#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81375);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/09/24 20:59:27 $");

  script_name(english:"Apache ActiveMQ Web Console Default Credentials");
  script_summary(english:"Tries to login with default credentials.");

  script_set_attribute(attribute:"synopsis", value:
"A web application administrative console is protected using default
credentials.");
  script_set_attribute(attribute:"description", value:
"ActiveMQ Web Console, an administrative interface for Apache ActiveMQ,
is protected using default credentials. Note that no authentication
mechanism was provided prior to version 5.4.0. However, in version
5.4.0, HTTP Basic Authentication was an option, and starting with
version 5.8.0, this was enabled by default.");
  script_set_attribute(attribute:"see_also", value:"http://activemq.apache.org/web-console.html");
  script_set_attribute(attribute:"see_also", value:"http://activemq.apache.org/getting-started.html");
  script_set_attribute(attribute:"solution", value:
"Restrict access to ActiveMQ Web Console, using one of the methods
described at the referenced URLs, or change the default login
credentials.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_publication_date", value:"2015/02/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:activemq");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("activemq_web_console_detect.nasl");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_keys("installed_sw/ActiveMQ");
  script_require_ports("Services/www", 8161);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = 'ActiveMQ';
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:8161);

install = get_single_install(
  app_name : app,
  port     : port
);

dir = install['path'];
install_url = build_url(port:port, qs:dir);

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

clear_cookiejar();

user = "admin";
pass = "admin";

res = http_send_recv3(
  method       : "GET",
  item         : "/admin/",
  port         : port,
  username     : user,
  password     : pass,
  exit_on_fail : TRUE
);

if ( ('ActiveMQ Console</title>' >< res[2]) &&
   (ereg(
      pattern : 'Welcome to the (Apache )?ActiveMQ Console',
      string  : res[2],
      multiline : TRUE
  ))
)
{
  info +=
    '\n  Username : ' + user +
    '\n  Password : ' + pass + '\n';

  if (report_verbosity > 0)
  {
    report = '\n' +
      'Nessus was able to gain access using the following URL :\n' +
      '\n' +
      '  ' + install_url + '\n' +
      '\n' +
      'and the following set of credentials :\n' +
      info;
      security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);
