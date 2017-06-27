#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66234);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/12/17 20:21:34 $");

  script_name(english:"Puppet Enterprise Console Detection");
  script_summary(english:"Checks for the login page.");

  script_set_attribute(attribute:"synopsis", value:
"The front-end for an IT automation application was detected on the
remote web server.");
  script_set_attribute(attribute:"description", value:
"Puppet Enterprise Console, a web management interface for Puppet
Enterprise, was detected on the remote web server.");
  # http://docs.puppetlabs.com/pe/2.0/welcome_getting_started.html#about-the-console
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?860cdc6b");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/26");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:puppetlabs:puppet");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:443);

urls = make_list('/cas/login', '/auth/login');
found = FALSE;

foreach url (urls)
{
  res = http_send_recv3(
    method : 'GET',
    item : url,
    port : port
  );

  if (
    '<title>Puppet Enterprise Console</title>' >< res[2] ||
    '<h1>Puppet Enterprise Console Login</h1>' >< res[2] ||
    '<title>Log In | Puppet Enterprise</title>' >< res[2] ||
    '<title>Puppet Enterprise Console - Log In</title>' >< res[2]
  )
  {
    found = TRUE;
    break;
  }
}

if (!found) audit(AUDIT_WEB_APP_NOT_INST, 'Puppet Console', port);

dir = '';
install = add_install(
    appname:'puppet_enterprise_console',
    dir:dir,
    port:port
);

if (report_verbosity > 0)
{
  report = get_install_report(
      display_name:'Puppet Enterprise Console',
      installs:install,
      port:port
  );
  security_note(port:port, extra:report);
}
else security_note(port);
