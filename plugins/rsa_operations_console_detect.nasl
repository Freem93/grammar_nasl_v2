#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(55507);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/08/09 00:11:24 $");

  script_name(english:"RSA Operations Console Detection");
  script_summary(english:"Examines the HTML from the app's initial page");

  script_set_attribute(attribute:"synopsis", value:"The remote web server hosts a security-related application.");
  script_set_attribute(
    attribute:"description",
    value:
"The remote web server hosts an RSA Operations Console, which is used
with RSA appliances to configure replication as well as RADIUS or LDAP
authentication sources, perform backups, perform updates, and alter
network configurations."
  );
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/07/05");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2011-2014 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 7072);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");


port = get_http_port(default:7072);


installs = NULL;
dir = '/operations-console';
url = dir + '/';

res = http_send_recv3(port:port, method:"GET", item:url, exit_on_fail:TRUE);
if (
  "rsa-ops-session=" >< res[1] &&
  (
    'title>RSA Operations Console' >< res[2] ||
    'The Operations Console supports RSA products.' >< res[2]
  ) &&
  '/common/scripts/tigratree/tree.js"></script>' >< res[2] &&
  egrep(pattern:'<form name="LoginForm".+ConsoleSecurity\\.do', string:res[2])
)
{
  version = NULL;

  # Save info about the install.
  installs = add_install(
    appname  : "rsa_operations_console",
    installs : installs,
    port     : port,
    dir      : dir,
    ver      : version
  );

}
if (isnull(installs))
  exit(0, "RSA Operations Console was not detected on the web server on port "+port+".");


# Report findings.
if (report_verbosity > 0)
{
  report = get_install_report(
    port         : port,
    installs     : installs,
    display_name : "RSA Operations Console"
  );
  security_note(port:port, extra:report);
}
else security_note(port);
