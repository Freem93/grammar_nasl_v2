#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62029);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/09/10 20:33:05 $");

  script_name(english:"SquidClamav Detection");
  script_summary(english:"Checks for presence of SquidClamav");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts an antivirus application.");
  script_set_attribute(attribute:"description", value:
"The remote web server hosts SquidClamav, an antivirus for Squid proxy
based on the ClamAV antivirus toolkit.");
  script_set_attribute(attribute:"see_also", value:"http://squidclamav.darold.net");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/10");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:darold:squidclamav");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80);

dirs = cgi_dirs();
checks = make_array();

regexes = make_list();
regexes[0] = make_list('SquidClamAv (.+)');
regexes[1] = make_list('SquidClamAv ([0-9.]+($|[^0-9])*([0-9]+)*)</a>', 'SquidClamAv ([0-9.]+($|[^0-9\n])*([0-9]+)*)');
checks["/clwarn.cgi"] = regexes;

installs = find_install(appname:"squidclamav", checks:checks, dirs:dirs, port:port);

if (isnull(installs)) audit(AUDIT_WEB_APP_NOT_INST, "SquidClamav", port);

report = NULL;
if (report_verbosity > 0)
{
  report = get_install_report(
    display_name: "SquidClamav",
    installs    : installs,
    port        : port,
    item        : "/clwarn.cgi"
  );
}
security_note(port:port, extra:report);
