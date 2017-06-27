#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66972);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/06/25 01:11:26 $");

  script_name(english:"SolusVM Detection");
  script_summary(english:"Looks for SolusVM admin interface");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server contains a virtual server control
manager."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host is running Solus Virtual Manager (SolusVM), a
GUI based virtual server management system with a web interface
written in PHP."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.solusvm.com/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/24");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:solusvm:solusvm");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 5353, 5656);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:5353);
dirs = make_list("/");

checks = make_array();
regexes = make_list();

regexes[0] = make_list(
  '>SolusVM Admin Login<',
  '20[0-9][0-9]-20[0-9][0-9] Soluslabs Ltd. All Rights Reserved.'
);
checks["/admincp/login.php"] = regexes;

installs = find_install(
  appname : "solusvm",
  checks  : checks,
  dirs    : dirs,
  port    : port
);

if (isnull(installs)) audit(AUDIT_WEB_APP_NOT_INST, "SolusVM", port);

if (report_verbosity > 0)
{
  report = get_install_report(
    display_name : 'SolusVM',
    installs     : installs,
    port         : port,
    item         : "/admincp/login.php"
  );
  security_note(port:port, extra:report);
}
else security_note(port);
