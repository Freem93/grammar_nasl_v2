#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62717);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/10/27 01:06:02 $");

  script_name(english:"Mutiny Detection");
  script_summary(english:"Looks for Mutiny");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a network monitoring application.");
  script_set_attribute(attribute:"description", value:
"The remote web server hosts Mutiny, a network monitoring application
that uses SNMP to gather infrastructure information and process and
display the results in a web-based interface.  This information is used
to assess the health of network devices.");
  script_set_attribute(attribute:"see_also", value:"http://www.mutiny.com/products.php");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor",value:"None");

  script_set_attribute(attribute: "plugin_publication_date", value:"2012/10/26");
 
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mutiny:standard");
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

if (thorough_tests) dirs = list_uniq(make_list("/mutiny", cgi_dirs()));
else dirs = make_list(cgi_dirs());

checks = make_array();

regexes = make_list();
regexes[0] = make_list('href="http://www.mutiny.com" target=', 'Mutiny : Login');
regexes[1] = make_list('var currentMutinyVersion = "Version ([0-9.-]+)');
checks["/interface/index.do"] = regexes;

installs = find_install(
  appname : "mutiny",
  checks  : checks,
  dirs    : dirs,
  port    : port
);
if (isnull(installs)) audit(AUDIT_WEB_APP_NOT_INST, "Mutiny", port);

report = NULL;
if (report_verbosity > 0)
{
  report = get_install_report(
    display_name : 'Mutiny',
    installs     : installs,
    port         : port
  );
  security_note(port:port, extra:report);
}
else security_note(port);
