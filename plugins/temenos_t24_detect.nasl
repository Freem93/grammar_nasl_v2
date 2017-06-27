#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62776);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/10/31 14:57:17 $");

  script_name(english:"Temenos T24 Detection");
  script_summary(english:"Looks for T24");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a banking application.");
  script_set_attribute(attribute:"description", value:
"The remote web server hosts Temenos T24, a web application used by
banks and other financial institutions to manage and deploy banking
services.");
  script_set_attribute(attribute:"see_also", value:"http://www.temenos.com/products/t24/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor",value:"None");

  script_set_attribute(attribute: "plugin_publication_date", value:"2012/10/31");
 
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:temenos:t24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80, 8080);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:8080);

if (thorough_tests) dirs = list_uniq(make_list("/temenos", cgi_dirs()));
else dirs = make_list(cgi_dirs());

checks = make_array();

regexes = make_list();
regexes[0] = make_list('target="help">www.temenos.com', '>T24 Sign in<');
checks["/BrowserWeb/portal/portalbanner.htm"] = regexes;

installs = find_install(appname:"temenos_t24", checks:checks, dirs:dirs, port:port);
if (isnull(installs)) audit(AUDIT_WEB_APP_NOT_INST, "Temenos T24", port);

report = NULL;
if (report_verbosity > 0)
{
  report = get_install_report(
    display_name : 'Temenos T24',
    installs     : installs,
    port         : port
  );
  security_note(port:port, extra:report);
}
else security_note(port);
