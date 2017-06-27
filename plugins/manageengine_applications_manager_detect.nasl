#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(63157);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/06/08 17:43:29 $");

  script_name(english:"ManageEngine Applications Manager Detection");
  script_summary(english:"Checks for evidence of ManageEngine Applications Manager.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is running a server and application performance
monitoring software product.");
  script_set_attribute(attribute:"description", value:
"The remote web server hosts ManageEngine Applications Manager, a
web-based server and application performance monitoring software
product written in Java.");
  script_set_attribute(attribute:"see_also", value:"https://www.manageengine.com/products/applications_manager/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/12/05");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:manageengine:applications_manager");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 9090);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

port = get_http_port(default:9090);
app = "ManageEngine Applications Manager";
installs = NULL;
version = NULL;
build = NULL;
url = '/index.do';

res = http_send_recv3(method:"GET", item:url, port:port, follow_redirect:1,exit_on_fail:TRUE);

if (
  egrep(pattern:'>?(\\s*[0-9]+)?\\s?(AdventNet Inc|ZOHO Corporation|ZOHO Corp|Zoho Corp)', string:res[2]) &&
  egrep(pattern:'<title>Applications Manager Login Screen</title>', string:res[2])
)
{
  match = eregmatch(
    pattern : '>?Applications Manager \\(Build No:([0-9]+)\\)',
    string  : res[2]
  );
  if (!empty_or_null(match[1]))
  {
    build = match[1];
    # Extract version from build number
    len = strlen(build);
    if (len == 5)
    {
      v1 = substr(build, 0, 1);
      v2 = substr(build, 2, 2);
      if ( (!empty_or_null(v1)) && (!empty_or_null(v2)) )
        version = v1 + "." + v2;
    }
    else
    {
      v1 = substr(build, 0, 0);
      v2 = substr(build, 1, 1);
      if ( (!empty_or_null(v1)) && (!empty_or_null(v2)) )
        version = v1 + "." + v2;
    }
  }
  if (empty_or_null(version))
    version = UNKNOWN_VER;
  if (empty_or_null(build))
    build = UNKNOWN_VER;

  # Save info about the install.
  register_install(
      app_name : app,
      path     : url,
      port     : port,
      version  : version,
      cpe      : "cpe:/a:manageengine:applications_manager",
      extra    : make_array("Build", build),
      webapp   : TRUE
  );
  installs++;
}
if (isnull(installs))
  audit(AUDIT_WEB_APP_NOT_INST, app, port);

# Report findings.
report_installs(port:port);
