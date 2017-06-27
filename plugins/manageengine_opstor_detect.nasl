#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62782);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/02/07 18:43:41 $");

  script_name(english:"ManageEngine OpStor Detection");
  script_summary(english:"Looks for OpStor");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a storage management application.");
  script_set_attribute(attribute:"description", value:
"The remote web server hosts ManageEngine OpStor, a storage management
application written in Java.");
  script_set_attribute(attribute:"see_also", value:"http://www.manageengine.com/products/opstor/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor",value:"None");

  script_set_attribute(attribute: "plugin_publication_date", value:"2012/11/01");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:zohocorp:manageengine_opstor");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2017 Tenable Network Security, Inc.");

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

installs = NULL;
res = http_get_cache(item:"/", port:port, exit_on_fail:TRUE);

if (
  ">Sign In to OpStor<" >< res && 
  '"logincaptiontext">Simplified Multi-Vendor Storage Infrastructure' >< res
) 
{
  version = UNKNOWN_VER;

  installs = add_install(
    installs : installs,
    dir      : "",
    appname  : "manageengine_opstor",
    ver      : version,
    port     : port
  );
}
if (isnull(installs)) audit(AUDIT_WEB_APP_NOT_INST, "ManageEngine OpStor", port);

if (report_verbosity > 0)
{
  report = get_install_report(
    display_name : "ManageEngine OpStor",
    installs     : installs,
    port         : port
  );
  security_note(port:port, extra:report);
}
else security_note(port);
