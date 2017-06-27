#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(62703);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/10/25 21:03:30 $");

  script_name(english:"Novell ZENworks Asset Management Detection");
  script_summary(english:"Detects Novell ZENworks Asset Management web console");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote host is running an asset management application."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host is running the Novell ZENworks Asset Management, which
is a suite of tools for the management of IT resources."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.novell.com/products/zenworks/assetmanagement/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/10/25");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:novell:zenworks_asset_management");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 8080);
  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:8080);
appname = "Novell ZENworks Asset Management";

installs = NULL;
dir = "/rtrlet";

login_page = "/rtr?act=network.Login&rtyp=login";
help_page = "/Html/WebConsoleHelp/Welcome_to_the_Web_Console.htm";

url = dir + login_page;
res = http_send_recv3(port:port, method:"GET", item:url, exit_on_fail:TRUE);

if (
  'Novell' >< res[2] && 
  'ZENworks' >< res[2] && 
  'Asset Management Login' >< res[2] && 
  'network.CheckLogin' >< res[2]
)
{
  version = UNKNOWN_VER;
  
  # try and extract version from help page
  url = dir + help_page;
  res = http_send_recv3(port:port, method:"GET", item:url, exit_on_fail:TRUE);
  item = eregmatch(pattern:">Application[ \t\n\r]*Version[ \t\n\r]*([^<]+)<",
                   string:res[2]);
  if (!isnull(item)) version = chomp(item[1]);

  installs = add_install(
    appname  : "novell_zenworks_asset_management",
    installs : installs,
    port     : port,
    dir      : dir,
    ver     : version
  );
}

if (isnull(installs)) audit(AUDIT_WEB_APP_NOT_INST, appname, port);

# Report findings.
if (report_verbosity > 0)
{
  report = get_install_report(
    port         : port,
    installs     : installs,
    display_name : "novell_zenworks_asset_management",
    item         : login_page
  );
  security_note(port:port, extra:report);
}
else security_note(port);
