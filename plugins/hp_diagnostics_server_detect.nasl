#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64473);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/02/05 20:47:57 $");

  script_name(english:"HP Diagnostics Server Detection");
  script_summary(english:"Detects HP Diagnostics Server web interface");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host is running an application performance monitoring
server."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host is running HP (Formerly Mercury) Diagnostics Server, an
application performance monitoring solution."
  );
  #http://www8.hp.com/us/en/software-solutions/software.html?compURI=1175730
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1e81dc55");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/05");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:diagnostics_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 2006);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:2006);

appname = "HP Diagnostics Server";
kb_appname = "hp_diagnostics_server";

res = http_send_recv3(
  method:'GET',
  item:'/',
  port:port,
  exit_on_fail:TRUE
);
if (
  "<title>HP Diagnostics - Main Menu</title>" >< res[2] && 
  "Hewlett-Packard" >< res[2]
)
{
  version = UNKNOWN_VER;
  item = eregmatch(pattern:'class="diag">Diagnostics<p>Server[ ]*([^<]+)', 
                   string:res[2]);  
  if (!isnull(item[1])) version = item[1];
    
  # Register install
  installs = add_install(
    installs:installs,
    ver:version,
    dir:'/',
    appname:kb_appname,
    port:port
  );
}

if (isnull(installs)) audit(AUDIT_WEB_APP_NOT_INST, appname, port);

# Report findings.
if (report_verbosity > 0)
{
  report = get_install_report(
    port         : port,
    installs     : installs,
    display_name : appname,
    item         : '/' 
  );
  security_note(port:port, extra:report);
}
else security_note(port);
