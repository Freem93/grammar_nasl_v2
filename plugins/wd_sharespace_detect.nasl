#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(60017);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/07/18 15:30:10 $");

  script_name(english:"Western Digital ShareSpace Detection");
  script_summary(english:"Looks for a Western Digital ShareSpace device");

  script_set_attribute(attribute:"synopsis", value:"The remote host is a storage device.");
  script_set_attribute(attribute:"description", value:
"The remote host is a Western Digital ShareSpace device, a NAS storage
device with an embedded web server.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");
  
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/07/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
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

app = "Western Digital ShareSpace";
installs = make_array();

res = http_get_cache(item:"/", port:port, exit_on_fail:TRUE);
if (
  "<title>WD ShareSpace - " >< res &&
  "Western Digital Technologies, Inc. All rights reserved." >< res &&
  "Administrator Name" >< res
)
{
  installs = add_install(
    installs : installs,
    port     : port,
    dir      : "/",
    appname  : "sharespace"
  );
}

if (max_index(keys(installs)) == 0) audit(AUDIT_NOT_DETECT, app, port);

set_kb_item(name:"Services/www/"+port+"/embedded", value:TRUE); 
if (report_verbosity > 0)
{
  report = get_install_report(
    display_name : app,
    installs     : installs,
    port         : port
  );
  security_note(port:port, extra:report);
}
else security_note(port);

