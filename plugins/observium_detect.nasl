#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(95390);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2016/11/29 18:06:39 $");

  script_name(english:"Observium Detection");
  script_summary(english:"Checks for Observium.");

  script_set_attribute(attribute:"synopsis", value:
"Observium is running on the remote host.");
  script_set_attribute(attribute:"description", value:
"Observium, a network monitoring tool, is running on the remote host.");
  script_set_attribute(attribute:"see_also", value:"https://www.observium.org/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/29");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:observium_limited:observium");
  script_end_attributes();

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  
  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

appname = 'Observium';
port = get_http_port(default:80, php:TRUE);
res = http_get_cache(port:port, item:"/", exit_on_fail:TRUE);

# Observium sets a somewhat unique cookie and has a specific JavaScript
# include that really signals that this is Observium. Unfortunately,
# the <title> is editable by the user.
if ("Set-Cookie: OBSID=" >!< res ||
    "js/observium.js" >!< res) audit(AUDIT_NOT_DETECT, appname, port);

# The version is passed as a param to each css and js. For example:
# <script type="text/javascript" src="js/observium.js?v=0.16.10.8128"></script>
version = UNKNOWN_VER;
pattern = 'js/observium\\.js\\?v=([0-9\\.]+)"';
match = eregmatch(pattern:pattern, string:res);
if (!isnull(match)) version = match[1];

register_install(
  app_name:appname,
  port:port,
  path:'/',
  version:version);

report_installs();
