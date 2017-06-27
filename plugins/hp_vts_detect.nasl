#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(88020);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2016/01/20 19:46:36 $");

  script_name(english:"HP Virtual Table Server Detection");
  script_summary(english:"Checks for presence of HP Virtual Table Server.");

  script_set_attribute(attribute:"synopsis", value:
"An HP Virtual Table Server is listening on the remote host.");
  script_set_attribute(attribute:"description", value:
"An HP Virtual Table Server (VTS) is listening on the remote host.
VTS offers an alternative to standard parameterization for load and 
performance testing, and it is a component of HP LoadRunner and HP 
Performance Center.");
# http://community.hpe.com/t5/LoadRunner-and-Performance/The-New-Virtual-Table-Server-VTS-in-LoadRunner-11-52/ba-p/6069435#.Vpa31PkrLIU
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?db6d7d2b");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/20");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:loadrunner");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:performance_center");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 4000);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:4000);
appname = "HP Virtual Table Server";
dirs = make_list("/");

# Regexes for service detection 
re[0] = make_list(
      "Virtual Table Server", 
      "API Access Port", 
      "rdoImpCsv",  
      "Import from CSV file");

# Regexes for extracting version 
# Currently no webpages return version info
re[1] = NULL; 
checks[""] = re;

installs = find_install(
  port    : port,
  dirs    : dirs,
  checks  : checks,
  appname : appname
);

if (isnull(installs)) audit(AUDIT_WEB_APP_NOT_INST, appname, port);
report_installs(port:port);


