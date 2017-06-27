#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56876);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2011/11/21 21:18:28 $");

  script_name(english:"Oracle HTTP Server Version");
  script_summary(english:"Obtains the version of the remote Oracle HTTP Server.");

  script_set_attribute(attribute:"synopsis", value:
"It is possible to obtain the version number of the remote Oracle HTTP
server.");
  script_set_attribute(attribute:"description", value:
"The remote host is running the Oracle HTTP Server, a proprietary web
server.  It was possible to read the version number from the
banner.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/11/21");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:http_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2011 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_keys("www/oracle");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

# Get banner.
banner = get_http_banner(port:port, exit_on_fail:TRUE);

# Check for Server HTTP response header.
if ("Server:" >!< banner)
  exit(0, "The banner from port " + port + " does not have a Server response header.");

# We're only interested in recent versions of Oracle HTTP Server,
# which brand themselves as Oracle Application Server.
if (banner !~ "Oracle.Application.Server")
  exit(0, "The HTTP server listening on port " + port + " is not from Oracle Application Server.");

replace_kb_item(name:"www/oracle", value:TRUE);
set_kb_item(name:"www/"+port+"/oracle", value:TRUE);

pat = "^Server:.*Oracle.Application.Server( Containers for J2EE)?.([0-9]+.)(([ /]\(?([0-9.]+)\)?))?";
version = NULL;
source  = NULL;

matches = egrep(pattern:pat, string:banner);
if (!matches) exit(1, "Failed to parse the banner from port " + port + ".");

foreach match (split(matches, keep:FALSE))
{
  item = eregmatch(pattern:pat, string:match);
  if (!isnull(item))
  {
    source  = item[0];
    version = item[5];
    break;
  }
}

if (source)
{
  set_kb_item(name:"www/oracle/" + port + "/source", value:source);
  if (version) set_kb_item(name:"www/oracle/" + port + "/version", value:version);
}
else exit(1, "Failed to extract the version from the banner from port " + port + ".");
