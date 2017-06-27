#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(48204);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/02/04 22:11:24 $");

  script_name(english:"Apache HTTP Server Version");
  script_summary(english:"Obtains the version of the remote Apache HTTP server.");

  script_set_attribute(attribute:"synopsis", value:
"It is possible to obtain the version number of the remote Apache HTTP
server.");
  script_set_attribute(attribute:"description", value:
"The remote host is running the Apache HTTP Server, an open source web
server. It was possible to read the version number from the banner.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/30");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:http_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_keys("www/apache");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("backport.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

global_var port, src, ver;

function parse_banner(headers)
{
  local_var item, match, matches, pat;

  src = NULL;
  ver = NULL;

  pat = '^Server:.*Apache(-AdvancedExtranetServer)?(/([0-9]+(\\.[^ ]+)?))?';

  matches = egrep(pattern:pat, string:headers);
  if (!matches) exit(1, "Failed to parse Apache's banner on port " + port + ".");

  foreach match (split(matches, keep:FALSE))
  {
    item = eregmatch(pattern:pat, string:match);
    if (!isnull(item))
    {
      src = item[0];
      ver = item[3];
      break;
    }
  }
}

port = get_http_port(default:80);

# Get pristine banner.
pristine = get_http_banner(port:port, exit_on_fail:TRUE);

# Ensure that the banner is usable.
if ("Server:" >!< pristine)
  exit(0, "The banner from port " + port + " does not have a Server response header.");

if (ereg(string:pristine, pattern:'Server:.*(Apache-Coyote|Tomcat)'))
  exit(0, "The HTTP server listening on port " + port + " is Apache Tomcat, not Apache.");

if (!ereg(pattern:"Server:.*Apache", string:pristine, multiline:TRUE))
  exit(0, "The HTTP server listening on port " + port + " is not Apache.");


# Set a KB item so that we know its Apache on a certain port
set_kb_item(name:"www/" + port + "/apache", value:TRUE);

# Parse the pristine banner.
parse_banner(headers:pristine);
if (isnull(src)) exit(1, "Failed to extract the version from the banner from port " + port + ".");

set_kb_item(name:"www/apache/" + port + "/pristine/source", value:src);
if (ver) set_kb_item(name:"www/apache/" + port + "/pristine/version", value:ver);


# Parse backported banner.
banner = get_backport_banner(banner:pristine);
parse_banner(headers:banner);
if (isnull(src)) exit(1, "Failed to extract the version from the backported banner from port " + port + ".");

set_kb_item(name:"www/apache/" + port + "/source", value:src);
set_kb_item(name:"www/apache/" + port + "/backported", value:backported);
if (ver) set_kb_item(name:"www/apache/" + port + "/version", value:ver);
