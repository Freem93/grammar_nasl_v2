#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(42825);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/04/04 18:13:40 $");

  script_name(english:"Apple TV Detection");
  script_summary(english:"Looks for evidence of AppleTV in HTTP banner");

  script_set_attribute(attribute:"synopsis", value:"The remote host is a digital media receiver.");
  script_set_attribute(attribute:"description", value:
"The remote host is an Apple TV, a digital media receiver.");
  script_set_attribute(attribute:"see_also", value:"http://www.apple.com/appletv/");
  script_set_attribute(attribute:"solution", value:
"Make sure that use of such devices is in line with your organization's
acceptable use and security policies.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2009/11/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:apple_tv");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 3689);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:3689);

banner = get_http_banner(port:port);
if (isnull(banner)) audit(AUDIT_NO_BANNER, port);

if (
  "RIPT-Server: iTunesLib/" >< banner ||
  egrep(pattern:"^DAAP-Server: iTunes/[0-9][0-9.]+[a-z][0-9]+ \((Mac )?OS X\)", string:banner)
)
{
  set_kb_item(name:"www/appletv", value:TRUE);
  security_note(0);
}
else exit(0, "The banner from the web server listening on port "+port+" does not look like that of an Apple TV.");
