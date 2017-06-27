#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(12233);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2011/09/14 19:48:34 $");

  script_name(english:"eMule Web Server Detection");
  script_summary(english:"Detect eMule Web Server");

  script_set_attribute(attribute:"synopsis", value:
"There is a peer-to-peer file sharing application installed on the
remote host.");
  script_set_attribute(attribute:"description", value:
"The remote service is the web interface for eMule, an eDonkey2000
compatible peer-to-peer file sharing application.");
  script_set_attribute(attribute:"solution", value:
"Make sure that use of this program agrees with your organization's
acceptable use and security policies.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2004/05/07");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2011 Tenable Network Security, Inc."); 

  script_family(english:"Service detection");
  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 4711);
  script_require_keys("www/eMule");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc"); 
include("http.inc"); 

port = get_http_port(default:4711, embedded: 1);

banner = get_http_banner(port:port, exit_on_fail: 1);

if (egrep(string: banner, pattern: "^Server: *eMule"))
{
  page = http_get_cache(port:port, item:"/");
  ver = NULL;
  title = egrep(string: page, pattern:"<title>");
  if (title)
  {
    v = eregmatch(string: title, pattern: "<title>eMule ([0-9]\.[0-9]+[a-z]?) - Web .*</title>");
    if (! isnull(v)) ver = v[1];
  }
  if (! isnull(ver))
  {
    security_note(port:port, extra:'\neMule version : ' + ver + '\n');
    set_kb_item(name: "www/"+port+"/eMule", value: ver);
    if (COMMAND_LINE) display('ver=', ver, '\n');
  }
  else
    security_note(port);
}
