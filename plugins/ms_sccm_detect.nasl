#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(51836);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2011/07/01 21:15:06 $");

  script_name(english:"Microsoft System Center Configuration Manager Management Point Detection");
  script_summary(english:"Tries to detect a Configuration Manager management point");

  script_set_attribute(attribute:"synopsis", value:
"A systems management service is listening on this port.");
  script_set_attribute(attribute:"description", value:
"The remote service is a Management Point for a Microsoft System
Center Configuration Manager server.  It is used by client agents to
communicate with the Configuration Manager.");
  script_set_attribute(attribute:"see_also", value:
"http://en.wikipedia.org/wiki/System_Center_Configuration_Manager");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/02/01");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2011 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/iis");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80, embedded:0);

banner = get_http_banner(port:port, exit_on_fail:TRUE);
if (!egrep(string:banner, pattern:"^Server:.*Microsoft-IIS"))
  exit(0, "The web server on port "+port+" is not IIS.");


# Get information about the management point.
#
# The response should look like the following:
#  <MPList><MP Name="MSSC1" FQDN="MSSC1.ACMEINCLAB.COM" SiteCode="HVL"><Version>6487</Version><Capabilities SchemaVersion="1.0"/></MP></MPList>
item = '/SMS_MP/.sms_aut?MPLIST1';
pat = '<MP .*FQDN=\"(.+)\".*SiteCode=\"(.{3})\".*<Version>(.+)</Version>.*</MP>';

r = http_send_recv3(method:'GET', item:item, port:port, exit_on_fail:TRUE);
if (
  r[0] !~ "^HTTP/1\.[01][ \t]+200[ \t]+" || 
  !r[2] ||
  '<MP' >!< r[2] ||
  !egrep(pattern:pat, string:r[2])
) exit(0, 'The web server does not respond as expected to a ConfigMgr management point query.');

mps_info = NULL;
while ((i = stridx(r[2], '<MP ')) > 0)
{
  j = stridx(r[2], '</MP>');
  if (j > 0) mp = substr(r[2], i, j - 1) + '</MP>';
  else mp = '<MP '; # in case of not getting the terminating tag, avoid infinite loop.
  
  match = eregmatch(string:mp, pattern:pat);
  if (match)
  {
    mps_info += '\n  Site code                : ' + match[2] + 
                '\n  Management point name    : ' + match[1] + 
                '\n  Management point version : ' + match[3] + '\n';
                
    set_kb_item(name:"ms_sccm/site", value:match[2]);
  }           
  r[2] -= mp;
}   

if (!isnull(mps_info))
{
  if (report_verbosity > 0)
  {
    report = '\nNessus was able to extract the following information :\n' + mps_info;
    security_note(port:port, extra:report);
  }
  else security_note(port);
  exit(0);
}
else exit(1, "The web server listening on port "+port+" returned an unexpected response to a ConfigMgr management point query.");
