# netscaler_web_detect.nasl
# GPLv2
#
# History:
#
# 1.00, 11/21/07
# - Initial release

# Changes by Tenable:
# - Revised plugin title (9/23/09)
# - Added CPE and updated copyright (10/18/2012)

include("compat.inc");

if (description)
{
  script_id(29222);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2013/04/30 17:15:52 $");

  script_name(english:"Citrix NetScaler Web Management Interface Detection");
  script_summary(english:"Detects NetScaler web management interface");

  script_set_attribute(attribute:"synopsis", value:
"A Citrix NetScaler web management interface is running on this port.");
  script_set_attribute(attribute:"description", value:
"The remote host appears to be a Citrix NetScaler, an appliance for web
application delivery, and the remote web server is its management
interface.");
  script_set_attribute(attribute:"see_also", value:"http://www.citrix.com/lang/English/ps2/index.asp");
  script_set_attribute(attribute:"solution", value:"Filter incoming traffic to this port.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2007/12/06");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:citrix:netscaler");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");
  script_copyright(english:"This script is Copyright (c) 2007-2013 nnposter");

  script_dependencies("find_service1.nasl","httpver.nasl", "broken_web_server.nasl");
  script_require_ports("Services/www",80);
  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");


port=get_http_port(default:80);
if (!get_tcp_port_state(port)) exit(0, "Port "+port+" is not open.");

foreach url (make_list("/", "/index.html"))
{
  if (url == "/") resp = http_get_cache(port:port, item:"/");
  else
  {
    resp=http_keepalive_send_recv(port:port,
                                data:http_get(item:"/index.html",port:port),
                                embedded:TRUE);
  }
  if (isnull(resp)) exit(1, "The web server on port "+port+" failed to respond.");

  match1=egrep(pattern:"<title>Citrix Login</title>",string:resp,icase:TRUE);
  match2=egrep(pattern:'action="(/login/do_login|/ws/login\\.pl)"',string:resp,icase:TRUE);
  if (match1 && match2)
  {
    replace_kb_item(name:"www/netscaler", value:TRUE);
    replace_kb_item(name:"www/netscaler/"+port, value:TRUE);
    replace_kb_item(name:"www/netscaler/"+port+"/initial_page", value:url);
    replace_kb_item(name:"Services/www/"+port+"/embedded", value:TRUE);

    if (report_verbosity > 0)
    {
      report = '\n' + 'The following instance of Citrix NetScaler was detected on the remote' +
               '\n' + 'host :' +
               '\n' +
               '\n' + '  URL : ' + build_url(port:port, qs:url) +
               '\n';
      security_note(port:port, extra:report);
    }
    else security_note(port);
    exit(0);
  }
}
exit(0, "The web server listening on port "+port+" does not appear to be the web management interface for a Citrix NetScaler.");
