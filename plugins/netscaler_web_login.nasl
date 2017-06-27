# netscaler_web_login.nasl
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
  script_id(29223);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2013/04/30 17:15:52 $");

  script_name(english:"NetScaler Web Management Successful Authentication");
  script_summary(english:"Logs into NetScaler web management interface");

  script_set_attribute(attribute:"synopsis", value:
"It is possible to log into the remote web management interface.");
  script_set_attribute(attribute:"description", value:
"Nessus successfully logged into the remote Citrix NetScaler web
management interface using the supplied credentials and stored the
authentication cookie for later use.");
  script_set_attribute(attribute:"risk_factor", value:"None");
  script_set_attribute(attribute:"solution", value:"n/a");

  script_set_attribute(attribute:"plugin_publication_date", value:"2007/12/06");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:citrix:netscaler");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");
  script_copyright(english:"This script is Copyright (c) 2007-2013 nnposter");

  script_dependencies("logins.nasl", "netscaler_web_detect.nasl");
  script_require_keys("www/netscaler","http/login");
  script_require_ports("Services/www",80);
  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("url_func.inc");


if (!get_kb_item("www/netscaler")) exit(0, "The remote host was not found to have a Citrix NetScaler Web Management Interface.");
if (!get_kb_item("http/login"))    exit(0, "No HTTP credentials were provided in the scan policy.");


port = get_http_port(default:80);
if (!get_tcp_port_state(port)) exit(0, "Port "+port+" is not open.");
if (!get_kb_item("www/netscaler/"+port)) 
  exit(0, "The web server listening on port "+port+" does not appear to be the web management interface for a Citrix NetScaler.");

user = get_kb_item("http/login");
pass = get_kb_item("http/password");


initial_page = get_kb_item_or_exit("www/netscaler/"+port+"/initial_page");
if (initial_page == "/index.html")
{
  url="/ws/login.pl?"
      + "username="+urlencode(str:user)
      +"&password="+urlencode(str:pass)
      +"&appselect=stat";
  req = http_get(item:url, port:port);
}
else
{
  url="/login/do_login";
  host = get_host_name();
  postdata = "username=" + urlencode(str:user) + "&" +
             "password=" + urlencode(str:pass) + "&" +
             "startin=def" + "&" +
             "timeout=30" + "&" +
             "unit=Minutes" + "&" +
             "jvm_memory=256M" + "&" +
             "url=" + "&" +
             "timezone_offset=-14400";
  req = 'POST ' + url + ' HTTP/1.1\r\n' +
        'Host: ' + get_host_name() + ':' + port + '\r\n' +
        'Content-Type: application/x-www-form-urlencoded\r\n' +
        'Content-Length: ' + strlen(postdata) + '\r\n' +
        '\r\n' + 
        postdata;
}

resp = http_keepalive_send_recv(port:port, data:req, embedded:TRUE);
if (isnull(resp)) exit(1, "The web server on port "+port+" failed to respond.");

cookie = egrep(pattern:"^Set-Cookie:",string:resp,icase:TRUE);
if (cookie)
{
  cookie=ereg_replace(string:cookie,pattern:'^Set-',replace:" ",icase:TRUE);
  cookie=ereg_replace(string:cookie,pattern:';[^\r\n]*',replace:";",icase:TRUE);
  cookie=ereg_replace(string:cookie,pattern:'\r\nSet-Cookie: *',replace:" ",icase:TRUE);
  cookie=ereg_replace(string:cookie,pattern:'; *(\r\n)',replace:"\1",icase:TRUE);

  if (
    (
      initial_page != "/index.html" &&
      cookie =~ " SESSID=" &&
      "Location: /menu/" >< resp
    ) ||
    (
      initial_page == "/index.html" &&
      cookie =~ " ns1=.* ns2=" 
    )
  )
  {
    set_kb_item(name:"/tmp/http/auth/"+port, value:cookie);
    security_note(port);
    exit(0);
  }
}
exit(0, "The Citrix NetScaler Web Management Interface on port "+port+" is not affected.");
