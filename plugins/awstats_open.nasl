# Written by Gareth M. Phillips - SensePost PTY ltd
# www.sensepost.com

# Changes by Tenable:
# - Description touch-up, formatting (12/28/10)
# - Description enhancement (12/29/10)
# - Description enhancement (12/30/10)

include("compat.inc");

if (description) 
{
 script_id(26056);
 script_version("$Revision: 1.13 $");
 script_cvs_date("$Date: 2012/11/16 02:06:29 $");

 script_name(english:"AWStats is Openly Accessible");
 script_summary(english:"AWStats seems to be openly accessible to any user");

 script_set_attribute(attribute:"synopsis", value:"The remote web server allows access to its usage reports.");
 script_set_attribute(attribute:"description", value:
"The remote web server is running a version of AWStats that seems to be
accessible to the entire Internet.  Exposing AWStats unprotected to the
entire Internet can aid an attacker in gaining further knowledge of the
web server and its contents therein.  An attacker may gain access to
administrative backends or private files hosted on the server. 

Note that this may not be a concern if the scan was performed on an
internal network.");
 script_set_attribute(attribute:"solution", value:
"AWStats should be either restricted to authorised networks/hosts only,
or protected with some form of Basic-Auth." );
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2007/09/14");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:laurent_destailleur:awstats");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");

 script_copyright(english:"This script is Copyright (C) 2007-2012 SensePost");
 script_dependencies("awstats_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("www/AWStats");
 exit(0);
}

#

include("global_settings.inc");
include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if (!get_port_state(port)) exit(0, "Port "+port+" is closed");

if (get_kb_item("Services/www/"+port+"/embedded")) exit(0, "The web server on port "+port+" is embedded");

# Test an install.
install = get_kb_item(string("www/", port, "/AWStats"));
if (isnull(install)) exit(0, "AWStats was not detected on port "+port);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");

if (!isnull(matches))
{
  dir = matches[2];
  info = NULL;

  # Trying to retrieve the AWStats default File.
  url = dir+"/awstats.pl";
  req = http_get(item:url, port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
  if (res == NULL) exit(1, "The web server on port "+port+" failed to respond");
  if(egrep(pattern:"^HTTP.* 401 .*", string:res)) exit(0);

  if ('src="awstats.pl?framename=mainleft' >< res || egrep(pattern:'content="[aA]wstats - Advanced Web Statistics', string:res))
    info += ' ' + url + '\n';
}

if (!isnull(info))
{
  report = string(
    "\n",
    "AWStats' default page, awstats.pl, was found to exist on the web\n",
    "server under the following URL(s) :\n",
    "\n",
     info
     );
   security_note(port:port, extra:report); exit(0);
}
