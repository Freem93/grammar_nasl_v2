#
# This script was written by Alexander Strouk
#
# See the Nessus Scripts License for details
#


include("compat.inc");

if(description)
{
 script_id(10491); 
 script_version ("$Revision: 1.33 $");
 script_cve_id("CVE-2000-0778");
 script_bugtraq_id(1578);
 script_osvdb_id(390);

 script_name(english:"Microsoft IIS Translate f: ASP/ASA Source Disclosure");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an information disclosure flaw." );
 script_set_attribute(attribute:"description", value:
"There is a serious vulnerability in Windows 2000 (unpatched by SP1)
that allows an attacker to view ASP/ASA source code instead of a
processed file.  SP source code can contain sensitive information such
as usernames and passwords for ODBC connections." );
 script_set_attribute(attribute:"see_also", value:
"http://technet.microsoft.com/en-us/security/bulletin/ms00-058" );
 script_set_attribute(attribute:"solution", value:
"Install Windows 2000 Service Pack 1 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2000/08/23");
 script_set_attribute(attribute:"patch_publication_date", value: "2000/08/14");
 script_set_attribute(attribute:"vuln_publication_date", value: "2000/08/15");
 script_cvs_date("$Date: 2012/03/07 21:20:56 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english:"downloads the source of IIS scripts such as ASA,ASP");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2000-2012 Alexander Strouk");
 script_family(english:"CGI abuses");
 script_dependencie("find_service1.nasl", "no404.nasl", "http_version.nasl", "www_fingerprinting_hmap.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if  (! port || get_kb_item("Services/www/" + port + "/embedded") ) exit(0);

sig = get_kb_item("www/hmap/" + port + "/description");
if ( ! sig ) sig = get_http_banner(port:port);
if ( sig && "IIS" >!< sig ) exit(0);
if(!get_port_state(port)) exit(0);
req = string("GET /global.asa HTTP/1.0\r\n\r\n");
r = http_keepalive_send_recv(port:port, data:req);
if ( r !~ "HTTP/[0-9.]+ 500 " ) exit(0);
req = string("GET /global.asa\\ HTTP/1.0\r\nTranslate: f\r\n\r\n");
r = http_keepalive_send_recv(port:port, data:req);
if ( r =~ "HTTP/[0-9.]+ 404" )
{
 req = string("GET /global.asa HTTP/1.0\r\nTranslate: f\r\n\r\n");
 r = http_keepalive_send_recv(data:req, port:port);
 if ( r =~ "HTTP/[0-9.]+ 403 " ) { 
	security_warning(port);
	set_kb_item(name:"Services/www/ms00-058", value:"missing");
	}
 else 
	set_kb_item(name:"Services/www/ms00-058", value:"installed");
}

