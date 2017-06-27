#
# This script was written by John Lampe...j_lampe@bellsouth.net 
#
# See the Nessus Scripts License for details
#


include("compat.inc");

if(description)
{
 script_id(11746);
 script_version ("$Revision: 1.19 $");
 script_cve_id("CVE-2001-0938");
 script_bugtraq_id(3608);
 script_osvdb_id(8953, 8954);
 
 script_name(english:"AspUpload Test11.asp Arbitrary File Upload");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an ASP script that may allow uploading
of arbitrary files." );
 script_set_attribute(attribute:"description", value:
"At least one example script distributed with AspUpload appears to be
installed on the remote web server.  AspUpload is an ASP script that
supports saving and processing files uploading through other web
scripts, and the example script likely contains a flaw that allows an
attacker to upload arbitrary files and store them anywhere on the
affected drive." );
 script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=bugtraq&m=100715294425985&w=2" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");


 script_set_attribute(attribute:"plugin_publication_date", value: "2003/06/17");
 script_set_attribute(attribute:"vuln_publication_date", value: "2001/11/30");
 script_cvs_date("$Date: 2011/03/15 19:26:57 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 summary["english"] = "Checks for the AspUpload software";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2003-2011 John Lampe");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("www/ASP");
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if(!can_host_asp(port:port))exit(0);

 
foreach dir (cgi_dirs())
{
	req = http_get(item:dir + "/Test11.asp", port:port);
	res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
	if( res == NULL ) exit(0);
	if ("UploadScript11.asp" >< r) 
		{
			security_hole(port);
			exit(0);
		}
}
