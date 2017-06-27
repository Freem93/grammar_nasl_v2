#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(15470);
 script_version ("$Revision: 1.11 $");
 script_cvs_date("$Date: 2015/10/21 20:34:20 $"); 

 script_osvdb_id(10482);

 script_name(english:"BugPort Attached File Handling Unspecified Issue");

 script_set_attribute(attribute:"synopsis", value:
"A remote web application is vulnerable to an unspecified flaw." );
 script_set_attribute(attribute:"description", value:
"The remote host seems to be running BugPort, an open source web-based system 
to manage tasks and defects throughout the software development process.

This version of BugPort contains an unspecified attachment handling flaw." );
 script_set_attribute(attribute:"solution", value:
"Update to version 1.134 or newer" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/10/13");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/10/05");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();
 
 summary["english"] = "Checks for BugPort version";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2015 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("www/PHP");
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

function check(url)
{
  local_var r, req;
  req = http_get(item:string(url, "/index.php"), port:port);
  r = http_keepalive_send_recv(port:port, data:req);
  if ( r == NULL ) exit(0);

    #We need to match this
    #<title>My Project Information - BugPort v1.134</title> 
    if ("<title>My Project Information - BugPort v" >< r)
    {
       	if(egrep(pattern:"BugPort v1\.([01][^0-9]|[01][0-3][^0-9]|[01][0-3][0-3][^0-9])", string:r))
 	{
 		security_hole(port);
		exit(0);
	}
    }
 
}

check(url:"/bugport/php");

foreach dir (cgi_dirs())
{
  check(url:dir);
}
