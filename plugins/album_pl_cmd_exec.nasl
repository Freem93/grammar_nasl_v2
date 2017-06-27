#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(11581);
 script_version ("$Revision: 1.21 $");
 script_cve_id("CVE-2003-1456");
 script_bugtraq_id(7444);
 script_osvdb_id(41109);

 script_name(english:"Mike Bobbitt's album.pl Alternative Configuration File Remote Command Execution");
 script_summary(english:"Determines the version of album.pl");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is running a web application that is affected by a
remote command execution vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of the CGI 'album.pl' which
is older than version 6.2

According to its version number, this CGI may allow an attacker
to execute arbitrary commands on this host with the privileges of the
HTTP daemon." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/319763/30/0/threaded" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to album.pl version 6.2." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20);


 script_set_attribute(attribute:"plugin_publication_date", value: "2003/05/06");
 script_cvs_date("$Date: 2011/03/14 21:48:01 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003-2011 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

function check(loc)
{
 local_var	w, r;
 w = http_send_recv3(method:"GET", item:string(loc, "/album.pl?function=about"),port:port);			
 if (isnull(w)) exit(0);
 r = strcat(w[0], w[1], '\r\n', w[2]);
 if(egrep(pattern:"album.pl V([0-5]|6\.[01]([^0-9]|$))", string:r))
 {
 	security_warning(port);
	exit(0);
 }
}


dirs = make_list(cgi_dirs());
foreach dir (dirs)
{
 check(loc:dir);
}
