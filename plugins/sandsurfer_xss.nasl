#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(12087);
 script_version ("$Revision: 1.17 $");
 script_cve_id("CVE-2004-2550");
 script_bugtraq_id(9801);
 script_osvdb_id(4132);
 
 script_name(english:"SandSurfer < 1.7.1 XSS");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a CGI script that is prone to multiple
cross-site scripting attacks." );
 script_set_attribute(attribute:"description", value:
"The remote host is running SandSurfer, a web-based time keeping
application. 

A vulnerability has been disclosed in all versions of this software,
up to version 1.7.0 (included) which may allow an attacker to use it
to perform cross-site scripting attacks against third-party users." );
 script_set_attribute(attribute:"see_also", value:"http://sourceforge.net/forum/forum.php?forum_id=356882" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to SandSurfer 1.7.1 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/03/04");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/03/01");
 script_cvs_date("$Date: 2015/01/15 03:38:17 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english:"Checks for SandSurfer");
 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2004-2015 Tenable Network Security, Inc."); 
 script_family(english:"CGI abuses : XSS");
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("www/PHP");
 exit(0);
}

# The script code starts here

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
if(!can_host_php(port:port))exit(0);

foreach d ( cgi_dirs() )
{
 # SandSurfer installs under $prefix/cgi-bin/login.cgi
 w = http_send_recv3(method:"GET", item:string(d, "/cgi-bin/login.cgi"), port:port);
 if (isnull(w)) exit(1, "The web server on port "+port+ " did not answer");
 res = strcat(w[0], w[1], '\r\n', w[2]);
 if( egrep(pattern:"SandSurfer (0\.|1\.([0-5]\.|7\.1))", string:res)){
 	security_warning(port);
	set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
	exit(0);
 }

 w = http_send_recv3(method:"GET", item:string(d, "/login.cgi"), port:port);
 if (isnull(w)) exit(1, "The web server on port "+port+ " did not answer");
 res = strcat(w[0], w[1], '\r\n', w[2]);
 if( egrep(pattern:"SandSurfer (0\.|1\.([0-6]\.|7\.0))", string:res)){
 	security_warning(port);
	set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
	exit(0);
 }
}
