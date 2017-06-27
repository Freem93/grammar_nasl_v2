#
# This cgi abuse script was written by Jonathan Provencher
# Ce script de scanning de cgi a ete ecrit par Jonathan Provencher
# <druid@balistik.net>
#

# Changes by Tenable:
# - Revised plugin title, added OSVDB ref (4/28/09)


include("compat.inc");

if(description)
{
 script_id(10321);
 script_version ("$Revision: 1.29 $");
 script_cve_id("CVE-1999-0953");
 script_bugtraq_id(649, 12453);
 script_osvdb_id(11874);
 
 script_name(english:"WWWBoard passwd.txt Authentication Credential Disclosure");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a CGI application that is prone to an
information disclosure attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running WWWBoard, a bulletin board system written
by Matt Wright. 

This board system comes with a password file (passwd.txt) installed
next to the file 'wwwboard.html'.  An attacker may obtain the contents
of this file and decode the password to modify the remote www board." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/1998/Sep/34" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/1999/Sep/312" );
 script_set_attribute(attribute:"solution", value:
"Configure the wwwadmin.pl script to change the name and location of
'passwd.txt'." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "1999/11/27");
 script_set_attribute(attribute:"vuln_publication_date", value: "1999/09/17");
 script_cvs_date("$Date: 2016/11/29 20:13:38 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 script_summary(english:"Checks for the presence of /wwwboard/passwd.txt");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 1999-2016 Jonathan Provencher");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#

function debug_print() {
  local_var a;
  a =_FCT_ANON_ARGS[0];
}

include("http_func.inc");
include("http_keepalive.inc");
port = get_http_port(default:80);

foreach dir(cgi_dirs())
{
 res = http_keepalive_send_recv(port:port, data:http_get(port:port, item:dir + "/wwwboard.html"), bodyonly:TRUE);
 if (res == NULL )exit(0);
 if ( "wwwboard.pl" >< res )
 {
 res = http_keepalive_send_recv(port:port, data:http_get(port:port, item:dir + "/passwd.txt"), bodyonly:TRUE);
 if ( strlen(res) && egrep(pattern:"^[A-Za-z0-9]*:[a-zA-Z0-9-_.]$", string:res))
	{
	 security_warning(port);
	 exit(0);
	}
 }
}

