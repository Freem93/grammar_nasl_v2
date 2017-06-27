#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(10843);
 script_version ("$Revision: 1.21 $");
 script_osvdb_id(50615);
 script_cvs_date("$Date: 2017/01/30 23:05:16 $");
 script_name(english:"Microsoft ASP.NET Malformed File Request Path Disclosure");
 script_summary(english:"Tests for ASP.NET Path Disclosure Vulnerability");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is using a web application framework that is
affected by an information disclosure vulnerability.");

 script_set_attribute(attribute:"description", value:"
ASP.NET is vulnerable to a path disclosure attack.  This allows an
attacker to determine where the remote web root is physically stored
in the remote file system, hence gaining more information about the
remote system." );
 script_set_attribute(attribute:"solution", value:
"There is no known solution at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

 script_set_attribute(attribute:"plugin_publication_date", value: "2002/02/05");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2002-2017 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("find_service1.nasl", "http_version.nasl", "www_fingerprinting_hmap.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

 banner = get_http_banner(port:port);
 if ( "Microsoft-IIS" >!< sig ) exit(0);
w = http_send_recv3(method:"GET", item:string("/a%5c.aspx"), port:port);
if (isnull(w)) exit(0);
r = strcat(w[0], w[1], '\r\n', w[2]);
 if("Server Error" >< r)
 {
  r = strstr(r, "Invalid file name");
  end = strstr(r, '\n');
  str = r - end;
  path = ereg_replace(pattern:".*Invalid file name for monitoring: (.*)</title>",
		    string:str,
		    replace:"\1");
  if(ereg(string:path, pattern:"[A-Za-z]:\\.*", icase:TRUE))security_warning(port);
  }
