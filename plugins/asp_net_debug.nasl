#
# (C) Tenable Network Security, Inc.
#
#
# Thanks to Adam Poiton for asking us to write this one :)


include("compat.inc");

if(description)
{
 script_id(33270);
 script_version ("$Revision: 1.12 $");
 script_name(english: "ASP.NET DEBUG Method Enabled");
 
 script_set_attribute(attribute:"synopsis", value:
"The DEBUG method is enabled on the remote host." );
 script_set_attribute(attribute:"description", value:
"It is possible to send debug statements to the remote ASP scripts.  An
attacker might use this to alter the runtime of the remote scripts." );
 script_set_attribute(attribute:"solution", value:
"Make sure that DEBUG statements are disabled or only usable by
authenticated users." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
 script_set_attribute(attribute:"see_also", value:"http://support.microsoft.com/default.aspx?scid=kb;en-us;815157");
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/06/27");
 script_cvs_date("$Date: 2013/01/25 01:19:07 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_summary(english: "Tests for ASP.NET Path Disclosure Vulnerability");
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2008-2013 Tenable Network Security, Inc.");
 script_family(english: "CGI abuses");
 script_dependencie("webmirror.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("torture_cgi_func.inc");

port = get_http_port(default:80, embedded: 0);

files = get_kb_list("www/" + port + "/content/extensions/aspx");
if ( isnull(files) ) exit(0, "No ASPX page was found on port "+port+".");
else files = make_list(files);

sig = get_http_banner(port:port);
r = http_send_recv3(port: port, item: files[0], method: "DEBUG", version: 11, 
  add_headers: make_array("Command", "stop-debug"), exit_on_fail: 1 );

if (r[0] =~ "^HTTP/1\.1 200 "  &&  'Content-Length: 2\r\n' >< r[1] &&
    r[2] == "OK")
	security_warning(port:port, extra:
  '\nThe request\n' 
+ http_last_sent_request() 
+ '\nProduces the following output :\n'
+ r[0] + r[1] + '\r\n' + r[2] );
