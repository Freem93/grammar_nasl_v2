#

# Changes by Tenable:
# - Revised plugin title, changed family (6/4/09)


include("compat.inc");

if (description)
{
script_id(33927);
script_version("$Revision: 1.9 $");

script_name(english:"Web Server Generic 3xx Redirect");
script_summary(english:"Checks for a redirection flaw which allows redirection to arbitrary domains");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server allows redirects to arbitrary domains." );
 script_set_attribute(attribute:"description", value:
"The remote web server is configured to redirect users using a HTTP
302, 303 or 307 response.  However, the server can redirect to a
domain that includes components included in the original request. 

A remote attacker could exploit this by crafting a URL which appears
to resolve to the remote server, but redirects to a malicious
location." );
 script_set_attribute(attribute:"see_also", value:"http://www.owasp.org/index.php/Phishing" );
 script_set_attribute(attribute:"see_also", value:"http://www.technicalinfo.net/papers/Phishing.html" );
 script_set_attribute(attribute:"solution", value:"Contact the web server vendor for a fix.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2008/08/18");

 script_cvs_date("$Date: 2015/02/13 21:07:13 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


script_category(ACT_ATTACK);
script_family(english:"CGI abuses");

script_copyright(english:"This script is Copyright (C) 2008-2015 Westpoint Ltd");

script_dependencies("find_service2.nasl", "http_version.nasl");
script_require_ports("Services/www", 80);

exit(0);
}



include("global_settings.inc");
include("http_func.inc");
exploit=".anydomain.test";

# Build the HTTP request
request = string(
"GET /",exploit," HTTP/1.0\r\n",
"Accept-Language:en-US\r\n",	# Make response header predicable
"Connection: close\r\n",	
"\r\n"
);


# Open the socket
port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
soc = http_open_socket(port);
if (!soc) exit(0);


# Send the exploit request, get header and body. 

send(socket:soc, data:request);
header = http_recv_headers2(socket:soc);
http_close_socket(soc);
if (!header) exit(0);

redirection=egrep(string:tolower(header), pattern:"location:");
if (!redirection) exit(0);
redirection = chomp(redirection);

if (
	egrep(string:header, pattern:"^HTTP[^ 	]+[ 	]+30[237][^0-9]") 
	&& ereg(string:redirection, pattern:string("location:[ 	]*https?://[^/]+\",exploit))
)
{
        set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
        desc = string('\n',
			 build_url(port:port, qs:exploit), 
			' redirects to ', redirection, '\n');
	security_warning(port:port, extra:desc);
}
