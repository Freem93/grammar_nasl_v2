#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
  script_id(46802);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2011/10/24 15:38:14 $");

  script_cve_id("CVE-2010-1937", "CVE-2010-2054");
  script_bugtraq_id(40475);
  script_osvdb_id(65157);

  script_name(english:"SBLIM-SFCB Multiple Buffer Overflows");
  script_summary(english:"Detects a vulnerable sfcbd HTTP Daemon");
 
  script_set_attribute(attribute:"synopsis",value:
"The application is affected by multiple buffer overflow
vulnerabilities."
  );
  script_set_attribute(attribute:"description", value:
"The web server component of SBLIM-SFCB that is listening on the
remote host contains multiple heap-based buffer overflows that can be
triggered by sending an HTTP request with a specially crafted
Content-Length header.  Specifically :

 - There is a particular scenario where heap corruption can
   exist if httpMaxContentLength in sfcb.cfg is set to 0
   and the Content-Length of a request is 4294967290,
   getPayload() will try to memcpy() into an incorrectly
   sized buffer due to wrap around (we add 8 to
   Content-Length in the malloc). Also, sfcb.cfg states
   that the default value for httpMaxContentLength _is_ 0,
   which is untrue.

 - httpAdapter contains a heap overflow that is caused by an
   HTTP request with the Content-Length value being smaller
   than the actual size of the payload. The affect of this bug
   can cause the handling HTTP process to crash. If the
   request is specially crafted, arbitrary code execution
   could occur.

Successful exploit of these vulnerabilities may result in a server
crash or execution of arbitrary code in the context of the server."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?149a07e1");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8729b62f");
	
  script_set_attribute(attribute:"solution", value:"Upgrade to version 1.3.8");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vuln_publication_date", value: "2010/05/14");
  script_set_attribute(attribute:"patch_publication_date",value:"2010/05/25");
  script_set_attribute(attribute:"plugin_publication_date", value: "2010/06/07");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2010-2011 Tenable Network Security, Inc.");

  script_dependencie("http_version.nasl");
  script_require_ports("Services/www", 5988);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_service(svc:"www", default:5988, exit_on_fail:TRUE);

banner = get_http_banner(port:port);

if(isnull(banner))
{

soc = open_sock_tcp(port);
if (!soc) exit(1, "Can't open a socket on port "+port+".");

  send(socket:soc, data:'HEAD / HTTP/1.1\r\n\r\n');
  banner = recv(socket:soc, length:4096);
if(isnull(banner)) exit(1, "Can't retrieve banner from the server on port "+port+".");

  close(soc);
}

if(!egrep(pattern:"^Server:.*sfcHttpd", string:banner))
  exit (0, "The web server on port "+port+" is not SBLIM-SFCB");

soc = open_sock_tcp(port);
if (!soc) exit(1, "Can't open a socket on port "+port+".");

req = string ("POST / HTTP/1.0\r\n",
              "Content-Length: 9\r\n\r\n",
              "nessus\r\n\r\n");

w = http_send_recv_buf(port:port, data:req, exit_on_fail:TRUE);

headers = parse_http_headers(status_line:w[0], headers:w[1]);
if (isnull(headers)) exit(1, 'Error parsing HTTP headers on port '+port+'.');

code = headers['$code'];
if (isnull(code)) exit(1, 'Error parsing HTTP status code on port '+port+'.');

# patched version replies with "HTTP/1.1 400 Bad request"

if (code == 200) security_hole(port);
else exit(0, 'The SBLIM-SFCB sfcbd HTTP Daemon on port '+port+' is not affected.');
