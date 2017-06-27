#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10156);
 script_version ("$Revision: 1.35 $");
 script_cve_id("CVE-1999-0239");
 script_bugtraq_id(481);
 script_osvdb_id(122);

 script_name(english:"Netscape FastTrack get Command Forced Directory Listing");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is vulnerable to an information disclosure
attack." );
 script_set_attribute(attribute:"description", value:
"When the remote web server is issued a request with a lower-case
'get', it will return a directory listing even if a default page such
as index.html is present. 
		
For example :
		get / HTTP/1.0

will return a listing of the root directory. 

This allows an attacker to gain valuable information about the
directory structure of the remote host and could reveal the presence
of files that are not intended to be visible." );
 script_set_attribute(attribute:"solution", value:
"Upgrade the server to the latest version." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "1999/06/22");
 script_set_attribute(attribute:"vuln_publication_date", value: "1998/01/16");
 script_cvs_date("$Date: 2016/08/29 13:57:36 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:netscape:fasttrack_server");
script_end_attributes();

 script_summary(english:"'get / ' gives a directory listing");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 1999-2016 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");
 script_dependencie("find_service1.nasl", "httpver.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/netscape-fasttrack");
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

bad = "<title>index of /</title>";

function check(pattern, port)
{
 local_var	w, rq, res, buf;
 
 
 rq = http_mk_get_req(item:"/", port:port);
 buf = http_mk_buffer_from_req(req: rq);
 buf = str_replace(string:buf, find:pattern, replace:"get", count:1);
 w = http_send_recv_buf(port: port, data: buf);
 if (isnull(w)) exit(1, "The web server on port "+port+" did not answer");
 res = strcat(w[0], w[1], '\r\n', w[2]);
 res = tolower(res);
 if(bad >< res){
 	security_warning(port);
	exit(0);
  }
}


port = get_http_port(default:80);

w = http_send_recv3(method: "GET", item:"/", port:port);
if (isnull(w)) exit(1, "The web server on port "+port+" did not answer");
res = strcat(w[0], w[1], '\r\n', w[2]);
res = tolower(res);
if(bad >< res) exit(0);

# See www.securityfocus.com/bid/481/exploit

check(pattern:"GET", port:port);
check(pattern:"GET ", port:port);

