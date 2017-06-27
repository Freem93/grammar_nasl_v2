#
# (C) Tenable Network Security, Inc.
#

# Script audit and contributions from Carmichael Security
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID and CVE
#

include("compat.inc");

if (description)
{
 script_id(10496);
 script_version("$Revision: 1.27 $");
 script_cvs_date("$Date: 2014/07/14 21:05:21 $");

 script_cve_id("CVE-2000-0825");
 script_bugtraq_id(2011);
 script_osvdb_id(395);

 script_name(english:"IMail Host: Header Field Handling Remote Overflow");
 script_summary(english:"Web server buffer overflow.");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a denial of service
vulnerability.");
 script_set_attribute(attribute:"description", value:
"The remote web server crashes when it is issued a too long argument
to the 'Host:' field of an HTTP request.

An attacker may use this flaw to either completely prevent this host
from serving web pages to the world, or to make it die by crashing
several threads of the web server until the complete exhaustion of
this host memory");
 script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=bugtraq&m=96659012127444&w=2");
 script_set_attribute(attribute:"solution", value:"Upgrade to IMail 6.0.4 or later, as this reportedly fixes the issue.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");

 script_set_attribute(attribute:"vuln_publication_date", value:"2000/08/17");
 script_set_attribute(attribute:"plugin_publication_date", value:"2000/08/24");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_DENIAL);

 script_copyright(english:"This script is Copyright (C) 2000-2014 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");

 script_dependencie("http_version.nasl");
 script_require_keys("Settings/ParanoidReport");
 script_require_ports("Services/www",80);

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

global_var	port;

function check_port(port)
{
 local_var soc;

 if(get_port_state(port))
 {
 soc = http_open_socket(port);
 if(soc){
 	http_close_socket(soc);
	return(TRUE);
	}
  }
  return(FALSE);
}

port = 8181;
if(!(check_port(port:port)))
{
 port = 8383;
 if(!(check_port(port:port)))
 {
  port = get_http_port(default:80);

 }
}

if (http_is_dead(port:port))exit(0, "The web server on port "+port+" is dead");

w = http_send_recv3(method:"GET", item:"/", port:port,
  add_headers: make_array("Host", crap(500)));

if (isnull(w)) security_warning(port);
