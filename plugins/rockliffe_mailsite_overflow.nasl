#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(10421);
 script_version ("$Revision: 1.27 $");
 script_cve_id("CVE-2000-0398");
 script_bugtraq_id(1244);
 script_osvdb_id(323);

 script_name(english:"Rockliffe MailSite Management Agent wconsole.dll GET Request Overflow");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a buffer overflow issue." );
 script_set_attribute(attribute:"description", value:
"The version of Rockliffe MailSite installed on the remote host is
prone to a buffer overflow attack that can be triggered by a request
like :

	GET /cgi-bin/wconsole.dll?AAAA....AAAA
	
This may be of some use to an attacker to run arbitrary code on this
system and/or crash it." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to version 4.2.2 of this software." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
 script_set_attribute(attribute:"plugin_publication_date", value: "2000/05/25");
 script_set_attribute(attribute:"vuln_publication_date", value: "2000/05/24");
 script_cvs_date("$Date: 2011/03/14 21:48:12 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 script_summary(english:"MailSite buffer overflow");
 script_category(ACT_DESTRUCTIVE_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2000-2011 Tenable Network Security, Inc.");
 script_family(english:"Gain a shell remotely");
 script_dependencie("find_service1.nasl", "www_too_long_url.nasl", "http_version.nasl");
 script_require_ports(90);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = 90;

if (! get_port_state(port)) exit(0, "Port "+port+" is closed");
if (http_is_dead(port: port)) exit(0);

foreach dir (cgi_dirs())
{
 data = string(dir, "/wconsole.dll?", crap(1024));
 r = http_send_recv3(method:"GET", item:data, port:port);
 if(http_is_dead(port:port))security_hole(port);
}

