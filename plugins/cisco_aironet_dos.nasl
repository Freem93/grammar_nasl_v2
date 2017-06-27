#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(11014);
 script_version("$Revision: 1.25 $");
 script_cvs_date("$Date: 2014/05/25 02:11:20 $");

 script_cve_id("CVE-2002-0545");
 script_bugtraq_id(4461);
 script_osvdb_id(5238);

 script_name(english:"Cisco Aironet Telnet Invalid Username/Password DoS");
 script_summary(english:"Checks for CSCdw81244");

 script_set_attribute(attribute:"synopsis", value:
"The remote wireless access point has a denial of service
vulnerability.");
 script_set_attribute(attribute:"description", value:
"The remote host appears to be a Cisco Aironet wireless access point.

It was possible to reboot the AP by connecting via telnet and and
providing a specially crafted username and password. A remote attacker
could do this repeatedly to disable the device.");
 # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20020409-aironet-telnet
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a6678575");
 script_set_attribute(attribute:"solution", value:"Update to release 11.21, or disable telnet.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:W/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2004/04/09");
 script_set_attribute(attribute:"patch_publication_date", value:"2002/04/09");
 script_set_attribute(attribute:"plugin_publication_date", value:"2002/06/05");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:aironet_ap350:11.21");
 script_end_attributes();

 script_category(ACT_KILL_HOST);
 script_family(english:"CISCO");

 script_copyright(english:"This script is Copyright (C) 2002-2014 Tenable Network Security, Inc.");

 script_dependencie("find_service1.nasl");
 script_require_keys("Settings/ParanoidReport");
 script_require_ports("Services/telnet", 23);

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include('telnet_func.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port=get_kb_item("Services/telnet");
if(!port)port=23;


# we don't use start_denial/end_denial because they
# might be too slow (the device takes a short time to reboot)

alive = tcp_ping(port:port);
if(alive)
{
 if(!get_port_state(port))exit(0);
 soc = open_sock_tcp(port);
 if(!soc)exit(0);
 buf = telnet_negotiate(socket:soc);
 r = recv(socket:soc, length:4096);
 send(socket:soc, data:string("n3ssus", rand(), "\r\n"));
 r = recv(socket:soc, length:4096);
 send(socket:soc, data:string("n3ssus", rand(), "\r\n"));
 close(soc);

 sleep(1);
 alive = tcp_ping(port:port);
 if(!alive)security_hole(port);
}


