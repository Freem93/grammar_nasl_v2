#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description) {
  script_id(17663);
  script_version("$Revision: 1.15 $");

  script_cve_id("CVE-2005-0957");
  script_bugtraq_id(12955);
  script_osvdb_id(15299);

  script_name(english:"BayTech RPC-3 Telnet Daemon Remote Authentication Bypass");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote TELNET server is affected by an authentication bypass flaw." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Bay Technical Associates RPC3
TELNET Daemon that lets a user bypass authentication by sending a
special set of keystrokes at the username prompt.  Since BayTech RPC3
devices provide remote power management, this vulnerability enables an
attacker to cause a denial of service, shut down the device itself as
well as any connected devices." );
 script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=bugtraq&m=111230568025271&w=2" );
 script_set_attribute(attribute:"solution", value:
"None at this time.  Filter incoming traffic to port 23 on this device." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/04/01");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/03/31");
 script_cvs_date("$Date: 2011/03/11 21:52:31 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
  script_summary(english:"Checks for authentication bypass vulnerability in BayTech RPC3 Telnet daemon");
  script_category(ACT_ATTACK);
  script_family(english:"Gain a shell remotely");
  script_copyright(english:"This script is Copyright (C) 2005-2011 Tenable Network Security, Inc.");
  script_dependencies("find_service1.nasl");
  script_require_ports("Services/telnet", 23);

  exit(0);
}


include('telnet_func.inc');
port = get_kb_item("Services/telnet");
if (!port) port = 23;
if (!get_port_state(port)) exit(0);


buf = get_telnet_banner(port:port);
if (!buf || "RPC-3 Telnet Host" >!< buf) exit(0);


soc = open_sock_tcp(port);
if (!soc) exit(0);
buf = telnet_negotiate(socket:soc);
# If the banner indicates it's an RPC3 device...
if ("RPC-3 Telnet Host" >< buf) {
  # Send an ESC.
  send(socket:soc, data:raw_string(0x1b, "\r\n"));
  res = recv(socket:soc, length:1024);
  # If we get a command prompt, there's a problem.
  if (egrep(string:res, pattern:"^RPC-?3>")) security_hole(port);
}
close(soc);
