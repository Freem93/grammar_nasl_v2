#
# (C) Tenable Network Security, Inc.
#

# Credit for the default root account values:
# - Metsaploit and an anonymous contributor


include("compat.inc");

if (description)
{
 script_id(19427);
 script_version("$Revision: 1.21 $");
 script_cvs_date("$Date: 2016/07/11 14:12:52 $");

 script_cve_id("CVE-2005-2611");
 script_bugtraq_id(14551);
 script_osvdb_id(18695);

 script_name(english:"VERITAS Backup Exec Remote Agent Static Password Arbitrary File Download");
 script_summary(english:"Test the VERITAS Backup Exec Agent Default Account");

 script_set_attribute(attribute:"synopsis", value:
"It is possible to retrieve/delete files on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of VERITAS Backup Exec Agent
which is configured with a default root account. 

An attacker may exploit this flaw to retrieve files from the remote
host." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e9b1913d" );
 script_set_attribute(attribute:"see_also", value:"http://seer.support.veritas.com/docs/278434.htm" );
 script_set_attribute(attribute:"solution", value:
"Update the product as described in the vendor advisory referenced above." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
script_set_attribute(attribute:"vuln_publication_date", value: "2005/08/12");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/08/12");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:veritas_backup_exec");
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
 script_family(english:"Misc.");
 if ( NASL_LEVEL >= 3000 ) script_dependencie("veritas_agent_bypass.nbin");
 script_exclude_keys("Veritas/BackupExecAgent/Bypass");
 script_require_ports(10000);
 exit(0);
}

if ( get_kb_item("Veritas/BackupExecAgent/Bypass") ) exit(0);

port = 10000;

#
# WebMin also listens on port 10000
#
if ( (banner = get_kb_item("www/banner/10000")) && "Server: MiniServ" >< banner ) exit(0);



connect_open_request = raw_string(
	0x80, 0x00, 0x00, 0x1C, 0x00, 0x00, 0x00, 0x01, 0x42, 0xBA, 0xF9, 0x91, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03
);


connect_client_auth_request = raw_string (
	0x80, 0x00, 0x00, 0x34, 0x00, 0x00, 0x00, 0x01, 0x42, 0xBA, 0xF9, 0x91, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x09, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
	0x00, 0x00, 0x00, 0x04, 0x72, 0x6F, 0x6F, 0x74, 0xB4, 0xB8, 0x0F, 0x26, 0x20, 0x5C, 0x42, 0x34,
	0x03, 0xFC, 0xAE, 0xEE, 0x8F, 0x91, 0x3D, 0x6F);

connect_client_auth_reply = raw_string (
	0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x09, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00);

if (!get_port_state(port))
  exit (0);

soc = open_sock_tcp (port);
if (!soc) exit (0);

buf = recv (socket:soc, length:40);
send (socket:soc, data:connect_open_request);
buf = recv (socket:soc, length:32);
send (socket:soc, data:connect_client_auth_request);
buf = recv (socket:soc, length:32);
if (strlen(buf) != 32)
  exit(0);
rep = substr (buf, 12, 31);

if (connect_client_auth_reply >< rep)
  security_hole(port);
