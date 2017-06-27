#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
 script_id(19387);
 script_version ("$Revision: 1.18 $");

 script_cve_id("CVE-2005-1272");
 script_bugtraq_id(14453);
 script_osvdb_id(18501);
 script_xref(name:"CERT", value:"279774");

 script_name(english:"CA BrightStor ARCserve Backup Agent for Windows Long String Overflow");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host." );
 script_set_attribute(attribute:"description", value:
"This host is running BrightStor ARCServe MSSQL Agent.

The remote version of this software is susceptible to a buffer
overflow attack. 

An attacker, by sending a specially crafted packet, may be able to
execute code on the remote host." );
 script_set_attribute(attribute:"see_also", value:"http://www.kb.cert.org/vuls/id/279774" );
 script_set_attribute(attribute:"solution", value:
"Apply the patch or upgrade to a newer version when available.

Note that for ARCServe 11.1, patch QO70767 (not working) has been
replaced by patch QO71010." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_core", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'CA BrightStor Agent for Microsoft SQL Overflow');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/08/05");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/08/02");
 script_cvs_date("$Date: 2017/04/28 14:01:58 $");
 script_set_attribute(attribute:"patch_publication_date", value: "2005/09/02");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english:"Check buffer overflow in BrightStor ARCServe MSSQL Agent");
 script_category(ACT_GATHER_INFO);
 script_family(english:"Windows");
 script_copyright(english:"This script is Copyright (C) 2005-2017 Tenable Network Security, Inc.");
 script_dependencies("arcserve_mssql_agent_detect.nasl");
 script_require_keys("ARCSERVE/MSSQLAgent");
 script_require_ports (6070);
 exit(0);
}

if (!get_kb_item ("ARCSERVE/MSSQLAgent")) exit (0);

port = 6070;
if ( ! get_port_state(port) ) exit(0);
soc = open_sock_tcp (port);
if (!soc) exit(0);

req = "[LUHISL" + crap(data:"A", length:18) + crap (data:"B", length:669) + raw_string (0x01, 0x06) + crap (data:"C", length:0x106) + crap (data:"D", length:0x106);

send (socket:soc, data:req);
buf = recv(socket:soc, length:1000);

if (strlen(buf) > 8)
{
 val = raw_string (0x00,0x00,0x04,0x1b,0x00,0x00,0x00,0x00);

 header = substr(buf,0,7);
 if (val >< header)
   security_hole(port);
}
