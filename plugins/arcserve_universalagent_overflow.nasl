#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
 script_id(18041);
 script_version ("$Revision: 1.17 $");
 script_cve_id("CVE-2005-1018");
 script_bugtraq_id(13102);
 script_osvdb_id(15471);

 script_name(english:"CA BrightStor ARCserve Backup Universal Agent Remote Overflow (QO66526)");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host." );
 script_set_attribute(attribute:"description", value:
"This host is running BrightStor ARCServe UniversalAgent.

The remote version of this software is affected by a buffer overflow
vulnerability. 

An attacker, by sending a specially crafted packet, may be able to
execute code on the remote host." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/395512" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to the newest version of this software, when available" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'CA BrightStor Universal Agent Overflow');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/04/13");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/04/11");
 script_cvs_date("$Date: 2011/08/08 17:20:25 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english:"Check buffer overflow in BrightStor ARCServe UniversalAgent");
 script_category(ACT_GATHER_INFO);
 script_family(english:"Windows");
 script_copyright(english:"This script is Copyright (C) 2005-2011 Tenable Network Security, Inc.");
 script_dependencies("arcserve_universalagent_detect.nasl");
 script_require_keys("ARCSERVE/UniversalAgent");
 script_require_ports (6050);
 exit(0);
}

if (!get_kb_item ("ARCSERVE/UniversalAgent")) exit (0);

port = 6050;
if ( ! get_port_state(port) ) exit(0);
soc = open_sock_tcp (port);
if (!soc) exit(0);

data = raw_string (0x00,0x00,0x00,0x00,0x03,0x20,0xBC,0x02);
data += crap (data:"2", length:256);
data += crap (data:"A", length:32);
data += raw_string (0x0B, 0x11, 0x0B, 0x0F, 0x03, 0x0E, 0x09, 0x0B,
                    0x16, 0x11, 0x14, 0x10, 0x11, 0x04, 0x03, 0x1C,
                    0x11, 0x1C, 0x15, 0x01, 0x00, 0x06);
data += crap (data:"A", length:390);

send (socket:soc, data:data);
ret = recv (socket:soc, length:4096);

if ((strlen(ret) == 8) && (hexstr(ret) >< "0000730232320000"))
{
 security_hole(port);
}
