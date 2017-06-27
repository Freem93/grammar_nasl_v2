#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(23787);
 script_version("$Revision: 1.13 $");

 script_cve_id("CVE-2006-6299");
 script_bugtraq_id(21395, 21400);
 script_osvdb_id(31352, 31353);

 script_name(english:"Novell ZENworks Asset Management Collection Client Remote Overflow");
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Novell ZENworks Asset (or Inventory)
Management, a remote desktop and network management software. 

The remote version of this software has multiple heap overflow
vulnerabilities that may be exploited by an attacker to execute
arbitrary code on the remote host with SYSTEM privileges." );
 script_set_attribute(attribute:"solution", value: "See the vendor advisory for update information.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 # http://support.novell.com/docs/Readmes/InfoDocument/patchbuilder/readme_2974824.html
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9ff412fd" );

 script_set_attribute(attribute:"plugin_publication_date", value: "2006/12/11");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/12/01");
 script_set_attribute(attribute:"patch_publication_date", value: "2006/11/30");
 script_cvs_date("$Date: 2016/11/23 20:31:34 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 script_summary(english:"Determines if ZENWorks Asset Management is vulnerable to an Heap Overflow");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");
 script_family(english:"Gain a shell remotely");
 script_dependencies("novell_asset_management_detect.nasl");
 script_require_ports(7461);
 exit(0);
}

include ("byte_func.inc");

if (!get_kb_item("Novell/AMCC"))
  exit (0);

set_byte_order(BYTE_ORDER_LITTLE_ENDIAN);

port = 7461;

if (!get_tcp_port_state(port))
  exit(0);

soc = open_sock_tcp (port);
if (!soc)
  exit(0);


req = mkbyte (0x00) + crap(data:raw_string(0), length:0x0d) + mkword (0) +
	mkword (0xfe) +
	mkword (0x0) +
	mkdword (0x40001);  # new check on the length (<= 0x40000)

send(socket:soc, data:req);
res = recv (socket:soc, length:4096);


if ("TS.Census module" >< res)
{
  security_hole(port);
}
