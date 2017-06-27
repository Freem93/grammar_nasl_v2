#
# (C) Tenable Network Security, Inc.
#

# Thanks to Nicolas FISCHBACH (nico@securite.org) for his help
#
# Ref:  http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20020903-vpn3k-vulnerability

include("compat.inc");

if(description)
{
 script_id(11291);
 script_version("$Revision: 1.17 $");
 script_cve_id("CVE-2002-1092");
 script_bugtraq_id(5613);
 script_osvdb_id(8907);

 script_name(english:"Cisco VPN 3000 Concentrator PPTP/IPSEC Group Credential Authentication Bypass (CSCdv66718)");

 script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch." );
 script_set_attribute(attribute:"description", value:
"The remote VPN concentrator has a bug in its PPTP client.

This vulnerability is documented as Cisco bug ID CSCdv66718." );
 script_set_attribute(attribute:"solution", value:
"http://www.nessus.org/u?d2dd6759" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/03/01");
 script_cvs_date("$Date: 2014/08/11 19:44:18 $");
 script_set_attribute(attribute:"vuln_publication_date", value: "2002/09/03");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value: "cpe:/o:cisco:ios");
 script_end_attributes();

 script_summary(english:"Uses SNMP to determine if a flaw is present");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is (C) 2003-2014 Tenable Network Security, Inc.");
 script_family(english:"CISCO");
 script_require_ports(23);
 script_dependencie("snmp_sysDesc.nasl");
 script_require_keys("SNMP/community", "SNMP/sysDesc", "CISCO/model");
 exit(0);
}

if(!get_port_state(23))exit(0);
soc = open_sock_tcp(23);
if(!soc)exit(0);
else close(soc);

# The code starts here

ok=0;

os = get_kb_item("SNMP/sysDesc"); if(!os)exit(0);



# Is this a VPN3k concentrator ?
if(!egrep(pattern:".*VPN 3000 Concentrator.*", string:os))exit(0);



# < 2.5.2(F)
if(egrep(pattern:".*Version 2\.[0-4]\..*", string:os))ok = 1;
if(egrep(pattern:".*Version 2\.5\.Rel", string:os))ok = 1;
if(egrep(pattern:".*Version 2\.5\.[0-1]", string:os))ok = 1;


if(ok)security_hole(port:161, proto:"udp");
