#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(11594);
 script_version("$Revision: 1.19 $");
 script_cve_id("CVE-2003-0258","CVE-2003-0259","CVE-2003-0260");
 script_osvdb_id(8904, 8905, 8906);

 script_name(english:"Cisco VPN 3000 Series Multiple Vulnerabilities (CSCdea77143, CSCdz15393, CSCdt84906)");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch." );
 script_set_attribute(attribute:"description", value:
"The remote Cisco VPN 3000 concentrator is affected by several
vulnerabilities that could allow an attacker to use this device
to break into a VPN, disable the remote device by sending
a malformed SSH initialization packet or disable the
remote device by sending a flood of malformed ICMP packets.

These vulnerabilities are documented with the CISCO
bug IDs CSCdea77143, CSCdz15393 and CSCdt84906." );
 script_set_attribute(attribute:"solution", value:
"http://www.nessus.org/u?a98c23a3" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/05/07");
 script_cvs_date("$Date: 2014/08/11 19:44:18 $");
 script_set_attribute(attribute:"vuln_publication_date", value: "2003/05/07");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value: "cpe:/o:cisco:ios");
 script_end_attributes();

 script_summary(english:"Uses SNMP to determine if a flaw is present");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is (C) 2003-2014 Tenable Network Security, Inc.");
 script_family(english:"CISCO");
 script_dependencie("snmp_sysDesc.nasl", "snmp_cisco_type.nasl");
 script_require_keys("SNMP/community", "SNMP/sysDesc", "CISCO/model");
 exit(0);
}

# The code starts here

ok=0;
os = get_kb_item("SNMP/sysDesc"); if(!os)exit(0);
hardware = get_kb_item("CISCO/model"); if(!hardware)exit(0);

# Check for the required hardware...
#----------------------------------------------------------------
# catalyst.*
if(ereg(string:hardware, pattern:"^catalyst.*$"))ok=1;

if(!ok)exit(0);
ok = 0;


# Check for the required operating system...
#----------------------------------------------------------------
# Is this CatOS ?

if(!egrep(pattern:".*Cisco Catalyst Operating System.*", string:os))exit(0);
# 3.0, 3.1 and 3.5 are vulnerable
if(egrep(string:os, pattern:"3\.[015].*,"))ok=1;


# 3.6.x fixed in 3.6.7
if(egrep(string:os, pattern:"3\.6\.[0-6][^0-9].*,"))ok=1;
if(egrep(string:os, pattern:"3\.6\.7[A-E].*,"))ok=1;


# 4.x -> fixed in 4.0.1
if(egrep(string:os, pattern:"4\.0(\.0)?.*,"))ok=1;



if(ok)security_hole(port:161, proto:"udp");
