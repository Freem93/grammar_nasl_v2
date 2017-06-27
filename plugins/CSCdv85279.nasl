#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(11382);
 script_version("$Revision: 1.25 $");
 script_cve_id("CVE-2002-1024");
 script_bugtraq_id(5114);
 script_osvdb_id(5029);

 script_name(english:"Cisco Catalyst SSH Large Packet CPU Consumption DoS (CSCdv85279, CSCdw59394)");

 script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"It is possible to make the remote CatOS crash
when sending malformed SSH packets.

This vulnerability is documented with the CISCO
bug ID CSCdv85279 and CSCdw59394" );
 script_set_attribute(attribute:"solution", value:
"http://www.nessus.org/u?7641e722" );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:U/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(399);

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/03/14");
 script_cvs_date("$Date: 2016/05/04 18:02:12 $");
 script_set_attribute(attribute:"vuln_publication_date", value: "2002/06/27");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value: "cpe:/o:cisco:ios");
 script_end_attributes();

 script_summary(english:"Uses SNMP to determine if a flaw is present");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is (C) 2003-2016 Tenable Network Security, Inc.");
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
# catalyst6.*
if(ereg(string:hardware, pattern:"^catalyst6.*$"))ok=1;

if(!ok)exit(0);
ok = 0;


# Check for the required operating system...
#----------------------------------------------------------------
# Is this CatOS ?
if(!egrep(pattern:".*Cisco Catalyst Operating System.*", string:os))exit(0);
# 6.3
if(egrep(string:os, pattern:"(6\.3\(([0-2][^0-9]|3.[0-5])\)|6\.3),"))ok=1;

# 7.1
if(egrep(string:os, pattern:"(7\.1\(([0-1][^0-9]|0.([0-9]|[1-8][0-9]|9[0-3]))\)|7\.1),"))ok=1;

# 7.2
if(egrep(string:os, pattern:"(7\.2\(([0-1][^0-9]|0.([0-9]|1[0-3]))\)|7\.2),"))ok=1;


#----------------------------------------------

if(ok)security_hole(port:161, proto:"udp");
