#
# (C) Tenable Network Security, Inc.
#

# Script audit and contributions from Carmichael Security
#      Erik Anderson <eanders@carmichaelsecurity.com> (nb: domain no longer exists)
#      Added BugtraqID and CVE
#


include("compat.inc");

if(description)
{
 script_id(10975);
 script_version("$Revision: 1.21 $");
 script_cve_id("CVE-2000-0700");
 script_bugtraq_id(1541);
 script_osvdb_id(793, 798);

 script_name(english:"Cisco Gigabit Switch Routers (GSR) Line Card Failure ACL Bypas (CSCdp35794)");

 script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch." );
 script_set_attribute(attribute:"description", value:
"A defect in Cisco IOS Software running on all models of Gigabit 
Switch Routers (GSRs) configured with Gigabit Ethernet or Fast 
Ethernet cards may cause packets to be forwarded without correctly 
evaluating configured access control lists (ACLs). In addition to 
circumventing the access control lists, it is possible to stop an 
interface from forwarding any packets, thus causing a denial of 
service.

This vulnerability is documented as Cisco bug ID CSCdp35794." );
 script_set_attribute(attribute:"solution", value:
"http://www.nessus.org/u?23472f49" );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:U/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"plugin_publication_date", value: "2002/06/05");
 script_cvs_date("$Date: 2016/05/04 18:02:12 $");
 script_set_attribute(attribute:"vuln_publication_date", value: "2000/08/03");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value: "cpe:/o:cisco:ios");
 script_end_attributes();

 script_summary(english:"Uses SNMP to determine if a flaw is present");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is (C) 2002-2016 Tenable Network Security, Inc.");
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
# cisco12008
if(ereg(string:hardware, pattern:"^cisco12008$"))ok=1;

# cisco12012
if(ereg(string:hardware, pattern:"^cisco12012$"))ok=1;

# cisco12016
if(ereg(string:hardware, pattern:"^cisco12016$"))ok=1;

if(!ok)exit(0);
ok = 0;


# Check for the required operating system...
#----------------------------------------------------------------
# Is this IOS ?
if(!egrep(pattern:".*(Internetwork Operating|IOS).*", string:os))exit(0);
# 11.2GS
if(egrep(string:os, pattern:"(11\.2\(([0-9]|1[0-8])\)|11\.2)GS[0-9]*,"))ok=1;

# 12.0S
if(egrep(string:os, pattern:"(12\.0\([0-8]\)|12\.0)S[0-9]*,"))ok=1;

# 12.0SC
if(egrep(string:os, pattern:"(12\.0\([0-8]\)|12\.0)SC[0-9]*,"))ok=1;


#----------------------------------------------

if(ok)security_warning(port:161, proto:"udp");
