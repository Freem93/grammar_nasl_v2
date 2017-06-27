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
 script_id(10979);
 script_version("$Revision: 1.20 $");
 script_cve_id("CVE-2001-1183");
 script_bugtraq_id(3022);
 script_osvdb_id(802);

 script_name(english:"Cisco IOS Malformed PPTP Packet Remote DoS (CSCdt46181)");

 script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch." );
 script_set_attribute(attribute:"description", value:
"Point-to-Point Tunneling Protocol (PPTP) allows users to tunnel to an 
Internet Protocol (IP) network using a Point-to-Point Protocol (PPP). 
The protocol is described in RFC2637.

PPTP implementation using Cisco IOS software releases contains a 
vulnerability that will crash a router if it receives a malformed or 
crafted PPTP packet. To expose this vulnerability, PPTP must be 
enabled on the router. PPTP is disabled by default. No additional 
special conditions are required.

An attacker may use this issue to prevent your network
from working properly.

This vulnerability is documented as Cisco Bug ID CSCdt46181." );
 script_set_attribute(attribute:"solution", value:
"http://www.nessus.org/u?1583fe45" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"plugin_publication_date", value: "2002/06/05");
 script_cvs_date("$Date: 2014/08/11 19:44:17 $");
 script_set_attribute(attribute:"vuln_publication_date", value: "2001/07/12");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value: "cpe:/o:cisco:ios");
 script_end_attributes();

 script_summary(english:"Uses SNMP to determine if a flaw is present");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is (C) 2002-2014 Tenable Network Security, Inc.");
 script_family(english:"CISCO");
 script_dependencie("snmp_sysDesc.nasl", "snmp_cisco_type.nasl");
 script_require_keys("SNMP/community", "SNMP/sysDesc", "CISCO/model");
 exit(0);
}

# The code starts here

ok=0;
os = get_kb_item("SNMP/sysDesc"); if(!os)exit(0);
hardware = get_kb_item("CISCO/model"); if(!hardware)exit(0);




# Check for the required operating system...
#----------------------------------------------------------------
# Is this IOS ?
if(!egrep(pattern:".*(Internetwork Operating|IOS).*", string:os))exit(0);
# 12.1E
if(egrep(string:os, pattern:"(12\.1\([0-8]\)|12\.1)E[0-9]*,"))ok=1;

# 12.1EZ
if(egrep(string:os, pattern:"((12\.1\([0-5]\)|12\.1)EZ[0-9]*|12\.1\(6\)EZ[0-1]),"))ok=1;

# 12.1T
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)T[0-9]*,"))ok=1;

# 12.1XM
if(egrep(string:os, pattern:"((12\.1\([0-4]\)|12\.1)XM[0-9]*|12\.1\(5\)XM[0-3]),"))ok=1;

# 12.1XV
if(egrep(string:os, pattern:"((12\.1\([0-4]\)|12\.1)XV[0-9]*|12\.1\(5\)XV[0-2]),"))ok=1;

# 12.1YA
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)YA[0-9]*,"))ok=1;

# 12.1YB
if(egrep(string:os, pattern:"((12\.1\([0-4]\)|12\.1)YB[0-9]*|12\.1\(5\)YB[0-3]),"))ok=1;

# 12.1YC
if(egrep(string:os, pattern:"((12\.1\([0-4]\)|12\.1)YC[0-9]*|12\.1\(5\)YC[0-0]),"))ok=1;

# 12.1YD
if(egrep(string:os, pattern:"((12\.1\([0-4]\)|12\.1)YD[0-9]*|12\.1\(5\)YD[0-1]),"))ok=1;

# 12.2
if(egrep(string:os, pattern:"(12\.2\([0-2]\)|12\.2),"))ok=1;

# 12.2T
if(egrep(string:os, pattern:"(12\.2\([0-3]\)|12\.2)T[0-9]*,"))ok=1;

# 12.2XA
if(egrep(string:os, pattern:"(12\.2\([0-1]\)|12\.2)XA[0-9]*,"))ok=1;

# 12.2XD
if(egrep(string:os, pattern:"((12\.2\([0-0]\)|12\.2)XD[0-9]*|12\.2\(1\)XD[0-0]),"))ok=1;

# 12.2XE
if(egrep(string:os, pattern:"(12\.2\([0-0]\)|12\.2)XE[0-9]*,"))ok=1;

# 12.2XH
if(egrep(string:os, pattern:"(12\.2\([0-0]\)|12\.2)XH[0-9]*,"))ok=1;

# 12.2XQ
if(egrep(string:os, pattern:"(12\.2\([0-0]\)|12\.2)XQ[0-9]*,"))ok=1;


#----------------------------------------------

if(ok)security_warning(port:161, proto:"udp");
