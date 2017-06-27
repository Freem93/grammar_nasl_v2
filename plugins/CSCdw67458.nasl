#
# (C) Tenable Network Security, Inc.
#

# Script audit and contributions from Carmichael Security
#      Erik Anderson <eanders@carmichaelsecurity.com> (nb: domain no longer exists)
#      Added BugtraqID and CAN
#     

include("compat.inc");

if(description)
{
 script_id(10987);
 script_version("$Revision: 1.28 $");
 script_cve_id("CVE-2002-0012", "CVE-2002-0013");
 script_bugtraq_id(4088, 4132);
 script_osvdb_id(3664, 810);

 script_name(english:"Cisco Malformed SNMP Message Handling DoS (CSCdw67458)");

 script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch." );
 script_set_attribute(attribute:"description", value:
"There is a vulnerability in the way the remote device handles
SNMP messages. An attacker may use this flaw to crash the remote
device continuously.

This vulnerability is documented as Cisco bug ID CSCdw67458." );
 script_set_attribute(attribute:"solution", value:
"http://www.nessus.org/u?a1f3c81e

Reference : http://online.securityfocus.com/archive/1/255807" );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(264);

 script_set_attribute(attribute:"plugin_publication_date", value: "2002/06/05");
 script_cvs_date("$Date: 2016/05/04 18:02:12 $");
 script_set_attribute(attribute:"vuln_publication_date", value: "2002/02/12");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value: "cpe:/o:cisco:ios");
 script_end_attributes();

 script_summary(english:"Uses SNMP to determine if a flaw is present");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2002-2016 Tenable Network Security, Inc.");
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
# 4.5
if(egrep(string:os, pattern:"(4\.5\(([0-9]|1[0-2])\)|4\.5),"))ok=1;

# 5.1CSX
if(egrep(string:os, pattern:"(5\.1\([0-0]\)|5\.1)CSX[0-9]*,"))ok=1;

# 5.1
if(egrep(string:os, pattern:"(5\.1\([0-1]\)|5\.1),"))ok=1;

# 5.2CSX
if(egrep(string:os, pattern:"(5\.2\([0-2]\)|5\.2)CSX[0-9]*,"))ok=1;

# 5.2
if(egrep(string:os, pattern:"(5\.2\([0-6]\)|5\.2),"))ok=1;

# 5.3CSX
if(egrep(string:os, pattern:"(5\.3\([0-5]\)|5\.3)CSX[0-9]*,"))ok=1;

# 5.4
if(egrep(string:os, pattern:"(5\.4\([0-3]\)|5\.4),"))ok=1;

# 5.5
if(egrep(string:os, pattern:"(5\.5\([0-6]\)|5\.5),"))ok=1;

# 5.5
if(egrep(string:os, pattern:"(5\.5\(([0-9]|1[0-2])\)|5\.5),"))ok=1;

# 6.1
if(egrep(string:os, pattern:"(6\.1\([0-3]\)|6\.1),"))ok=1;

# 6.2
if(egrep(string:os, pattern:"(6\.2\([0-2]\)|6\.2),"))ok=1;

# 6.3X
if(egrep(string:os, pattern:"((6\.3\([0-2]\)|6\.3)X[0-9]*|6\.3\(3\)X[0-0]),"))ok=1;

# 6.3
if(egrep(string:os, pattern:"(6\.3\([0-4]\)|6\.3),"))ok=1;

# 7.1
if(egrep(string:os, pattern:"(7\.1\([0-1]\)|7\.1),"))ok=1;


#----------------------------------------------

if(ok)security_hole(port:161, proto:"udp");
