#
# (C) Tenable Network Security, Inc.
#

# Script audit and contributions from Carmichael Security
#      Erik Anderson <eanders@carmichaelsecurity.com> (nb: domain no longer exists)
#      Added link to the Bugtraq message archive
#

include("compat.inc");

if(description)
{
 script_id(10986);
 script_version("$Revision: 1.23 $");
 script_cve_id("CVE-2001-0554");
 script_bugtraq_id(3064);
 script_osvdb_id(809);

 script_name(english:"Cisco CatOS Telnet Option Handling Overflow (CSCdw19195)");

 script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch." );
 script_set_attribute(attribute:"description", value:
"Some Cisco Catalyst switches, running certain CatOS based software
releases, have a vulnerability wherein a buffer overflow in the telnet
option handling can cause the telnet daemon to crash and result in a
switch reload. This vulnerability can be exploited to initiate a 
denial of service (DoS) attack.

This vulnerability is documented as Cisco bug ID CSCdw19195." );
 script_set_attribute(attribute:"solution", value:
"http://www.nessus.org/u?c67eaadb

Reference : http://online.securityfocus.com/archive/1/252833" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2002/06/05");
 script_cvs_date("$Date: 2014/08/11 19:44:18 $");
 script_set_attribute(attribute:"vuln_publication_date", value: "2001/07/18");
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


# Check for the required hardware...
#----------------------------------------------------------------
# catalyst8500
if(ereg(string:hardware, pattern:"^catalyst85[0-9][0-9]$"))ok=1;

# catalyst4kGateway
if(ereg(string:hardware, pattern:"^catalyst4kGateway$"))ok=1;

# catalyst3[0-9][0-9][0-9][^0-9]*
if(ereg(string:hardware, pattern:"^catalyst3[0-9][0-9][0-9][^0-9]*$"))ok=1;

# catalyst29[0-9][0-9][^0-9]*
if(ereg(string:hardware, pattern:"^catalyst29[0-9][0-9][^0-9]*$"))ok=1;

# catalyst19[0-9][0-9][^0-9]*
if(ereg(string:hardware, pattern:"^catalyst19[0-9][0-9][^0-9]*$"))ok=1;

if(!ok)exit(0);
ok = 0;


# Check for the required operating system...
#----------------------------------------------------------------
# Is this CatOS ?
if(!egrep(pattern:".*Cisco Catalyst Operating System.*", string:os))exit(0);
# 4.5
if(egrep(string:os, pattern:"(4\.5\(([0-9]|1[0-2])\)|4\.5),"))ok=1;

# 5.5
if(egrep(string:os, pattern:"(5\.5\(([0-9]|1[0-2])\)|5\.5),"))ok=1;

# 6.3
if(egrep(string:os, pattern:"(6\.3\([0-3]\)|6\.3),"))ok=1;

# 7.1
if(egrep(string:os, pattern:"(7\.1\([0-1]\)|7\.1),"))ok=1;


#----------------------------------------------

if(ok)security_hole(port:161, proto:"udp");
