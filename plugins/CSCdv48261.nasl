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
 script_id(10985);
 script_version("$Revision: 1.19 $");
 script_cve_id("CVE-2001-0929");
 script_osvdb_id(808);

 script_name(english:"Cisco IOS Firewall CBAC ACL Bypass (CSCdv48261)");

 script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch." );
 script_set_attribute(attribute:"description", value:
"The IOS Firewall Feature set, also known as Cisco Secure Integrated
Software, also known as Context Based Access Control (CBAC), and
introduced in IOS version 11.2P, has a vulnerability that permits
traffic normally expected to be denied by the dynamic access control 
lists.

An attacker may use this flaw to break into your network even though
it was explicitly denied.

This vulnerability is documented as Cisco Bug ID CSCdv48261." );
 script_set_attribute(attribute:"solution", value:
"http://www.nessus.org/u?3fbe8d75

Reference : http://online.securityfocus.com/archive/1/242844" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

 script_set_attribute(attribute:"plugin_publication_date", value: "2002/06/05");
 script_cvs_date("$Date: 2014/08/11 19:44:18 $");
 script_set_attribute(attribute:"vuln_publication_date", value: "2001/11/28");
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


# Check that we have CBAC abilities...
if(!egrep(pattern:".*Software (.*-.*O.*-.*).*", string:os))exit(0);


# Check for the required hardware...
#----------------------------------------------------------------
# cisco800
if(ereg(string:hardware, pattern:"^cisco80[0-9]$"))ok=1;

# cisco820
if(ereg(string:hardware, pattern:"^cisco82[0-9]$"))ok=1;

# cisco950
if(ereg(string:hardware, pattern:"^cisco95[0-9]$"))ok=1;

# cisco1400
if(ereg(string:hardware, pattern:"^cisco14[0-9][0-9]$"))ok=1;

# cisco1600
if(ereg(string:hardware, pattern:"^cisco16[0-9][0-9]$"))ok=1;

# cisco2500
if(ereg(string:hardware, pattern:"^cisco25[0-9][0-9]$"))ok=1;

# cisco2600
if(ereg(string:hardware, pattern:"^cisco26[0-9][0-9]$"))ok=1;

# cisco3600
if(ereg(string:hardware, pattern:"^cisco36[0-9][0-9]$"))ok=1;

# cisco4000
if(ereg(string:hardware, pattern:"^cisco40[0-9][0-9]$"))ok=1;

# cisco4224
if(ereg(string:hardware, pattern:"^cisco4224$"))ok=1;

# cisco7100
if(ereg(string:hardware, pattern:"^cisco71[0-9][0-9]$"))ok=1;

# cisco7200
if(ereg(string:hardware, pattern:"^cisco72[0-9][0-9]$"))ok=1;

# cisco7400
if(ereg(string:hardware, pattern:"^cisco74[0-9][0-9]$"))ok=1;

# cisco7500
if(ereg(string:hardware, pattern:"^cisco75[0-9][0-9]$"))ok=1;

# ciscoSOHO7[0-9]
if(ereg(string:hardware, pattern:"^ciscoSOHO7[0-9]$"))ok=1;

# ciscoUBR90[0-9]
if(ereg(string:hardware, pattern:"^ciscoUBR90[0-9]$"))ok=1;

# cisco7750
if(ereg(string:hardware, pattern:"^cisco775[0-9]$"))ok=1;

# catalyst5k.*
if(ereg(string:hardware, pattern:"^catalyst5k.*$"))ok=1;

# catalyst6k.*
if(ereg(string:hardware, pattern:"^catalyst6k.*$"))ok=1;

if(!ok)exit(0);
ok = 0;


# Check for the required operating system...
#----------------------------------------------------------------
# Is this IOS ?
if(!egrep(pattern:".*(Internetwork Operating|IOS).*", string:os))exit(0);
# 11.2P
if(egrep(string:os, pattern:"(11\.2\([0-9]*\)|11\.2)P[0-9]*,"))ok=1;

# 11.3T
if(egrep(string:os, pattern:"(11\.3\([0-9]*\)|11\.3)T[0-9]*,"))ok=1;

# 12.0
if(egrep(string:os, pattern:"(12\.0\(([0-9]|[1-1][0-9]|2[0-0])\)|12\.0),"))ok=1;

# 12.0T
if(egrep(string:os, pattern:"(12\.0\([0-9]*\)|12\.0)T[0-9]*,"))ok=1;

# 12.0XA
if(egrep(string:os, pattern:"(12\.0\([0-9]*\)|12\.0)XA[0-9]*,"))ok=1;

# 12.0XB
if(egrep(string:os, pattern:"(12\.0\([0-9]*\)|12\.0)XB[0-9]*,"))ok=1;

# 12.0XC
if(egrep(string:os, pattern:"(12\.0\([0-9]*\)|12\.0)XC[0-9]*,"))ok=1;

# 12.0XD
if(egrep(string:os, pattern:"(12\.0\([0-9]*\)|12\.0)XD[0-9]*,"))ok=1;

# 12.0XE
if(egrep(string:os, pattern:"(12\.0\([0-9]*\)|12\.0)XE[0-9]*,"))ok=1;

# 12.0XG
if(egrep(string:os, pattern:"(12\.0\([0-9]*\)|12\.0)XG[0-9]*,"))ok=1;

# 12.0XI
if(egrep(string:os, pattern:"(12\.0\([0-9]*\)|12\.0)XI[0-9]*,"))ok=1;

# 12.0XK
if(egrep(string:os, pattern:"(12\.0\([0-9]*\)|12\.0)XK[0-9]*,"))ok=1;

# 12.0XM
if(egrep(string:os, pattern:"(12\.0\([0-9]*\)|12\.0)XM[0-9]*,"))ok=1;

# 12.0XQ
if(egrep(string:os, pattern:"(12\.0\([0-9]*\)|12\.0)XQ[0-9]*,"))ok=1;

# 12.0XR
if(egrep(string:os, pattern:"(12\.0\([0-9]*\)|12\.0)XR[0-9]*,"))ok=1;

# 12.0XV
if(egrep(string:os, pattern:"(12\.0\([0-9]*\)|12\.0)XV[0-9]*,"))ok=1;

# 12.1
if(egrep(string:os, pattern:"(12\.1\(([0-9]|1[0-1])\)|12\.1),"))ok=1;

# 12.1E
if(egrep(string:os, pattern:"(12\.1\([0-9]\)|12\.1)E[0-9]*,"))ok=1;

# 12.1T
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)T[0-9]*,"))ok=1;

# 12.1XB
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)XB[0-9]*,"))ok=1;

# 12.1XC
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)XC[0-9]*,"))ok=1;

# 12.1XF
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)XF[0-9]*,"))ok=1;

# 12.1XG
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)XG[0-9]*,"))ok=1;

# 12.1XH
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)XH[0-9]*,"))ok=1;

# 12.1XI
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)XI[0-9]*,"))ok=1;

# 12.1XJ
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)XJ[0-9]*,"))ok=1;

# 12.1XK
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)XK[0-9]*,"))ok=1;

# 12.1XL
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)XL[0-9]*,"))ok=1;

# 12.1XM
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)XM[0-9]*,"))ok=1;

# 12.1XP
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)XP[0-9]*,"))ok=1;

# 12.1XT
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)XT[0-9]*,"))ok=1;

# 12.1YB
if(egrep(string:os, pattern:"((12\.1\([0-4]\)|12\.1)YB[0-9]*|12\.1\(5\)YB[0-4]),"))ok=1;

# 12.1YC
if(egrep(string:os, pattern:"((12\.1\([0-4]\)|12\.1)YC[0-9]*|12\.1\(5\)YC[0-1]),"))ok=1;

# 12.1YE
if(egrep(string:os, pattern:"((12\.1\([0-4]\)|12\.1)YE[0-9]*|12\.1\(5\)YE[0-3]),"))ok=1;

# 12.1YF
if(egrep(string:os, pattern:"((12\.1\([0-4]\)|12\.1)YF[0-9]*|12\.1\(5\)YF[0-2]),"))ok=1;

# 12.2
if(egrep(string:os, pattern:"(12\.2\([0-5]\)|12\.2),"))ok=1;

# 12.2DD
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)DD[0-9]*,"))ok=1;

# 12.2T
if(egrep(string:os, pattern:"(12\.2\([0-7]\)|12\.2)T[0-9]*,"))ok=1;

# 12.2XD
if(egrep(string:os, pattern:"((12\.2\([0-1]\)|12\.2)XD[0-9]*|12\.2\(2\)XD[0-2]),"))ok=1;

# 12.2XE
if(egrep(string:os, pattern:"((12\.2\([0-0]\)|12\.2)XE[0-9]*|12\.2\(1\)XE[0-1]),"))ok=1;

# 12.2XH
if(egrep(string:os, pattern:"((12\.2\([0-1]\)|12\.2)XH[0-9]*|12\.2\(2\)XH[0-1]),"))ok=1;

# 12.2XI
if(egrep(string:os, pattern:"((12\.2\([0-1]\)|12\.2)XI[0-9]*|12\.2\(2\)XI[0-0]),"))ok=1;

# 12.2XJ
if(egrep(string:os, pattern:"((12\.2\([0-1]\)|12\.2)XJ[0-9]*|12\.2\(2\)XJ[0-0]),"))ok=1;

# 12.2XK
if(egrep(string:os, pattern:"((12\.2\([0-1]\)|12\.2)XK[0-9]*|12\.2\(2\)XK[0-4]),"))ok=1;

# 12.2XQ
if(egrep(string:os, pattern:"((12\.2\([0-1]\)|12\.2)XQ[0-9]*|12\.2\(2\)XQ[0-1]),"))ok=1;


#----------------------------------------------

if(ok)security_hole(port:161, proto:"udp");
