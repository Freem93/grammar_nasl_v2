#
# (C) Tenable Network Security, Inc.
#
# @DEPRECATED@
#
# Disabled on 2010/11/15.  Use cisco-sa-20030515-saa.nasl (plugin ID 48970) instead.
#


include("compat.inc");

if(description)
{
 script_id(11632);
 script_cve_id("CVE-2003-0305");
 script_xref(name:"OSVDB", value:"8902");
 script_version("$Revision: 1.16 $");
 script_cvs_date("$Date: 2014/08/11 19:44:18 $");

 script_name(english:"Cisco IOS SAA Malformed RTR Packet DoS (CSCdx17916, CSCdx61997)");

 script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch." );
 script_set_attribute(attribute:"description", value:
"It is possible to crash the remote router by sending malformed
Response Time Responder (RTR) packets. 
For this flaw to be exploitable, the router needs to have RTR
responder enabled.

This bug is referenced as CISCO bug id CSCdx17916 and CSCdx61997." );
 script_set_attribute(attribute:"solution", value:
"See http://www.nessus.org/u?7e84eef2" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

 script_set_attribute(attribute:"cpe", value: "cpe:/o:cisco:ios");
 script_set_attribute(attribute:"plugin_publication_date", value: "2003/05/16");
 script_set_attribute(attribute:"vuln_publication_date", value: "2003/05/15");
 script_end_attributes();


 summary["english"] = "Uses SNMP to determine if a flaw is present";
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is (C) 2003-2014 Tenable Network Security, Inc.");

 script_family(english:"CISCO");

 script_dependencie("snmp_sysDesc.nasl",
			 "snmp_cisco_type.nasl");
 script_require_keys("SNMP/community",
			  "SNMP/sysDesc",
			  "CISCO/model");
 exit(0);
}


# Deprecated
exit(0, "This plugin has been deprecated. Use cisco-sa-20030515-saa.nasl (plugin ID 48970) instead.");

# The code starts here
ok=0;
os = get_kb_item("SNMP/sysDesc"); if(!os)exit(0);
hardware = get_kb_item("CISCO/model"); if(!hardware)exit(0);




# Check for the required operating system...
#----------------------------------------------------------------
# Is this IOS ?
if(!egrep(pattern:".*(Internetwork Operating|IOS).*", string:os))exit(0);
# 12.0S
if(egrep(string:os, pattern:"((12\.0\(([0-9]|[1-1][0-9]|2[0-0])\)|12\.0)S[0-9]*|12\.0\(21\)S[0-2]),"))ok=1;

# 12.0SC
if(egrep(string:os, pattern:"(12\.0\([0-9]*\)|12\.0)SC[0-9]*,"))ok=1;

# 12.0SL
if(egrep(string:os, pattern:"(12\.0\([0-9]*\)|12\.0)SL[0-9]*,"))ok=1;

# 12.0ST
if(egrep(string:os, pattern:"((12\.0\(([0-9]|[1-1][0-9]|2[0-0])\)|12\.0)ST[0-9]*|12\.0\(21\)ST[0-1]),"))ok=1;

# 12.0WC
if(egrep(string:os, pattern:"(12\.0\([0-4]\)|12\.0)WC[0-9]*,"))ok=1;

# 12.0SX
if(egrep(string:os, pattern:"(12\.0\([0-9]*\)|12\.0)SX[0-9]*,"))ok=1;

# 12.0SY
if(egrep(string:os, pattern:"(12\.0\(([0-9]|[1-1][0-9]|2[0-1])\)|12\.0)SY[0-9]*,"))ok=1;

# 12.1
if(egrep(string:os, pattern:"(12\.1\(([0-9]|1[0-7])\)|12\.1),"))ok=1;

# 12.1E
if(egrep(string:os, pattern:"(12\.1\(([0-9]|1[0-2])\)|12\.1)E[0-9]*,"))ok=1;

# 12.1EA
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)EA[0-9]*,"))ok=1;

# 12.1EW
if(egrep(string:os, pattern:"(12\.1\(([0-9]|1[0-0])\)|12\.1)EW[0-9]*,"))ok=1;

# 12.1EX
if(egrep(string:os, pattern:"(12\.1\(([0-9]|1[0-0])\)|12\.1)EX[0-9]*,"))ok=1;

# 12.1XF
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)XF[0-9]*,"))ok=1;

# 12.1XG
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)XG[0-9]*,"))ok=1;

# 12.1YG
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)YG[0-9]*,"))ok=1;

# 12.1YC
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)YC[0-9]*,"))ok=1;

# 12.2
if(egrep(string:os, pattern:"(12\.2\([0-9]\)|12\.2),"))ok=1;

# 12.2BC
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)BC[0-9]*,"))ok=1;

# 12.2BY
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)BY[0-9]*,"))ok=1;

# 12.2BZ
if(egrep(string:os, pattern:"(12\.2\(([0-9]|1[0-4])\)|12\.2)BZ[0-9]*,"))ok=1;

# 12.2DA
if(egrep(string:os, pattern:"(12\.2\(([0-9]|1[0-1])\)|12\.2)DA[0-9]*,"))ok=1;

# 12.2MB
if(egrep(string:os, pattern:"((12\.2\([0-3]\)|12\.2)MB[0-9]*|12\.2\(4\)MB[0-4]),"))ok=1;

# 12.2S
if(egrep(string:os, pattern:"(12\.2\(([0-9]|1[0-1])\)|12\.2)S[0-9]*,"))ok=1;

# 12.2XC
if(egrep(string:os, pattern:"((12\.2\([0-0]\)|12\.2)XC[0-9]*|12\.2\(1\)XC[0-4]),"))ok=1;

# 12.2XD
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)XD[0-9]*,"))ok=1;

# 12.2XE
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)XE[0-9]*,"))ok=1;

# 12.2XH
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)XH[0-9]*,"))ok=1;

# 12.2XI
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)XI[0-9]*,"))ok=1;

# 12.2XJ
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)XJ[0-9]*,"))ok=1;

# 12.2XK
if(egrep(string:os, pattern:"((12\.2\([0-1]\)|12\.2)XK[0-9]*|12\.2\(2\)XK[0-2]),"))ok=1;

# 12.2XL
if(egrep(string:os, pattern:"((12\.2\([0-3]\)|12\.2)XL[0-9]*|12\.2\(4\)XL[0-4]),"))ok=1;

# 12.2XM
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)XM[0-9]*,"))ok=1;

# 12.2YA
if(egrep(string:os, pattern:"((12\.2\([0-3]\)|12\.2)YA[0-9]*|12\.2\(4\)YA[0-2]),"))ok=1;

# 12.2YB
if(egrep(string:os, pattern:"(12\.2\([0-7]\)|12\.2)YB[0-9]*,"))ok=1;

# 12.2YC
if(egrep(string:os, pattern:"((12\.2\([0-3]\)|12\.2)YC[0-9]*|12\.2\(4\)YC[0-3]),"))ok=1;

# 12.2YF
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)YF[0-9]*,"))ok=1;

# 12.2YG
if(egrep(string:os, pattern:"(12\.2\([0-3]\)|12\.2)YG[0-9]*,"))ok=1;

# 12.2YH
if(egrep(string:os, pattern:"(12\.2\([0-3]\)|12\.2)YH[0-9]*,"))ok=1;


#----------------------------------------------

if(ok)security_warning(port:161, proto:"udp");
