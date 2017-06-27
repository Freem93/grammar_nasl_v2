#
# (C) Tenable Network Security / Description (C) George Theall
#


include("compat.inc");

if(description)
{
 script_id(14337);
 script_osvdb_id(9009);
 script_cve_id("CVE-2004-1454");
 script_bugtraq_id(10971);
 script_version("$Revision: 1.20 $");

 script_name(english:"Cisco IOS OSPF Packet Handling DoS (CSCec16481)");

 script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch." );
 script_set_attribute(attribute:"description", value:
"The target is a Cisco device running a version of IOS that is vulnerable
to a DoS attack from a malformed OSPF packet.  Given knowledge of OSPF
area number, netmask, hello, and dead timers that are configured on the
targeted interface, a remote attacker can send a malformed OSPF packet and
cause the device to be reset, which may take several minutes. Note,
though, that the OSPF protocol is not enabled by default.

This vulnerability is documented as Cisco Bug ID CSCec16481." );
 script_set_attribute(attribute:"solution", value:
"http://www.nessus.org/u?fefa1e85" );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:W/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/08/22");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/08/18");
 script_cvs_date("$Date: 2016/05/04 18:02:12 $");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value: "cpe:/o:cisco:ios");
 script_end_attributes();


 summary["english"] = "Uses SNMP to determine if a flaw is present";
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is (C) 2004-2016 Tenable Network Security, Inc. and George Theall");

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
# 12.0S
if(egrep(string:os, pattern:"((12\.0\(([0-9]|[1-1][0-9]|2[0-5])\)|12\.0)S[0-9]*|12\.0\(26\)S[0-0]),"))ok=1;

# 12.0SX
if(egrep(string:os, pattern:"((12\.0\(([0-9]|[1-1][0-9]|2[0-4])\)|12\.0)SX[0-9]*|12\.0\(25\)SX[0-1]),"))ok=1;

# 12.0SY
if(egrep(string:os, pattern:"(12\.0\([0-9]*\)|12\.0)SY[0-9]*,"))ok=1;

# 12.0SZ
if(egrep(string:os, pattern:"(12\.0\([0-9]*\)|12\.0)SZ[0-9]*,"))ok=1;

# 12.2B
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)B[0-9]*,"))ok=1;

# 12.2BC
if(egrep(string:os, pattern:"((12\.2\(([0-9]|1[0-4])\)|12\.2)BC[0-9]*|12\.2\(15\)BC[0-1]),"))ok=1;

# 12.2BX
if(egrep(string:os, pattern:"(12\.2\(([0-9]|1[0-5])\)|12\.2)BX[0-9]*,"))ok=1;

# 12.2BZ
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)BZ[0-9]*,"))ok=1;

# 12.2CX
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)CX[0-9]*,"))ok=1;

# 12.2EW
if(egrep(string:os, pattern:"((12\.2\(([0-9]|1[0-7])\)|12\.2)EW[0-9]*|12\.2\(18\)EW[0-0]),"))ok=1;

# 12.2MC
if(egrep(string:os, pattern:"((12\.2\(([0-9]|1[0-4])\)|12\.2)MC[0-9]*|12\.2\(15\)MC[0-1]),"))ok=1;

# 12.2S
if(egrep(string:os, pattern:"(12\.2\(([0-9]|1[0-9])\)|12\.2)S[0-9]*,"))ok=1;

# 12.2SE
if(egrep(string:os, pattern:"(12\.2\(([0-9]|1[0-9])\)|12\.2)SE[0-9]*,"))ok=1;

# 12.2SV
if(egrep(string:os, pattern:"(12\.2\(([0-9]|[1-1][0-9]|2[0-1])\)|12\.2)SV[0-9]*,"))ok=1;

# 12.2SW
if(egrep(string:os, pattern:"(12\.2\(([0-9]|1[0-9])\)|12\.2)SW[0-9]*,"))ok=1;

# 12.2SZ
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)SZ[0-9]*,"))ok=1;

# 12.2T
if(egrep(string:os, pattern:"((12\.2\(([0-9]|1[0-4])\)|12\.2)T[0-9]*|12\.2\(15\)T[0-7]),"))ok=1;

# 12.2YU
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)YU[0-9]*,"))ok=1;

# 12.2YV
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)YV[0-9]*,"))ok=1;

# 12.2ZD
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)ZD[0-9]*,"))ok=1;

# 12.2ZE
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)ZE[0-9]*,"))ok=1;

# 12.2ZF
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)ZF[0-9]*,"))ok=1;

# 12.2ZE
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)ZE[0-9]*,"))ok=1;

# 12.2ZF
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)ZF[0-9]*,"))ok=1;

# 12.2ZG
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)ZG[0-9]*,"))ok=1;

# 12.2ZH
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)ZH[0-9]*,"))ok=1;

# 12.2ZJ
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)ZJ[0-9]*,"))ok=1;

# 12.2ZK
if(egrep(string:os, pattern:"((12\.2\(([0-9]|1[0-4])\)|12\.2)ZK[0-9]*|12\.2\(15\)ZK[0-1]),"))ok=1;

# 12.2ZL
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)ZL[0-9]*,"))ok=1;

# 12.2ZN
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)ZN[0-9]*,"))ok=1;

# 12.2ZO
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)ZO[0-9]*,"))ok=1;

# 12.3
if(egrep(string:os, pattern:"(12\.3\([0-4]\)|12\.3),"))ok=1;

# 12.3B
if(egrep(string:os, pattern:"(12\.3\([0-4]\)|12\.3)B[0-9]*,"))ok=1;

# 12.3BW
if(egrep(string:os, pattern:"(12\.3\([0-9]*\)|12\.3)BW[0-9]*,"))ok=1;

# 12.3T
if(egrep(string:os, pattern:"((12\.3\([0-1]\)|12\.3)T[0-9]*|12\.3\(2\)T[0-3]),"))ok=1;

# 12.3XA
if(egrep(string:os, pattern:"(12\.3\([0-9]*\)|12\.3)XA[0-9]*,"))ok=1;

# 12.3XB
if(egrep(string:os, pattern:"((12\.3\([0-1]\)|12\.3)XB[0-9]*|12\.3\(2\)XB[0-2]),"))ok=1;

# 12.3XC
if(egrep(string:os, pattern:"(12\.3\([0-9]*\)|12\.3)XC[0-9]*,"))ok=1;

# 12.3XE
if(egrep(string:os, pattern:"(12\.3\([0-9]*\)|12\.3)XE[0-9]*,"))ok=1;


#----------------------------------------------

if(ok)security_warning(port:161, proto:"udp");
