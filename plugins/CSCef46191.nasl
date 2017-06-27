#
# (C) Tenable Network Security
#


include("compat.inc");

if(description)
{
 script_id(15627);
 script_cve_id("CVE-2004-1464");
 script_bugtraq_id(11060);
 script_osvdb_id(9265);
 script_version("$Revision: 1.18 $");

 script_name(english:"Cisco IOS Telnet Service DoS (CSCef46191)");

 script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch." );
 script_set_attribute(attribute:"description", value:
"The remote router contains a version of IOS which has a flaw in the
telnet service that could allow an attacker to disable the 
administation of the remote router by SSH, HTTP and telnet.

CISCO identifies this vulnerability as bug id CSCef46191.

An attacker may use this flaw to render this router unmanageable." );
 script_set_attribute(attribute:"solution", value:
"http://www.nessus.org/u?5bb6a85b" );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:W/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/11/04");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/08/27");
 script_cvs_date("$Date: 2016/05/04 18:02:12 $");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value: "cpe:/o:cisco:ios");
 script_end_attributes();


 summary["english"] = "Uses SNMP to determine if a flaw is present";
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");

 script_family(english:"CISCO");

 script_dependencie("snmp_sysDesc.nasl",
			 "snmp_cisco_type.nasl");
 script_require_keys("SNMP/community",
			  "SNMP/sysDesc",
			  "CISCO/model");
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
# 12.0
if(egrep(string:os, pattern:"((12\.0\(([0-9]|[1-1][0-9]|2[0-7])\)|12\.0)|12\.0\(28\)),"))ok=1;

# 12.1
if(egrep(string:os, pattern:"(12\.1\(([0-9]|[1-1][0-9]|2[0-5])\)|12\.1),"))ok=1;

# 12.1E
if(egrep(string:os, pattern:"((12\.1\(([0-9]|1[0-9])\)|12\.1)E[0-9]*|12\.1\(20\)E[0-4]),"))ok=1;

# 12.1EA
if(egrep(string:os, pattern:"((12\.1\(([0-9]|[1-1][0-9]|2[0-1])\)|12\.1)EA[0-9]*|12\.1\(22\)EA[0-1]),"))ok=1;

# 12.2
if(egrep(string:os, pattern:"(12\.2\(([0-9]|[1-1][0-9]|2[0-6])\)|12\.2),"))ok=1;

# 12.2BC
if(egrep(string:os, pattern:"((12\.2\(([0-9]|1[0-4])\)|12\.2)BC[0-9]*|12\.2\(15\)BC[0-0]),"))ok=1;

# 12.2EW
if(egrep(string:os, pattern:"((12\.2\(([0-9]|1[0-7])\)|12\.2)EW[0-9]*|12\.2\(18\)EW[0-1]),"))ok=1;

# 12.2JK
if(egrep(string:os, pattern:"((12\.2\(([0-9]|1[0-4])\)|12\.2)JK[0-9]*|12\.2\(15\)JK[0-1]),"))ok=1;

# 12.2S
if(egrep(string:os, pattern:"((12\.2\(([0-9]|1[0-7])\)|12\.2)S[0-9]*|12\.2\(18\)S[0-5]),"))ok=1;

# 12.2SE
if(egrep(string:os, pattern:"((12\.2\(([0-9]|1[0-9])\)|12\.2)SE[0-9]*|12\.2\(20\)SE[0-2]),"))ok=1;

# 12.2SU
if(egrep(string:os, pattern:"((12\.2\(([0-9]|1[0-9])\)|12\.2)SU[0-9]*|12\.2\(20\)SU[0-2]),"))ok=1;

# 12.2SV
if(egrep(string:os, pattern:"(12\.2\(([0-9]|[1-1][0-9]|2[0-3])\)|12\.2)SV[0-9]*,"))ok=1;

# 12.2SXD
if(egrep(string:os, pattern:"((12\.2\(([0-9]|1[0-7])\)|12\.2)SXD[0-9]*|12\.2\(18\)SXD[0-0]),"))ok=1;

# 12.2T
if(egrep(string:os, pattern:"((12\.2\(([0-9]|1[0-2])\)|12\.2)T[0-9]*|12\.2\(13\)T([0-9]|1[0-3])),"))ok=1;

# 12.2XR
if(egrep(string:os, pattern:"((12\.2\(([0-9]|1[0-4])\)|12\.2)XR[0-9]*|12\.2\(15\)XR[0-1]),"))ok=1;

# 12.3
if(egrep(string:os, pattern:"(12\.3\(([0-9]|1[0-1])\)|12\.3),"))ok=1;

# 12.3BC
if(egrep(string:os, pattern:"((12\.3\([0-4]\)|12\.3)BC[0-9]*|12\.3\(5\)BC[0-1]),"))ok=1;

# 12.3JA
if(egrep(string:os, pattern:"(12\.3\([0-1]\)|12\.3)JA[0-9]*,"))ok=1;

# 12.3T
if(egrep(string:os, pattern:"((12\.3\([0-1]\)|12\.3)T[0-9]*|12\.3\(2\)T[0-7]),"))ok=1;

# 12.3XD
if(egrep(string:os, pattern:"((12\.3\([0-3]\)|12\.3)XD[0-9]*|12\.3\(4\)XD[0-3]),"))ok=1;

# 12.3XG
if(egrep(string:os, pattern:"((12\.3\([0-3]\)|12\.3)XG[0-9]*|12\.3\(4\)XG[0-1]),"))ok=1;

# 12.3XI
if(egrep(string:os, pattern:"((12\.3\([0-6]\)|12\.3)XI[0-9]*|12\.3\(7\)XI[0-1]),"))ok=1;

# 12.3XK
if(egrep(string:os, pattern:"((12\.3\([0-3]\)|12\.3)XK[0-9]*|12\.3\(4\)XK[0-0]),"))ok=1;

# 12.3XR
if(egrep(string:os, pattern:"((12\.3\([0-6]\)|12\.3)XR[0-9]*|12\.3\(7\)XR[0-2]),"))ok=1;

# 12.3XU
if(egrep(string:os, pattern:"((12\.3\([0-7]\)|12\.3)XU[0-9]*|12\.3\(8\)XU[0-1]),"))ok=1;

# 12.3YD
if(egrep(string:os, pattern:"(12\.3\([0-7]\)|12\.3)YD[0-9]*,"))ok=1;


#----------------------------------------------

if(ok)security_hole(port:161, proto:"udp");
