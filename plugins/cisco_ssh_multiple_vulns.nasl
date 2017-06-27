#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(10972);
 script_version("$Revision: 1.27 $");

 script_cve_id("CVE-2001-0361", "CVE-2001-0572");
 script_bugtraq_id(2344);
 script_osvdb_id(2116, 3561, 3562);

 script_name(english:"Cisco Devices Multiple SSH Information Disclosure Vulnerabilities");
 script_summary(english:"Uses SNMP to determine if a flaw is present");

 script_set_attribute(attribute:"synopsis", value:
"The remote network device is running an SSH server with multiple
vulnerabilities." );
 script_set_attribute( attribute:"description", value:
"According to its version number, the remote host is a Cisco router
or switch running a vulnerable SSH daemon.

By exploiting weaknesses in the SSH protocol, it is possible to
insert arbitrary commands into an established SSH session, collect
information that may help in brute-force key recovery, or brute-force
a session key." );
 script_set_attribute(
   attribute:"see_also",
   value:"http://seclists.org/bugtraq/2001/Mar/262"
 );
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20010627-ssh
 script_set_attribute(
   attribute:"see_also",
   value:"http://www.nessus.org/u?cf3fc1b5"
 );
 script_set_attribute(
   attribute:"solution",
   value:"Apply the fix referenced in the vendor's advisory."
 );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(310);
 script_set_attribute(attribute:"plugin_publication_date", value: "2002/06/05");
 script_set_attribute(attribute:"vuln_publication_date", value: "2001/03/18");
 script_set_attribute(attribute:"patch_publication_date", value: "2001/06/27");
 script_cvs_date("$Date: 2016/11/15 13:39:08 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"CISCO");

 script_copyright(english:"This script is (C) 2002-2016 Tenable Network Security, Inc.");

 script_dependencie("snmp_sysDesc.nasl",
			 "snmp_cisco_type.nasl",
			 "find_service1.nasl");
 script_require_keys("SNMP/community",
			  "SNMP/sysDesc",
			  "CISCO/model");
 exit(0);
}


# The code starts here
ok=0;
os = get_kb_item("SNMP/sysDesc"); if(!os)exit(0);
hardware = get_kb_item("CISCO/model"); if(!hardware)exit(0);


# Make sure SSH is running first...
ssh = get_kb_item("Services/ssh");
if(!ssh)ssh = 22;

if(!get_port_state(ssh))exit(0);
soc = open_sock_tcp(ssh);
if(!soc)exit(0);


# Check for the required operating system...
#----------------------------------------------------------------
# Is this IOS ?
if(!egrep(pattern:".*(Internetwork Operating|IOS).*", string:os))exit(0);
# 12.0S
if(egrep(string:os, pattern:"(12\.0\(([0-9]|1[0-9])\)|12\.0)S[0-9]*,"))ok=1;

# 12.1DB
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)DB[0-9]*,"))ok=1;

# 12.1DC
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)DC[0-9]*,"))ok=1;

# 12.1E
if(egrep(string:os, pattern:"(12\.1\([0-8]\)|12\.1)E[0-9]*,"))ok=1;

# 12.1EC
if(egrep(string:os, pattern:"((12\.1\([0-6]\)|12\.1)EC[0-9]*|12\.1\(7\)EC[0-2]),"))ok=1;

# 12.1EX
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)EX[0-9]*,"))ok=1;

# 12.1EY
if(egrep(string:os, pattern:"(12\.1\([0-5]\)|12\.1)EY[0-9]*,"))ok=1;

# 12.1EZ
if(egrep(string:os, pattern:"((12\.1\([0-5]\)|12\.1)EZ[0-9]*|12\.1\(6\)EZ[0-1]),"))ok=1;

# 12.1T
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)T[0-9]*,"))ok=1;

# 12.1XA
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)XA[0-9]*,"))ok=1;

# 12.1XB
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)XB[0-9]*,"))ok=1;

# 12.1XC
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)XC[0-9]*,"))ok=1;

# 12.1XD
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)XD[0-9]*,"))ok=1;

# 12.1XE
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)XE[0-9]*,"))ok=1;

# 12.1XF
if(egrep(string:os, pattern:"((12\.1\([0-1]\)|12\.1)XF[0-9]*|12\.1\(2\)XF[0-3]),"))ok=1;

# 12.1XG
if(egrep(string:os, pattern:"((12\.1\([0-4]\)|12\.1)XG[0-9]*|12\.1\(5\)XG[0-4]),"))ok=1;

# 12.1XH
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)XH[0-9]*,"))ok=1;

# 12.1XI
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)XI[0-9]*,"))ok=1;

# 12.1XJ
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)XJ[0-9]*,"))ok=1;

# 12.1XL
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)XL[0-9]*,"))ok=1;

# 12.1XM
if(egrep(string:os, pattern:"((12\.1\([0-3]\)|12\.1)XM[0-9]*|12\.1\(4\)XM[0-3]),"))ok=1;

# 12.1XP
if(egrep(string:os, pattern:"((12\.1\([0-2]\)|12\.1)XP[0-9]*|12\.1\(3\)XP[0-3]),"))ok=1;

# 12.1XQ
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)XQ[0-9]*,"))ok=1;

# 12.1XR
if(egrep(string:os, pattern:"((12\.1\([0-4]\)|12\.1)XR[0-9]*|12\.1\(5\)XR[0-1]),"))ok=1;

# 12.1XS
if(egrep(string:os, pattern:"((12\.1\([0-4]\)|12\.1)XS[0-9]*|12\.1\(5\)XS[0-1]),"))ok=1;

# 12.1XT
if(egrep(string:os, pattern:"((12\.1\([0-2]\)|12\.1)XT[0-9]*|12\.1\(3\)XT[0-2]),"))ok=1;

# 12.1XU
if(egrep(string:os, pattern:"((12\.1\([0-4]\)|12\.1)XU[0-9]*|12\.1\(5\)XU[0-0]),"))ok=1;

# 12.1XV
if(egrep(string:os, pattern:"((12\.1\([0-4]\)|12\.1)XV[0-9]*|12\.1\(5\)XV[0-2]),"))ok=1;

# 12.1XY
if(egrep(string:os, pattern:"((12\.1\([0-4]\)|12\.1)XY[0-9]*|12\.1\(5\)XY[0-5]),"))ok=1;

# 12.1YA
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)YA[0-9]*,"))ok=1;

# 12.1YB
if(egrep(string:os, pattern:"((12\.1\([0-4]\)|12\.1)YB[0-9]*|12\.1\(5\)YB[0-3]),"))ok=1;

# 12.1YD
if(egrep(string:os, pattern:"((12\.1\([0-4]\)|12\.1)YD[0-9]*|12\.1\(5\)YD[0-1]),"))ok=1;

# 12.1YF
if(egrep(string:os, pattern:"((12\.1\([0-4]\)|12\.1)YF[0-9]*|12\.1\(5\)YF[0-1]),"))ok=1;

# 12.2
if(egrep(string:os, pattern:"(12\.2\([0-2]\)|12\.2),"))ok=1;

# 12.2T
if(egrep(string:os, pattern:"(12\.2\([0-2]\)|12\.2)T[0-9]*,"))ok=1;

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

if(ok)security_hole(port:161, proto:"udp");
