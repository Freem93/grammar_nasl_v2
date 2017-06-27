#
# (C) Tenable Network Security, Inc.
#

# CSCdm44976 - ACL will not block non initial fragments of a packet. 
# CSCdu57417 - The keyword "fragment" in the compiled ACL (Turbo ACL) is ignored if a packet is destined to the router itself.
# CSCdu03323 - The implicit "deny ip any any" rule at the end of an ACL is ignored ..
# CSCdu35175 - A support for "fragment" keyword in an outgoing ACL is added. 
# CSCdt96370 - An outbound Access Control List (ACL) may not block all intended traffic ..
# CSCdt69741 - Packet fragments are not filtered by the ACL despite using "fragment" keyword. 


include("compat.inc");


if(description)
{
 script_id(10970);
 script_cve_id(
   "CVE-2001-0862", 
   "CVE-2001-0863", 
   "CVE-2001-0864", 
   "CVE-2001-0865", 
   "CVE-2001-0866", 
   "CVE-2001-0867"
 );
 script_bugtraq_id(
   3535, 
   3536, 
   3537, 
   3538, 
   3539, 
   3540
 );
 script_osvdb_id(
   1984, 
   1985, 
   1986, 
   1987, 
   1988, 
   1989
 );
 
 script_version("$Revision: 1.21 $");

 script_name(english:"Cisco 12000 Series Routers Multiple Vulnerabilities (DoS, ACL Bypass)");
 script_summary(english:"Uses SNMP to determine if a flaw is present");

 script_set_attribute(
   attribute:"synopsis",
   value:"The remote router has multiple security bypass vulnerabilities."
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "The remote host appears to be a Cisco 12000 Series router.  According\n",
     "to its version number, it has multiple vulnerabilities involving\n",
     "bypassing access control lists (ACLs).  A remote attacker could use\n",
     "these flaws to cause a denial of service, or bypass firewall rules."
   )
 );
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20011114-gsr-acl
 script_set_attribute(
   attribute:"see_also",
   value:"http://www.nessus.org/u?b0647406"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Apply the fix referenced in the vendor's advisory."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2002/06/05");
 script_set_attribute(attribute:"vuln_publication_date", value: "2001/11/14");
 script_set_attribute(attribute:"patch_publication_date", value: "2001/11/14");
 script_cvs_date("$Date: 2016/11/17 21:12:11 $");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe",value:"cpe:/h:cisco:12000_router");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"CISCO");

 script_copyright(english:"This script is (C) 2002-2016 Tenable Network Security, Inc.");


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




# Check for the required hardware...
#----------------------------------------------------------------
# cisco12000
if(ereg(string:hardware, pattern:"^cisco12[0-9][0-9][0-9]$"))ok=1;

if(!ok)exit(0);
ok = 0;


# Check for the required operating system...
#----------------------------------------------------------------
# Is this IOS ?
if(!egrep(pattern:".*(Internetwork Operating|IOS).*", string:os))exit(0);
# 12.0S
if(egrep(string:os, pattern:"(12\.0\(([0-9]|1[0-6])\)|12\.0)S[0-9]*,"))ok=1;

# 12.0ST
if(egrep(string:os, pattern:"(12\.0\(([0-9]|1[0-8])\)|12\.0)ST[0-9]*,"))ok=1;


#----------------------------------------------

if(ok)security_hole(port:161, proto:"udp");
