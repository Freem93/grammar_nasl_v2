#
# (C) Tenable Network Security, Inc.
#

# This vulnerability is tracked by three different bug IDs: CSCdr46528,
# CSCdt66560, and CSCds36541 


include("compat.inc");


if(description)
{
 script_id(10971);
 script_version("$Revision: 1.21 $");
 script_cve_id("CVE-2001-0861");
 script_bugtraq_id(3534);
 script_osvdb_id(794);

 script_name(english:"Cisco 12000 Series Router ICMP Unreachable DoS");
 script_summary(english:"Uses SNMP to determine if a flaw is present");

 script_set_attribute(
   attribute:"synopsis",
   value:"The remote router has a denial of service vulnerability."
 );
 script_set_attribute( attribute:"description",  value:
"The remote device appears to be a Cisco 12000 Series router.
According to its version number, it is vulnerable to a denial of
service issue.  Forcing it to send a large number of ICMP unreachable
packets can slow down throughput.  A remote attacker could use this to
degrade the performance of the network." );
 # https://web.archive.org/web/20011221043803/http://archives.neohapsis.com/archives/cisco/2001-q4/0005.html
 script_set_attribute(
   attribute:"see_also",
   value:"http://www.nessus.org/u?8c7b55bb"
 );
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20011114-gsr-unreachable
 script_set_attribute(
   attribute:"see_also",
   value:"http://www.nessus.org/u?e37ea3d2"
 );
 script_set_attribute(
   attribute:"solution", 
   value:string(
     "Upgrade to the latest version of the software, or disable/rate\n",
     "limit the sending of ICMP unreachable packets."
   )
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2002/06/05");
 script_set_attribute(attribute:"vuln_publication_date", value: "2001/11/14");
 script_set_attribute(attribute:"patch_publication_date", value: "2001/11/14");
 script_cvs_date("$Date: 2016/11/15 13:39:08 $");
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
if(egrep(string:os, pattern:"(12\.0\(([0-9]|1[0-5])\)|12\.0)ST[0-9]*,"))ok=1;


#----------------------------------------------

if(ok)security_warning(port:161, proto:"udp");
