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
 script_id(10981);
 script_version("$Revision: 1.19 $");
 script_cve_id("CVE-2001-0757");
 script_bugtraq_id(2874);
 script_osvdb_id(804);

 script_name(english:"Cisco 6400 NRP2 Unauthenticated Telnet Access (CSCdt65960)");

 script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch." );
 script_set_attribute(attribute:"description", value:
"The Cisco 6400 Access Concentrator Node Route Processor 2 (NRP2) 
module allows Telnet access when no password has been set. The 
correct response is to disallow any remote access to the module until 
the password has been set. This vulnerability may result in users 
gaining unintended access to secure systems.

This vulnerability is documented as Cisco bug ID CSCdt65960." );
 script_set_attribute(attribute:"solution", value:
"http://www.nessus.org/u?63852177" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2002/06/05");
 script_cvs_date("$Date: 2014/08/11 19:44:17 $");
 script_set_attribute(attribute:"vuln_publication_date", value: "2001/06/14");
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
# cisco6400Nrp
if(ereg(string:hardware, pattern:"^cisco6400Nrp$"))ok=1;

if(!ok)exit(0);
ok = 0;


# Check for the required operating system...
#----------------------------------------------------------------
# Is this IOS ?
if(!egrep(pattern:".*(Internetwork Operating|IOS).*", string:os))exit(0);
# 12.1DC
if(egrep(string:os, pattern:"((12\.1\([0-4]\)|12\.1)DC[0-9]*|12\.1\(5\)DC[0-0]),"))ok=1;


#----------------------------------------------

if(ok)security_hole(port:161, proto:"udp");
