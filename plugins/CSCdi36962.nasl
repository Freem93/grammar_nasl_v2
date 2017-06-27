#
# (C) Tenable Network Security, Inc.
#

# Script audit and contributions from Carmichael Security
#      Erik Anderson <eanders@carmichaelsecurity.com> (nb: domain no longer exists)
#      Fixed broken link
#


include("compat.inc");

if(description)
{
 script_id(10974);
 script_version("$Revision: 1.20 $");
 script_cve_id("CVE-1999-0161");
 script_bugtraq_id(703);
 script_osvdb_id(797);

 script_name(english:"Cisco IOS tacacs Keyword ACL Bypass (CSCdi36962)");

 script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch." );
 script_set_attribute(attribute:"description", value:
"The remote device seems to be vulnerable to a flaw in IOS when
the keyword 'tacacs-ds' or 'tacacs' is being used in
extended ACLs.

This bug can, under very specific circumstances and only with
certain IP host implementations, allow unauthorized packets to
circumvent a filtering router.

This vulnerability is documented as Cisco Bug ID CSCdi36962." );
 script_set_attribute(attribute:"solution", value:
"http://www.nessus.org/u?a0cafc92" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

 script_set_attribute(attribute:"plugin_publication_date", value: "2002/06/05");
 script_cvs_date("$Date: 2014/08/11 19:44:17 $");
 script_set_attribute(attribute:"vuln_publication_date", value: "1995/07/31");
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




# Check for the required operating system...
#----------------------------------------------------------------
# Is this IOS ?
if(!egrep(pattern:".*(Internetwork Operating|IOS).*", string:os))exit(0);
# 10.3
if(egrep(string:os, pattern:"(10\.3\([0-4]\)|10\.3),"))ok=1;


#----------------------------------------------

if(ok)security_hole(port:161, proto:"udp");
