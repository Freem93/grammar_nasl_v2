#
# (C) Tenable Network Security, Inc.
#

# Script audit and contributions from Carmichael Security
#      Erik Anderson <eanders@carmichaelsecurity.com> (nb: domain no longer exists)
#      Added BugtraqID and CAN
#


include("compat.inc");

if(description)
{
 script_id(11056);
 script_version("$Revision: 1.24 $");
 script_cve_id("CVE-2002-0813");
 script_bugtraq_id(5328);
 script_osvdb_id(854);

 script_name(english:"Cisco TFTP Server Long Filename DoS (CSCdy03429)");

 script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch." );
 script_set_attribute(attribute:"description", value:
"Trivial File Transfer Protocol (TFTP) is a protocol which allows for 
easy transfer of files between network connected devices. 

A vulnerability has been discovered in the processing of filenames 
within a TFTP read request when Cisco IOS is configured to act as a 
TFTP server.

This vulnerability is documented as Cisco Bug ID CSCdy03429." );
 script_set_attribute(attribute:"solution", value:
"http://www.nessus.org/u?1212ca9e" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:W/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(119);

 script_set_attribute(attribute:"plugin_publication_date", value: "2002/07/30");
 script_cvs_date("$Date: 2014/08/11 19:44:18 $");
 script_set_attribute(attribute:"vuln_publication_date", value: "2002/07/25");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value: "cpe:/o:cisco:ios");
 script_end_attributes();

 script_summary(english:"Uses SNMP to determine if a flaw is present");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is (C) 2002-2014 Tenable Network Security, Inc.");
 script_family(english:"CISCO");
 script_dependencie("snmp_sysDesc.nasl");
 script_require_keys("SNMP/community", "SNMP/sysDesc");
 exit(0);
}

# The code starts here

ok=0;
os = get_kb_item("SNMP/sysDesc"); if(!os)exit(0);

# Check for the required operating system...
#----------------------------------------------------------------
# Is this IOS ?

if(!egrep(pattern:".*(Internetwork Operating|IOS).*", string:os))exit(0);

# IOSes 11.1 to 11.3 are vulnerable
if(egrep(string:os, pattern:".* 11\.[1-3][^0-9].*"))
	security_hole(port:161, proto:"udp");

