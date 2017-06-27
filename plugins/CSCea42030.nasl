#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(11547);
 script_cve_id("CVE-2003-0216");
 script_osvdb_id(8903);
 script_version("$Revision: 1.16 $");

 script_name(english:"Cisco Catalyst Enable Access Authentication Bypass (CSCea42030)");

 script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch." );
 script_set_attribute(attribute:"description", value:
"The remote Catalyst is affected by a password bypass vulnerability. 
Basically, an attacker who has a command line access may gain the
'enable' privileges without having to know the right password, which
would allow him to reconfigure this host remotely. 

This vulnerability is documented with the CISCO bug ID CSCde42030." );
 script_set_attribute(attribute:"solution", value:
"http://www.nessus.org/u?62e6a495" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_cwe_id(287);

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/04/24");
 script_set_attribute(attribute:"vuln_publication_date", value: "2003/04/19");
 script_cvs_date("$Date: 2014/08/11 19:44:18 $");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value: "cpe:/o:cisco:ios");
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


# The code starts here
ok=0;
os = get_kb_item("SNMP/sysDesc"); if(!os)exit(0);
hardware = get_kb_item("CISCO/model"); if(!hardware)exit(0);




# Check for the required hardware...
#----------------------------------------------------------------
# catalyst.*
if(ereg(string:hardware, pattern:"^catalyst.*$"))ok=1;

if(!ok)exit(0);
ok = 0;


# Check for the required operating system...
#----------------------------------------------------------------
# Is this CatOS ?
if(!egrep(pattern:".*Cisco Catalyst Operating System.*", string:os))exit(0);
# 7.5
if(egrep(string:os, pattern:"(7\.5\([0-9]*\)|7\.5),"))ok=1;

# 7.6
if(egrep(string:os, pattern:"(7\.6\([0-0]\)|7\.6),"))ok=1;


#----------------------------------------------

if(ok)security_hole(port:161, proto:"udp");
