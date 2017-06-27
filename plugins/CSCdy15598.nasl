#
# (C) Tenable Network Security
#


include("compat.inc");

if(description)
{
 script_id(12039);
 script_cve_id("CVE-2004-0244");
 script_bugtraq_id(9562);
 script_osvdb_id(3804);

 script_version("$Revision: 1.17 $");

 script_name(english:"Cisco IOS 6000/6500/7600 Series Layer 2 Frame DoS (CSCdy15598, CSCeb56052)");

 script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch." );
 script_set_attribute(attribute:"description", value:
"The remote router contains a version of IOS which has multiple flaws when
dealing with specially layer 2 packets.

CISCO identifies this vulnerability as bug id CSCdy15598 and CSCeb56052.

An attacker may use this flaw to render this router inoperable." );
 script_set_attribute(attribute:"solution", value:
"http://www.nessus.org/u?efcdea28" );
 script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:N/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(20);

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/02/03");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/02/04");
 script_cvs_date("$Date: 2014/08/11 19:44:18 $");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value: "cpe:/o:cisco:ios");
 script_end_attributes();


 summary["english"] = "Uses SNMP to determine if a flaw is present";
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is (C) 2004-2014 Tenable Network Security, Inc.");

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
# catalyst6k.*
if(ereg(string:hardware, pattern:"^catalyst6k.*$"))ok=1;

if(!ok)exit(0);
ok = 0;


# Check for the required operating system...
#----------------------------------------------------------------
# Is this IOS ?
if(!egrep(pattern:".*(Internetwork Operating|IOS).*", string:os))exit(0);
# 12.1E
if(egrep(string:os, pattern:"(12\.1\(([0-9]|1[0-8])\)|12\.1)E[0-9]*,"))ok=1;

# 12.2SY
if(egrep(string:os, pattern:"(12\.2\(([0-9]|1[0-3])\)|12\.2)SY[0-9]*,"))ok=1;

# 12.2ZA
if(egrep(string:os, pattern:"(12\.2\(([0-9]|1[0-3])\)|12\.2)ZA[0-9]*,"))ok=1;


#----------------------------------------------

if(ok)security_warning(port:161, proto:"udp");
