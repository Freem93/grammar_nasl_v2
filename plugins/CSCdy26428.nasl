#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(11285);
 script_version("$Revision: 1.20 $");
 script_cve_id("CVE-2002-1222");
 script_bugtraq_id(5976);
 script_osvdb_id(8875);

 script_name(english:"Cisco Catalyst Switches Embeded HTTP Server Long HTTP Request DoS (CSCdy26428)");

 script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch." );
 script_set_attribute(attribute:"description", value:
"The remote switch is vulnerable to a buffer overflow
in its embedded HTTP server. An attacker may use this
flaw to make your switch reboot continuously, resulting
in a denial of service.

This vulnerability is documented with the CISCO
bug ID CSCdy26428." );
 script_set_attribute(attribute:"solution", value:
"http://www.nessus.org/u?9ddf57aa" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(119);

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/02/28");
 script_cvs_date("$Date: 2014/08/11 19:44:18 $");
 script_set_attribute(attribute:"vuln_publication_date", value: "2002/10/16");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value: "cpe:/o:cisco:ios");
 script_end_attributes();

 script_summary(english:"Uses SNMP to determine if a flaw is present");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is (C) 2003-2014 Tenable Network Security, Inc.");
 script_family(english:"CISCO");
 script_dependencie("snmp_sysDesc.nasl", "snmp_cisco_type.nasl");
 script_require_keys("SNMP/community", "SNMP/sysDesc", "CISCO/model");
 exit(0);
}

# The code starts here

ok=0;
os = get_kb_item("SNMP/sysDesc"); if(!os)exit(0);
hardware = get_kb_item("CISCO/model"); if(!hardware)exit(0);

if(!get_port_state(80))exit(0);
soc = http_open_socket(80);
if(!soc)exit(0);
else close(soc);

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
# 5.4
if(egrep(string:os, pattern:"(5\.4\([0-9]*\)|5\.4),"))ok=1;

# 5.5
if(egrep(string:os, pattern:"(5\.5\(([0-9]|1[0-6])\)|5\.5),"))ok=1;

# 6.0
if(egrep(string:os, pattern:"(6\.0\([0-9]*\)|6\.0),"))ok=1;

# 6.1
if(egrep(string:os, pattern:"(6\.1\([0-9]*\)|6\.1),"))ok=1;

# 6.2
if(egrep(string:os, pattern:"(6\.2\([0-9]*\)|6\.2),"))ok=1;

# 6.3
if(egrep(string:os, pattern:"(6\.3\([0-8]\)|6\.3),"))ok=1;

# 7.0
if(egrep(string:os, pattern:"(7\.0\([0-9]*\)|7\.0),"))ok=1;

# 7.1
if(egrep(string:os, pattern:"(7\.1\([0-9]*\)|7\.1),"))ok=1;

# 7.2
if(egrep(string:os, pattern:"(7\.2\([0-9]*\)|7\.2),"))ok=1;

# 7.3
if(egrep(string:os, pattern:"(7\.3\([0-9]*\)|7\.3),"))ok=1;

# 7.4
if(egrep(string:os, pattern:"(7\.4\([0-0]\)|7\.4),"))ok=1;


#----------------------------------------------

if(ok)security_hole(port:161, proto:"udp");
