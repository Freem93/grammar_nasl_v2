#
# (C) Tenable Network Security, Inc.
#

# References:
#
# From: FX <fx@phenoelit.de>
# To: bugtraq@securityfocus.com, darklab@darklab.org
# Subject: Cisco IOS OSPF exploit
# Message-ID: <20030220164519.GC282@echelon.cluster.phenoelit.de>
#
#
# From: Mike Caudill <mcaudill@cisco.com>
# Message-Id: <200302212229.h1LMToD25063@rtp-cse-184.cisco.com> 
# Subject: Re: Cisco IOS OSPF exploit 
#
# http://www.nessus.org/u?b37db228
#


include("compat.inc");

if(description)
{
 script_id(11283);
 script_version("$Revision: 1.19 $");
 script_cve_id("CVE-2003-0100");
 script_bugtraq_id(6895);
 script_osvdb_id(6455);

 script_name(english:"Cisco IOS OSPF Neighbor Announcement Remote Overflow (CSCdp58462)");

 script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The Open Shortest Path First (OSPF) implementation in remote
Cisco IOS software versions is vulnerable to a denial of service
if it receives a flood of neighbor announcements in which more than
255 hosts try to establish a neighbor relationship per interface.

An attacker may use this flaw to prevent your router from working
properly

This vulnerability is documented as Cisco Bug ID CSCdp58462." );
 script_set_attribute(attribute:"solution", value:
"http://www.nessus.org/u?b37db228" );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:W/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/02/28");
 script_cvs_date("$Date: 2016/05/04 18:02:12 $");
 script_set_attribute(attribute:"vuln_publication_date", value: "2003/02/20");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value: "cpe:/o:cisco:ios");
 script_end_attributes();

 script_summary(english:"Uses SNMP to determine if a flaw is present");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is (C) 2003-2016 Tenable Network Security, Inc.");
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
# 11.1
if(egrep(string:os, pattern:"(11\.1\([0-9]*\)|11\.1),"))ok=1;

# 12.0S
if(egrep(string:os, pattern:"(12\.0\(([0-9]|1[0-8])\)|12\.0)S[0-9]*,"))ok=1;

# 12.0ST
if(egrep(string:os, pattern:"(12\.0\(([0-9]|1[0-8])\)|12\.0)ST[0-9]*,"))ok=1;

# 12.1
if(egrep(string:os, pattern:"(12\.1\([0-1]\)|12\.1),"))ok=1;

# 12.1DB
if(egrep(string:os, pattern:"(12\.1\([0-0]\)|12\.1)DB[0-9]*,"))ok=1;

# 12.1DC
if(egrep(string:os, pattern:"(12\.1\([0-0]\)|12\.1)DC[0-9]*,"))ok=1;

# 12.1T
if(egrep(string:os, pattern:"(12\.1\([0-0]\)|12\.1)T[0-9]*,"))ok=1;


#----------------------------------------------

if(ok)security_hole(port:161, proto:"udp");
