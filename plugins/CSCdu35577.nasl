#
# (C) Tenable Network Security, Inc.
#
# Thanks to Nicolas FISCHBACH (nico@securite.org) for his help
#
# Ref:  http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20020903-vpn3k-vulnerability
#
# Changes by Tenable :
# - Added CVSS score, revised desc.
# - Fixed typo, added URL comment.


include("compat.inc");

if(description)
{
 script_id(11289);
 script_bugtraq_id(5621, 5623, 5624);
 script_osvdb_id(8909);
 script_version("$Revision: 1.18 $");
 script_cve_id("CVE-2002-1094");

 script_name(english:"Cisco VPN 3000 Concentrator Multiple Service Banner System Information Disclosure (CSCdu35577)");

 script_set_attribute(attribute:"synopsis", value:
"The remote VPN concentrator reveals application layer banners." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the remote VPN concentrator gives out
too much information in application layer banners. This
vulnerability is documented as Cisco bug ID CSCdu35577." );
 # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20020903-vpn3k-vulnerability
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d2dd6759" );
 script_set_attribute(attribute:"solution", value:
"Apply vendor-supplied patches." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/03/01");
 script_set_attribute(attribute:"vuln_publication_date", value: "2002/09/03");
 script_cvs_date("$Date: 2014/08/11 19:44:18 $");
script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value: "cpe:/o:cisco:ios");
script_end_attributes();


 summary["english"] = "Uses SNMP to determine if a flaw is present";
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is (C) 2003-2014 Tenable Network Security, Inc.");

 script_family(english:"CISCO");

 script_dependencie("snmp_sysDesc.nasl");
 script_require_keys("SNMP/community",
			  "SNMP/sysDesc",
			  "CISCO/model");
 exit(0);
}


# The code starts here
ok=0;

os = get_kb_item("SNMP/sysDesc"); if(!os)exit(0);

# Is this a VPN3k concentrator ?
if(!egrep(pattern:".*VPN 3000 Concentrator.*", string:os))exit(0);

# < 3.5.4
if(egrep(pattern:".*Version 3\.5\.Rel.*", string:os))ok = 1;
if(egrep(pattern:".*Version 3\.5\.[0-3].*", string:os))ok = 1;

# 3.0.x and 3.1.x
if(egrep(pattern:".*Version 3\.[0-1]\..*", string:os))ok = 1;

# 2.x.x
if(egrep(pattern:".*Version 2\..*", string:os))ok = 1;


if(ok)security_warning(port:161, proto:"udp");
