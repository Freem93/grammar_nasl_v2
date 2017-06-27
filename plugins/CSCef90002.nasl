#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(24736);
 script_version("$Revision: 1.18 $");
 script_cve_id("CVE-2007-1258");
 script_bugtraq_id(22750);
 script_osvdb_id(33067);

 script_name(english:"Cisco Catalyst Hybrid Mode Malformed MPLS Packet Remote DoS (CSCsd37415, CSCef90002)");

 script_set_attribute(attribute:"synopsis", value:
"The remote switch can be crashed remotely." );

 script_set_attribute(attribute:"description", value: 
"The remote host is a CISCO Catalyst 6500 switch containing a version
of IOS that is affected by a denial of service vulnerability when
processing malformed MPLS packets. 

An attacker may exploit this flaw to crash the remote device." );
 script_set_attribute(attribute:"solution", value:
"http://www.nessus.org/u?0e6ad627" );
 script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/03/01");
 script_set_attribute(attribute:"vuln_publication_date", value: "2007/02/28");
 script_cvs_date("$Date: 2014/08/11 19:44:18 $");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value: "cpe:/o:cisco:ios");
 script_end_attributes();

 summary["english"] = "Uses SNMP to determine if a flaw is present";
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2007-2014 Tenable Network Security, Inc.");

 script_family(english:"CISCO");

 script_dependencie("snmp_sysDesc.nasl", "snmp_cisco_type.nasl");
 script_require_keys("SNMP/community", "SNMP/sysDesc", "CISCO/model");
 exit(0);
}


include('cisco_func.inc');

os = get_kb_item("SNMP/sysDesc"); if(!os)exit(0);
if(!egrep(pattern:".*(Internetwork Operating|IOS).*", string:os)) exit(0);
hardware = get_kb_item("CISCO/model"); if(!hardware)exit(0);
if(!ereg(string:hardware, pattern:"^cat6500.*$"))exit(0);

version = extract_version(os);
if ( ! version ) exit(0);




if ( deprecated_version(version, "12.2SXA") ) vuln ++;


if ( "SXB" >< version &&
     check_release(version:version, 
		   patched:make_list("12.2(17d)SXB5"),
		   newest:"12.2(17d)SXB5") ) vuln ++;

if ( "SXB" >< version &&
     check_release(version:version, 
		   patched:make_list("12.2(18)SXD3"),
		   newest:"12.2(18)SXD3") ) vuln ++;

if ( "SXF" >< version &&
     check_release(version:version, 
		   patched:make_list("12.2(18)SXF5"),
		   newest:"12.2(18)SXF5") ) vuln ++;



if ( vuln == 1 ) security_warning(port:161, proto:"udp");
else if ( vuln > 1 )  display("IOS version ", version, " identified as vulnerable by multiple checks\n");


