#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(24737);
 script_cve_id("CVE-2007-1257");
 script_bugtraq_id(22751);
 script_osvdb_id(33066);
 script_version("$Revision: 1.18 $");

 script_name(english:"Cisco Multiple Products Network Analysis Module (NAM) SNMP Spoofing Remote Code Execution");

 script_set_attribute(attribute:"synopsis", value:
"The remote device can be crashed remotely." );
 script_set_attribute(attribute:"description", value:
"The remote host is a CISCO Catalyst or Cisco 7600 router that
contains a version of IOS or CatOS that is affected by an SNMP
communication spoofing vulnerability. 

An attacker may exploit this flaw to gain complete control of the remote
device." );
 script_set_attribute(attribute:"solution", value:
"http://www.nessus.org/u?519fd09c" );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(20);
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/03/01");
 script_set_attribute(attribute:"vuln_publication_date", value: "2007/02/28");
 script_cvs_date("$Date: 2016/05/04 18:02:12 $");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value: "cpe:/o:cisco:ios");
 script_end_attributes();

 summary["english"] = "Uses SNMP to determine if a flaw is present";
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");

 script_family(english:"CISCO");

 script_dependencie("snmp_sysDesc.nasl", "snmp_cisco_type.nasl");
 script_require_keys("SNMP/community", "SNMP/sysDesc", "CISCO/model");
 exit(0);
}


include('cisco_func.inc');

os = get_kb_item("SNMP/sysDesc"); if(!os)exit(0);
hardware = get_kb_item("CISCO/model"); if(!hardware)exit(0);
if(!ereg(string:hardware, pattern:"^(cat6[05]|catalyst6k|cisco76[0-9][0-9]).*$"))exit(0);


version = extract_version(os);
if ( ! version ) exit(0);

if(egrep(pattern:".*(Internetwork Operating|IOS).*", string:os))
{


#
# 12.1
#

if ( check_release(version:version, 
		   patched:make_list("12.1(26)E8", "12.1(27b)E1"),
		   newest:"12.1(27b)E1") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.1(12c)EX", "12.1(13)EX"),
		   newest:"12.1(13)EX") ) vuln ++;


#
# 12.2
#
if ( deprecated_version(version, "12.2EU", "12.2EW", "12.2IXA", "12.2SX", "12.2SXA", "12.2SXB", "12.2SY", "12.2ZA") ) vuln ++;

if ( "EWA" >< version &&
     check_release(version:version, 
		   patched:make_list("12.2(25)EWA7"),
		   newest:"12.2(25)EWA7") ) vuln ++;

if ( "IXB" >< version &&
     check_release(version:version, 
		   patched:make_list("12.2(18)IXB2"),
		   newest:"12.2(18)IXB2") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.2(14)S3", "12.2(18)S5", "12.2(20)S"),
		   newest:"12.2(20)S") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.2(25)SG1"),
		   newest:"12.2(25)SG1") ) vuln ++;

if ( "SGA" >< version &&
     check_release(version:version, 
		   patched:make_list("12.2(31)SGA1"),
		   newest:"12.2(31)SGA1") ) vuln ++;

if ( "SRA" >< version &&
     check_release(version:version, 
		   patched:make_list("12.2(33)SRA2"),
		   newest:"12.2(33)SRA2") ) vuln ++;

if ( "SXD" >< version &&
     check_release(version:version, 
		   patched:make_list("12.2(18)SXD7"),
		   newest:"12.2(18)SXD7") ) vuln ++;

if ( "SXE" >< version &&
     check_release(version:version, 
		   patched:make_list("12.2(18)SXE6a"),
		   newest:"12.2(18)SXE6a") ) vuln ++;

if ( "SXF" >< version &&
     check_release(version:version, 
		   patched:make_list("12.2(18)SXF5"),
		   newest:"12.2(18)SXF5") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.2(18)ZU1"),
		   newest:"12.2(18)ZU1") ) vuln ++;

} # IOS

else if ( egrep(pattern:".*Cisco Catalyst Operating System.*", string:os) )
{
if ( egrep(pattern:"7\.6\(1[5-9]\)", string:version) )
 {
 if ( check_release(version:version, 
		   patched:make_list("7.6(19.2)", "7.6(20)"),
		   newest:"7.6(20)") ) vuln ++;
 }
if ( egrep(pattern:"8\.5\([1-5]\)", string:version) )
 {
 if ( check_release(version:version, 
		   patched:make_list("8.5(5.3)", "8.5(6)"),
		   newest:"8.5(6)") ) vuln ++;
 }
}

if ( vuln == 1 ) security_hole(port:161, proto:"udp");
else if ( vuln > 1 ) display("IOS version ", version, " identified as vulnerable by multiple checks\n");
