#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if(description)
{
 script_id(20744);
 script_version("$Revision: 1.18 $");
 script_cve_id("CVE-2006-0340");
 script_bugtraq_id(16303);
 script_osvdb_id(22624);

 script_name(english:"Cisco IOS MMP Stack Group Bidding Protocol (SGBP) Crafted UDP Packet Remote DoS (CSCsb11124)");

 script_set_attribute(attribute:"synopsis", value:
"The remote router can be crashed remotely." );
 script_set_attribute(attribute:"description", value:
"The remote host is a CISCO router containing a version of IOS which is
prone to a denial of service vulnerability. 

An attacker may exploit this flaw to crash the remote device." );
 script_set_attribute(attribute:"solution", value:
"http://www.nessus.org/u?1142946b" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:N/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:W/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(20);


 script_set_attribute(attribute:"plugin_publication_date", value: "2006/01/19");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/01/18");
 script_cvs_date("$Date: 2014/08/11 19:44:18 $");
script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value: "cpe:/o:cisco:ios");
script_end_attributes();


 summary["english"] = "Uses SNMP to determine if a flaw is present";
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2006-2014 Tenable Network Security, Inc.");

 script_family(english:"CISCO");

 script_dependencie("snmp_sysDesc.nasl", "snmp_cisco_type.nasl");
 script_require_keys("SNMP/community", "SNMP/sysDesc", "CISCO/model");
 exit(0);
}


include('cisco_func.inc');

os = get_kb_item("SNMP/sysDesc"); if(!os)exit(0);
hardware = get_kb_item("CISCO/model"); if(!hardware)exit(0);
version = extract_version(os);
if ( ! version ) exit(0);


# 12.0
if ( deprecated_version(version, "12.0", "12.0SC", "12.0T", "12.0XA", "12.0XC", "12.0XD", "12.0XE", "12.0XG", "12.0XH", "12.0XI", "12.0XJ", "12.0XK", "12.0XL", "12.0XN", "12.0XR") ) vuln ++;


if ( check_release(version:version, 
		   patched:make_list("12.0(28)S6", "12.0(30)S5", "12.0(31)S3", "12.0(32)S"),
		   newest:"12.0(32)S") ) vuln ++;


# 12.1

if ( deprecated_version(version, "12.1", "12.1AA", "12.1EC", "12.1EX", "12.1EZ", "12.1GA", "12.1GB", "12.1T", "12.1XA", "12.1XD", "12.1XH", "12.1XI", "12.1XL", "12.1XM", "12.1XQ", "12.1XS", "12.1XU", "12.1XW", "12.1XX", "12.1XY", "12.1XZ", "12.1YA", "12.1YB", "12.1YD" ) ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.1(26)E5"),
		   newest:"12.1(26)E5") ) vuln ++;



# 12.2
if ( deprecated_version(version, "12.2B", "12.2BC", "12.2BW", "12.2CX", "12.2DD", "12.2DX", "12.2MC", "12.2SU", "12.2SY", "12.2SZ", "12.2T", "12.2XA", "12.2XB", "12.2XC", "12.2XF", "12.2XG", "12.2XK", "12.2XL", "12.2XS", "12.2XT", "12.2XV", "12.2YD", "12.2YE", "12.2YN", "12.2YT", "12.2YW", "12.2YX", "12.2YY", "12.2YZ", "12.2ZA", "12.2ZB", "12.2ZD", "12.2ZE", "12.2ZJ", "12.2ZN") ) vuln ++;


if ( check_release(version:version, 
		   patched:make_list("12.2(32)"),
		   newest:"12.2(32)") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.2(14)S16", "12.2(18)S"),
		   newest:"12.2(18)S") ) vuln ++;

#
# 12.3
#

if ( deprecated_version(version, "12.3B", "12.3BW", "12.3XB", "12.3XD", "12.3XF", "12.3XH", "12.3XJ", "12.3XM", "12.3XQ", "12.3XU", "12.3XW", "12.3YF", "12.3YJ", "12.3YT", "12.3YU") ) vuln ++;


if ( check_release(version:version, 
		   patched:make_list("12.3(16)"),
		   newest:"12.3(16)") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.3(13a)BC"),
		   newest:"12.3(13a)BC") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.3(11)T9", "12.3(14)T6"),
		   newest:"12.3(14)T6") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.3(14)YM4"),
		   newest:"12.3(14)YM4") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.3(14)YQ2"),
		   newest:"12.3(14)YQ2") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.3(14)YX"),
		   newest:"12.3(14)YX") ) vuln ++;


# 12.4

if ( check_release(version:version, 
		   patched:make_list("12.4(1b)", "12.4(3)"),
		   newest:"12.4(3)") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.4(2)MR"),
		   newest:"12.4(4)MR") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.4(2)T3", "12.4(4)T"),
		   newest:"12.4(4)T") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.4(2)XA"),
		   newest:"12.4(2)XA") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.4(2)XB"),
		   newest:"12.4(2)XB") ) vuln ++;

if ( vuln == 1 ) security_warning(port:161, proto:"udp");
else if ( vuln > 1 )  display("IOS version ", version, " identified as vulnerable by multiple checks\n");


