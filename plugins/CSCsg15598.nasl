#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(24739);
 script_cve_id("CVE-2007-0917", "CVE-2007-0918");
 script_bugtraq_id(22549);
 script_osvdb_id(33052, 33053);
 script_version("$Revision: 1.17 $");

 script_name(english:"Cisco IOS Intrusion Prevention System (IPS) Multiple Vulnerabilities (CSCsa53334, CSCsg15598)");

 script_set_attribute(attribute:"synopsis", value:
"The remote CISCO device can be crashed remotely." );
 script_set_attribute(attribute:"description", value:
"The remote version of IOS contains an intrusion prevention system
that is affected by a fragmented packet evasion vulnerability and a
denial of service vulnerability. 

An attacker might use these flaws to disable this device remotely or to 
sneak past the IPS." );
 script_set_attribute(attribute:"solution", value:
"http://www.nessus.org/u?16b1f263" );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(20);
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/03/01");
 script_set_attribute(attribute:"vuln_publication_date", value: "2007/02/13");
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
version = extract_version(os);
if ( ! version ) exit(0);



# 12.3 Deprecated
if ( deprecated_version(version, "12.3XQ", "12.3XR", "12.3XS", "12.3XW", "12.3XX", "12.3XY", "12.3YA", "12.3YD", "12.3YG", "12.3YH", "12.3YI", "12.3YJ", "12.3YK", "12.3YS", "12.3YT") ) vuln ++;


if ( check_release(version:version,
		   patched:make_list("12.3(2)T", "12.3(4)T", "12.3(7)T", "12.3(11)T10", "12.3(14)T7"),
		   newest:"12.3(14)T7") ) vuln ++;

if ( check_release(version:version,
		   patched:make_list("12.3(14)YM5"),
		   newest:"12.3(14)YM5") ) vuln ++;

if ( check_release(version:version,
		   patched:make_list("12.3(14)YQ8"),
		   newest:"12.3(14)YQ8") ) vuln ++;

if ( check_release(version:version,
		   patched:make_list("12.3(14)YX3"),
		   newest:"12.3(14)YX3") ) vuln ++;

if ( check_release(version:version,
		   patched:make_list("12.3(11)YZ"),
		   newest:"12.3(11)YZ") ) vuln ++;
# 12.4

if ( deprecated_version(version, "12.4XE") ) vuln ++;

if ( check_release(version:version,
		   patched:make_list("12.4(1c)", "12.4(3b)", "12.4(5)", "12.4(7e)", "12.4(10b)", "12.4(12)"),
		   newest:"12.4(12)") ) vuln ++;


if ( check_release(version:version,
		   patched:make_list("12.4(6)MR1"),
		   newest:"12.4(6)MR1") ) vuln ++;

if ( check_release(version:version,
		   patched:make_list("12.4(2)T3", "12.4(4)T", "12.4(6)T", "12.4(9)T3", "12.4(11)T1"),
		   newest:"12.4(11)T1") ) vuln ++;

if ( check_release(version:version,
		   patched:make_list("12.4(2)XA2"),
		   newest:"12.4(2)XA2") ) vuln ++;

if ( check_release(version:version,
		   patched:make_list("12.4(2)XB3"),
		   newest:"12.4(2)XB3") ) vuln ++;

if ( vuln == 1 ) security_hole(port:161, proto:"udp");
else if ( vuln > 1 ) display("IOS version ", version, " identified as vulnerable by multiple checks\n");
