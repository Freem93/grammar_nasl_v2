#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(24744);
 script_version("$Revision: 1.19 $");
 script_cve_id("CVE-2007-0479");
 script_bugtraq_id(22208);
 script_osvdb_id(32093);

 script_name(english:"Cisco IOS TCP Listener Crafted Packets Remote DoS (CSCek37177)");

 script_set_attribute(attribute:"synopsis", value:
"It is possible to crash the remote device remotely." );
 script_set_attribute(attribute:"description", value:
"The remote CISCO switch runs a version of IOS contains a flaw which
may cause the remote router to crash when processing specially
malformed TCP packets. 

An attacker might use these flaws to crash this router remotely." );
 script_set_attribute(attribute:"solution", value:
"http://www.nessus.org/u?1885e120" );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2007/03/01");
 script_set_attribute(attribute:"vuln_publication_date", value: "2007/01/24");
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



if ( deprecated_version(version, "12.0", "12.0DA", "12.0DB", "12.0DC", "12.0SC", "12.0SL", "12.0SP", "12.0ST", "12.0SZ", "12.0T", "12.0XA", "12.0XB", "12.0XC", "12.0XD", "12.0XE", "12.0XG", "12.0XH", "12.0XI", "12.0XJ", "12.0XK", "12.0XL", "12.0XM", "12.0XN", "12.0XQ", "12.0XR", "12.0XS", "12.0XV") ) vuln ++;

if ( check_release(version:version,
		   patched:make_list("12.0(31)S6", "12.0(32)S4"),
		   newest:"12.0(32)S4") ) vuln ++;

if ( check_release(version:version,
		   patched:make_list("12.0(25)SX11"),
		   newest:"12.0(25)SX11") ) vuln ++;

if ( check_release(version:version,
		   patched:make_list("12.0(32)SY"),
		   newest:"12.0(32)SY") ) vuln ++;

if ( check_release(version:version,
		   patched:make_list("12.0(5)WC15"),
		   newest:"12.0(5)WC15") ) vuln ++;


# 12.1
if ( deprecated_version(version, "12.1", "12.1AA", "12.1AX", "12.1AY", "12.1AZ", "12.1CX", "12.1DA", "12.1DB", "12.1DC", "12.1EB", "12.1EC", "12.1EU", "12.1EV", "12.1EW", "12.1EX", "12.1EY", "12.1EZ", "12.1T", "12.1XA", "12.1XB", "12.1XC", "12.1XD", "12.1XE", "12.1XF", "12.1XG", "12.1XH", "12.1XI", "12.1XJ", "12.1XL", "12.1XM", "12.1XP", "12.1XQ", "12.1XR", "12.1XS", "12.1XT", "12.1XU", "12.1XV", "12.1XW", "12.1XX", "12.1XY", "12.1XZ", "12.1YA", "12.1YB", "12.1YC", "12.1YD", "12.1YE", "12.1YF", "12.1YH", "12.1YI", "12.1YJ") ) vuln ++;

if ( check_release(version:version,
		   patched:make_list("12.1(26)E7", "12.1(27b)E1"),
		   newest:"12.1(27b)E1") ) vuln ++;

if ( check_release(version:version,
		   patched:make_list("12.1(22)EA8"),
		   newest:"12.1(22)EA8") ) vuln ++;

if ( check_release(version:version,
		   patched:make_list("12.1(19)EO6", "12.1(20)EO3"),
		   newest:"12.1(20)EO3") ) vuln ++;

# 12.2
if ( deprecated_version(version, "12.2B", "12.2BC", "12.2BW", "12.2BY", "12.2BZ", "12.2CX", "12.2CY", "12.2CZ", "12.2DD", "12.2DX", "12.2EU", "12.2EW", "12.2EZ", "12.2FY", "12.2IXA", "12.2IXB", "12.2IXC", "12.2JA", "12.2JK", "12.2MB","12.2MC", "12.2SEA", "12.2SEC", "12.2SED", "12.2SEG", "12.2SU", "12.2SX", "12.2SXA", "12.2SXB", "12.2SY", "12.2SZ", "12.2T", "12.2TPC", "12.2XA", "12.2XB", "12.2XC", "12.2XD", "12.2XE", "12.2XF", "12.2XG", "12.2XH", "12.2XI", "12.2XJ", "12.2XK", "12.2XL", "12.2XM", "12.2XN", "12.2XQ", "12.2XR", "12.2XS", "12.2XT", "12.2XU", "12.2XV", "12.2XW", "12.2YA", "12.2YB", "12.2YC", "12.2YD", "12.2YE", "12.2YF", "12.2YG", "12.2YH", "12.2YJ", "12.2YK", "12.2YL", "12.2YM", "12.YN", "12.2YP", "12.2YQ", "12.2YR", "12.2YS", "12.2YT", "12.2YU", "12.2YV", "12.2YW", "12.2YX", "12.2YY", "12.2YZ", "12.2ZA", "12.2AB", "12.2ZC", "12.2ZD", "12.2ZE", "12.2ZF", "12.2ZG", "12.2ZH", "12.2ZJ", "12.2ZL", "12.2ZN", "12.2ZP") ) vuln ++;

if ( check_release(version:version,
		   patched:make_list("12.2(37)"),
		   newest:"12.2(37)") ) vuln ++;

if ( check_release(version:version,
		   patched:make_list("12.2(10)DA5", "12.2(12)DA10"),
		   newest:"12.2(12)DA10") ) vuln ++;

if ( "EWA" >< version &&
     check_release(version:version,
		   patched:make_list("12.2(25)EWA6"),
		   newest:"12.2(25)EWA6") ) vuln ++;

if ( check_release(version:version,
		   patched:make_list("12.2(25)EX1"),
		   newest:"12.2(25)EX1") ) vuln ++;

if ( check_release(version:version,
		   patched:make_list("12.2(25)EY4"),
		   newest:"12.2(25)EY4") ) vuln ++;

if ( check_release(version:version,
		   patched:make_list("12.2(25)S12"),
		   newest:"12.2(25)S12") ) vuln ++;

if ( check_release(version:version,
		   patched:make_list("12.2(28)SB2", "12.2(31)SB"),
		   newest:"12.2(31)SB") ) vuln ++;

if ( "SBC" >< version &&
     check_release(version:version,
		   patched:make_list("12.2(27)SBC5"),
		   newest:"12.2(27)SBC5") ) vuln ++;

if ( version !~ 'SE[A-Z]' &&  # only check SE trains, not SEE or SEF
     check_release(version:version,
		   patched:make_list("12.2(35)SE"),
		   newest:"12.2(35)SE") ) vuln ++;

if ( 'SEE' >< version &&
     check_release(version:version,
		   patched:make_list("12.2(25)SEE1"),
		   newest:"12.2(25)SEE1") ) vuln ++;

if ( 'SEF' >< version &&  # only check SEF releases, not SEE
     check_release(version:version,
		   patched:make_list("12.2(25)SEF1"),
		   newest:"12.2(25)SEF1") ) vuln ++;

if ( check_release(version:version,
		   patched:make_list("12.2(37)SG"),
		   newest:"12.2(37)SG") ) vuln ++;

if ( check_release(version:version,
		   patched:make_list("12.2(18)SO7"),
		   newest:"12.2(18)SO7") ) vuln ++;

if ( check_release(version:version,
		   patched:make_list("12.2(27)SV4", "12.2(28)SV1", "12.2(29)SV1"),
		   newest:"12.2(29)SV1") ) vuln ++;

if ( check_release(version:version,
		   patched:make_list("12.2(25)SW8"),
		   newest:"12.2(25)SW8") ) vuln ++;

if ( "SXD" >< version &&
     check_release(version:version,
		   patched:make_list("12.2(18)SXD7a"),
		   newest:"12.2(18)SXD7a") ) vuln ++;

if ( "SXE" >< version &&
     check_release(version:version,
		   patched:make_list("12.2(18)SXE6"),
		   newest:"12.2(18)SXE6") ) vuln ++;

if ( "SXF" >< version &&
     check_release(version:version,
		   patched:make_list("12.2(18)SXF5"),
		   newest:"12.2(18)SXF5") ) vuln ++;

# 12.3 
if ( deprecated_version(version, "12.3B", "12.3BW", "12.3TPC", "12.3XA", "12.3XB", "12.3XD", "12.3XE", "13.3XF", "12.3XG", "12.3XH", "12.3XJ", "12.3XK", "12.3XQ", "12.3XR", "12.3XS", "12.3XU", "12.3XW", "12.3XX", "12.3XY", "12.3YA", "12.3YD", "12.3YF", "12.3YG", "12.3YH", "12.3YI", "12.3YJ", "12.3YK", "12.3YS", "12.3YT", "12.3YU") ) vuln ++;

if ( check_release(version:version,
		   patched:make_list("12.3(10f)", "12.3(19)"),
		   newest:"12.3(19)") ) vuln ++;

if ( check_release(version:version,
		   patched:make_list("12.3(13a)BC6", "12.3(17a)BC2"),
		   newest:"12.3(17a)BC2") ) vuln ++;

if ( check_release(version:version,
		   patched:make_list("12.3(8)JA2"),
		   newest:"12.3(8)JA2") ) vuln ++;

if ( check_release(version:version,
		   patched:make_list("12.3(2)JK2"),
		   newest:"12.3(2)JK2") ) vuln ++;

if ( check_release(version:version,
		   patched:make_list("12.3(7)JX4", "12.3(11)JX"),
		   newest:"12.3(11)JX") ) vuln ++;

if ( check_release(version:version,
		   patched:make_list("12.3(4)T13", "12.3(11)T11"),
		   newest:"12.3(11)T11") ) vuln ++;

if ( check_release(version:version,
		   patched:make_list("12.3(7)XI8"),
		   newest:"12.3(7)XI8") ) vuln ++;

if ( check_release(version:version,
		   patched:make_list("12.3(14)YM8"),
		   newest:"12.3(14)YM8") ) vuln ++;

if ( check_release(version:version,
		   patched:make_list("12.3(14)YQ8"),
		   newest:"12.3(14)YQ8") ) vuln ++;

if ( check_release(version:version,
		   patched:make_list("12.3(14)YX2"),
		   newest:"12.3(14)YX2") ) vuln ++;

if ( check_release(version:version,
		   patched:make_list("12.3(11)YZ1"),
		   newest:"12.3(11)YZ1") ) vuln ++;

# 12.4
if ( deprecated_version(version, "12.4XA", "12.4XB") ) vuln ++;

if ( check_release(version:version,
		   patched:make_list("12.4(3e)", "12.4(7b)", "12.4(8)"),
		   newest:"12.4(8)") ) vuln ++;

if ( check_release(version:version,
		   patched:make_list("12.4(6)MR1"),
		   newest:"12.4(6)MR1") ) vuln ++;

if ( check_release(version:version,
		   patched:make_list("12.4(2)T5", "12.4(4)T4", "12.4(6)T3", "12.4(9)T"),
		   newest:"12.4(9)T") ) vuln ++;

if ( check_release(version:version,
		   patched:make_list("12.4(4)XC3"),
		   newest:"12.4(4)XC3") ) vuln ++;

if ( check_release(version:version,
		   patched:make_list("12.4(4)XD4"),
		   newest:"12.4(4)XD4") ) vuln ++;

if ( vuln == 1 ) security_hole(port:161, proto:"udp");
else if ( vuln > 1 ) display("IOS version ", version, " identified as vulnerable by multiple checks\n");
