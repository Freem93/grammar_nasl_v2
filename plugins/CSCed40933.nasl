#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(17629);
 script_bugtraq_id(12368);
 script_osvdb_id(13193);
 script_cve_id("CVE-2005-0195");
 script_version("$Revision: 1.18 $");

 script_name(english:"Cisco IOS IPv6 Packet Processing Remote DoS (CSCed40933)");

 script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch." );
 script_set_attribute(attribute:"description", value:
"The remote version of IOS is vulnerable to a denial of service attack
when processing malformed IPv6 packets.

If IPv6 is enabled, an attacker may exploit this flaw to prevent the
router from working properly." );
 script_set_attribute(attribute:"solution", value:
"http://www.nessus.org/u?068dfdf7" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:W/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/03/25");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/01/26");
 script_cvs_date("$Date: 2014/08/11 19:44:18 $");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value: "cpe:/o:cisco:ios");
 script_end_attributes();


 summary["english"] = "Uses SNMP to determine if a flaw is present";
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2005-2014 Tenable Network Security, Inc.");

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



# 12.2 Deprecated
if ( deprecated_version(version, "12.2BX", "12.2BZ", "12.2CX", "12.2CZ", "12.2MC", "12.2SY", "12.2SZ", "12.2YT", "12.2YU", "12.2YV", "12.2YZ", "12.2ZC", "12.2ZD", "12.2ZE", "12.2ZF", "12.2ZG", "12.2ZH", "12.2ZI", "12.2ZJ", "12.2ZL", "12.2ZN", "12.2ZO", "12.2ZP" ) ) vuln ++;

# 12.3 Deprecated
if ( deprecated_version(version, "12.3BW", "12.3XA", "12.3XB", "12.3XF", "12.3XH", "12.3XN") ) vuln ++;


# 12.0S
if ( check_release(version:version,
		   patched:make_list("12.0(24)S6", "12.0(25)S3", "12.0(26)S2", "12.0(27)S1", "12.0(28)S0"),
		   newest:"12.0(28)S0",
		   oldest:"12.0(23)S0"
	          ) ) vuln++;

# 12.0SX
if ( check_release(version:version,
		   patched:make_list("12.0(25)SX8"),
		   newest:"12.0(25)SX8")) vuln ++;

# 12.0SZ
if ( check_release(version:version,
		   patched:make_list("12.0(27)SZ"),
		   newest:"12.0(27)SZ")) vuln ++;



# 12.2EW
if ( check_release(version:version,
		   patched:make_list("12.2(18)EW1"),
		   newest:"12.2(18)EW1")) vuln ++;
# 12.2EWA
if ( "EWA" >< version &&
     check_release(version:version,
		   patched:make_list("12.2(20)EWA"),
		   newest:"12.2(20)EWA")) vuln ++;

# 12.2JK
if ( check_release(version:version,
		   patched:make_list("12.2(15)JK2"),
		   newest:"12.2(15)JK2")) vuln ++;

# 12.2S
if ( check_release(version:version,
		   patched:make_list("12.2(14)S9", "12.2(18)S5", "12.2(20)S3", "12.2(22)S1", "12.2(25)S"),
		   newest:"12.2(25)S")) vuln ++;
# 12.2SE
if ( check_release(version:version,
		   patched:make_list("12.2(25)SE"),
		   newest:"12.2(25)SE")) vuln ++;
# 12.2SU
if ( check_release(version:version,
		   patched:make_list("12.2(14)SU1"),
		   newest:"12.2(14)SU1")) vuln ++;
# 12.2SV
if ( check_release(version:version,
		   patched:make_list("12.2(23)SV"),
		   newest:"12.2(23)SV")) vuln ++;
# 12.2SW
if ( check_release(version:version,
		   patched:make_list("12.2(23)SW"),
		   newest:"12.2(23)SW")) vuln ++;

# 12.2SXB
if ( "SXB" >< version &&
     check_release(version:version,
		   patched:make_list("12.2(17d)SXB1"),
		   newest:"12.2(17d)SXB1")) vuln ++;
# 12.2SXD
if ( "SXD" >< version &&
     check_release(version:version,
		   patched:make_list("12.2(18)SXD"),
		   newest:"12.2(18)SXD")) vuln ++;


# 12.2T
if ( check_release(version:version,
		   patched:make_list("12.2(15)T12", "12.2(13)T14"),
		   newest:"12.2(15)T12")) vuln ++;


# 12.3
if ( check_release(version:version,
		   patched:make_list("12.3(3f)", "12.3(5c)", "12.3(6a)", "12.3(9)"),
		   newest:"12.3(9)")) vuln ++;

# 12.3BC
if ( check_release(version:version,
		   patched:make_list("12.3(9a)BC"),
		   newest:"12.3(9a)BC")) vuln ++;

# 12.3B
if ( check_release(version:version,
		   patched:make_list("12.3(5a)B2"),
		   newest:"12.3(5a)B2")) vuln ++;

# 12.3JA
if ( check_release(version:version,
		   patched:make_list("12.3(2)JA"),
		   newest:"12.3(2)JA")) vuln ++;

# 12.3T
if ( check_release(version:version,
		   patched:make_list("12.3(2)T6", "12.3(4)T6"),
		   newest:"12.3(4)T6")) vuln ++;

# 12.3XD
if ( check_release(version:version,
		   patched:make_list("12.3(4)XD4"),
		   newest:"12.3(4)XD4")) vuln ++;

# 12.3XE
if ( check_release(version:version,
		   patched:make_list("12.3(2)XE1"),
		   newest:"12.3(2)XE1")) vuln ++;


# 12.3XG
if ( check_release(version:version,
		   patched:make_list("12.3(4)XG2"),
		   newest:"12.3(4)XG2")) vuln ++;
# 12.3XI
if ( check_release(version:version,
		   patched:make_list("12.3(7)XI"),
		   newest:"12.3(7)XI")) vuln ++;
# 12.3XJ
if ( check_release(version:version,
		   patched:make_list("12.3(7)XJ"),
		   newest:"12.3(7)XJ")) vuln ++;
# 12.3XK
if ( check_release(version:version,
		   patched:make_list("12.3(4)XK1"),
		   newest:"12.3(4)XK1")) vuln ++;
# 12.3XL
if ( check_release(version:version,
		   patched:make_list("12.3(7)XL"),
		   newest:"12.3(7)XL")) vuln ++;
# 12.3XM
if ( check_release(version:version,
		   patched:make_list("12.3(7)XM"),
		   newest:"12.3(7)XM")) vuln ++;

# 12.3XQ
if ( check_release(version:version,
		   patched:make_list("12.3(4)XQ"),
		   newest:"12.3(4)XQ")) vuln ++;
# 12.3XR
if ( check_release(version:version,
		   patched:make_list("12.3(7)XR"),
		   newest:"12.3(7)XR")) vuln ++;
# 12.3XS
if ( check_release(version:version,
		   patched:make_list("12.3(7)XS"),
		   newest:"12.3(7)XS")) vuln ++;
# 12.3XT
if ( check_release(version:version,
		   patched:make_list("12.3(2)XT"),
		   newest:"12.3(2)XT")) vuln ++;
# 12.3XU
if ( check_release(version:version,
		   patched:make_list("12.3(8)XU"),
		   newest:"12.3(8)XU")) vuln ++;
# 12.3XX
if ( check_release(version:version,
		   patched:make_list("12.3(8)XX"),
		   newest:"12.3(8)XX")) vuln ++;
# 12.3XW
if ( check_release(version:version,
		   patched:make_list("12.3(8)XW"),
		   newest:"12.3(8)XW")) vuln ++;

# 12.3XY
if ( check_release(version:version,
		   patched:make_list("12.3(8)XY"),
		   newest:"12.3(8)XY")) vuln ++;

# 12.3XZ
if ( check_release(version:version,
		   patched:make_list("12.3(2)XZ"),
		   newest:"12.3(2)XZ")) vuln ++;
# 12.3YA
if ( check_release(version:version,
		   patched:make_list("12.3(8)YA"),
		   newest:"12.3(8)YA")) vuln ++;
# 12.3YD
if ( check_release(version:version,
		   patched:make_list("12.3(8)YD"),
		   newest:"12.3(8)YD")) vuln ++;
# 12.3YE
if ( check_release(version:version,
		   patched:make_list("12.3(4)YE"),
		   newest:"12.3(4)YE")) vuln ++;
# 12.3YF
if ( check_release(version:version,
		   patched:make_list("12.3(11)YF"),
		   newest:"12.3(11)YF")) vuln ++;
# 12.3YG
if ( check_release(version:version,
		   patched:make_list("12.3(8)YH"),
		   newest:"12.3(8)YH")) vuln ++;
# 12.3YH
if ( check_release(version:version,
		   patched:make_list("12.3(8)YH"),
		   newest:"12.3(8)YH")) vuln ++;


if ( vuln == 1 ) security_warning(port:161, proto:"udp");
else if ( vuln > 1 ) display("IOS version ", version, " identified as vulnerable by multiple checks\n");
