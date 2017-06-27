#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(20807);
 script_version("$Revision: 1.19 $");
 script_cvs_date("$Date: 2016/08/29 13:57:36 $");

 script_cve_id("CVE-2005-3669");
 script_bugtraq_id(15401);
 script_osvdb_id(20822, 60990);

 script_name(english:"Cisco IOS IPSec IKE Traffic Remote DoS (CSCed94829)");
 script_summary(english:"Uses SNMP to determine if a flaw is present");

 script_set_attribute(attribute:"synopsis", value:
"The remote router can be crashed remotely.");
 script_set_attribute(attribute:"description", value:
"The remote host is a CISCO router containing a version of IOS which
is vulnerable to a denial of service attack.

An attacker may exploit this flaw to crash the remote device by
sending a malformed IKE packet to the remote device.");
 script_set_attribute(attribute:"solution", value:
"http://www.nessus.org/u?49cf7a82");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"plugin_publication_date", value:"2006/01/25");
 script_set_attribute(attribute:"vuln_publication_date", value:"2005/11/14");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value: "cpe:/o:cisco:ios");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");

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


if ( "SXD" >< version &&
     check_release(version:version,
		   patched:make_list("12.2(18)SXD7"),
		   newest:"12.2(18)SXD7") ) vuln ++;


#
# 12.3
#

if ( deprecated_version(version, "12.3TPC", "12.3XD", "12.3XE", "12.3XF", "12.3XG", "12.3XH", "12.3XI", "12.3XJ", "12.3XK", "12.3XM", "12.3XQ", "12.3XR", "12.3XS", "12.3XU", "12.3XW", "12.3XX", "12.3YA", "12.3YD", "12.3YF", "12.3YG", "12.3YH", "12.3YI", "12.3YJ", "12.3YK", "12.3YS", "12.3YT", "12.3YU", "12.3YX") ) vuln ++;


if ( check_release(version:version,
		   patched:make_list("12.3(11)T9", "12.3(14)T5"),
		   newest:"12.3(14)T5") ) vuln ++;

if ( check_release(version:version,
		   patched:make_list("12.3(14)YM4"),
		   newest:"12.3(14)YM4") ) vuln ++;

if ( check_release(version:version,
		   patched:make_list("12.3(14)YQ4"),
		   newest:"12.3(14)YQ4") ) vuln ++;



# 12.4
if ( deprecated_version(version, "12.3XA")) vuln ++;

if ( check_release(version:version,
		   patched:make_list("12.4(1c)", "12.4(3b)"),
		   newest:"12.4(3b)") ) vuln ++;

if ( check_release(version:version,
		   patched:make_list("12.4(2)T2"),
		   newest:"12.4(4)T2") ) vuln ++;

if ( check_release(version:version,
		   patched:make_list("12.4(2)XB"),
		   newest:"12.4(2)XB") ) vuln ++;


if ( vuln == 1 ) security_warning(port:161, proto:"udp");
else if ( vuln > 1 )  display("IOS version ", version, " identified as vulnerable by multiple checks\n");


