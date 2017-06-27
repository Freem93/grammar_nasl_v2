#
# (C) Tenable Network Security, Inc.
#

# These vulnerabilities are documented as Cisco bug ID CSCec17308/CSCec19124(tftp), 
# CSCec17406(port 1080), and CSCec66884/CSCec71157(SU access).


include("compat.inc");


if(description)
{
 script_id(16202);
 script_version("$Revision: 1.18 $");

 script_cve_id(
   "CVE-2002-0952", 
   "CVE-2002-1553", 
   "CVE-2002-1554", 
   "CVE-2002-1555", 
   "CVE-2002-1556", 
   "CVE-2002-1557",
   "CVE-2002-1558", 
   "CVE-2004-0306",
   "CVE-2004-0307",
   "CVE-2004-0308"
 );
 script_bugtraq_id(
   5058, 
   6073, 
   6076, 
   6078, 
   6081, 
   6082, 
   6083, 
   6084, 
   9699
 );
 script_osvdb_id(
  4008,
  4009,
  4010,
  5045,
  8879,
  8924,
  8925,
  8926,
  8927,
  8939
 );

 script_name(english:"Cisco ONS Multiple Remote Vulnerabilities (20040219-ONS)");
 script_summary(english:"Uses SNMP to determine if a flaw is present");

 script_set_attribute(
   attribute:"synopsis",
   value:"The remote Cisco device has multiple vulnerabilites."
 );
 script_set_attribute( attribute:"description", value:
"According to its version number, the remote Cisco ONS platform has
the following vulnerabilities :

  - The TFTP server allows unauthenticated access to TFTP
    GET and PUT commands. An attacker may exploit this flaw
    to upload or retrieve the system files of the remote
    ONS platform.

  - A denial of service attack may occur through the network
    management port of the remote device (1080/tcp).

  - Superuser accounts cannot be disabled over telnet." );
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20040219-ONS 
 script_set_attribute(
   attribute:"see_also",
   value:"http://www.nessus.org/u?d35df68b"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Apply the fixes referenced in Cisco's advisory."
 );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:W/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/01/18");
 script_set_attribute(attribute:"vuln_publication_date", value: "2002/10/31");
 script_set_attribute(attribute:"patch_publication_date", value: "2004/02/19");
 script_cvs_date("$Date: 2013/03/25 22:24:39 $");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe",value:"cpe:/o:cisco:ons");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"CISCO");

 script_copyright(english:"This script is (C) 2005-2013 Tenable Network Security, Inc.");

 script_dependencie("snmp_sysDesc.nasl");
 script_require_keys("SNMP/sysDesc");

 exit(0);
}

port = 0;

sysDesc = get_kb_item("SNMP/sysDesc"); 
if ( ! sysDesc ) exit(0);

if ("Cisco ONS" >!< sysDesc ) exit(0);

if ( egrep(pattern:"Cisco ONS 15327.*", string:sysDesc) ) 
{
 version = chomp(ereg_replace(pattern:".*Cisco ONS 15327.* ([0-9.]*)-.*", string:sysDesc, replace:"\1"));
 int_version = eregmatch(pattern:"^([0-9]+)\.([0-9])([0-9])$", string:version);
 if ( int(int_version[1]) == 4 && int(int_version[2]) == 0 && int(int_version[3]) <= 2) security_hole(port);
 else if ( int(int_version[1]) == 4 && int(int_version[2]) == 1 && int(int_version[3]) <= 2) security_hole(port);
}
else if ( egrep(pattern:"Cisco ONS 15454.*", string:sysDesc) ) 
{
 version = chomp(ereg_replace(pattern:".*Cisco ONS 15454.* ([0-9.]*)-.*", string:sysDesc, replace:"\1"));
 int_version = eregmatch(pattern:"^([0-9]+)\.([0-9])([0-9])$", string:version);
 if ( int(int_version[1]) == 4 && int(int_version[2]) == 0 && int(int_version[3]) <= 2) security_hole(port);
 else if ( int(int_version[1]) == 4 && int(int_version[2]) == 1 && int(int_version[3]) <= 2) security_hole(port);
 else if ( int(int_version[1]) == 4 && int(int_version[2]) == 5 ) security_hole(port);
}
else if ( egrep(pattern:"Cisco ONS 15600.*", string:sysDesc) ) 
{
 version = chomp(ereg_replace(pattern:".*Cisco ONS 15600.* ([0-9.]*)-.*", string:sysDesc, replace:"\1"));
 int_version = eregmatch(pattern:"^([0-9]+)\.([0-9])([0-9])$", string:version);
 if ( int(int_version[1]) <= 1 ) security_hole(port);
}
