#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);
if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if(description)
{
 script_id(14676);
 script_version ("$Revision: 1.23 $");

  script_cve_id("CVE-2004-0175", "CVE-2004-0183", "CVE-2004-0184", "CVE-2004-0361", "CVE-2004-0426", 
                "CVE-2004-0488", "CVE-2004-0493", "CVE-2004-0521", "CVE-2004-0523", "CVE-2004-0607",
                "CVE-2004-0720", "CVE-2004-0794", "CVE-2004-0821", "CVE-2004-0822", "CVE-2004-0823",
                "CVE-2004-0824", "CVE-2004-0825");
  script_bugtraq_id(9815, 9986, 10003, 10004, 10247, 10397, 11135, 11136, 11137, 11138, 11139, 11140);
  script_osvdb_id(
   4158,
   4750,
   4751,
   5731,
   6472,
   6841,
   6846,
   7113,
   7114,
   7269,
   7296,
   8232,
   8993,
   9550,
   9737,
   9738,
   9757,
   9758,
   9759,
   9760,
   9784,
   59837
  );

 script_name(english:"Mac OS X Multiple Vulnerabilities (Security Update 2004-09-07)");
 script_summary(english:"Check for Security Update 2004-09-07");
 
 script_set_attribute( attribute:"synopsis", value:
"The remote host is missing a Mac OS X update that fixes a security
issue." );
 script_set_attribute( attribute:"description",  value:
"The remote host is missing Security Update 2004-09-07.  This security
update fixes the following components :

  - CoreFoundation
  - IPSec
  - Kerberos
  - libpcap
  - lukemftpd
  - NetworkConfig
  - OpenLDAP
  - OpenSSH
  - PPPDialer
  - rsync
  - Safari
  - tcpdump

These applications contain multiple vulnerabilities that may allow
a remote attacker to execute arbitrary code." );
 # http://web.archive.org/web/20080915104713/http://support.apple.com/kb/HT1646?
 script_set_attribute(
   attribute:"see_also",
   value:"http://www.nessus.org/u?210abeb5"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Install Security Update 2004-09-07."
 );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(22);
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/09/08");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/03/08");
 script_set_attribute(attribute:"patch_publication_date", value: "2004/09/08");
 script_cvs_date("$Date: 2016/05/17 16:53:09 $");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"MacOS X Local Security Checks");

 script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");

 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/MacOSX/packages");
 exit(0);
}


packages = get_kb_item("Host/MacOSX/packages");
if ( ! packages ) exit(0);

uname = get_kb_item("Host/uname");
# MacOS X 10.2.8, 10.3.4 and 10.3.5 only
if ( egrep(pattern:"Darwin.* (6\.8\.|7\.[45]\.)", string:uname) )
{
  if ( ! egrep(pattern:"^SecUpd(Srvr)?2004-09-07", string:packages) ) security_hole(0);
}
