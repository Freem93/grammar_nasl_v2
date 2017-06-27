#
# (C) Tenable Network Security, Inc.
#

# URLs dead
#"macosx_SecUpd20040503.nasl"
#http://www.apple.com/downloads/macosx/apple/securityupdate__2004-05-24_(10_3_3).html
#http://www.apple.com/downloads/macosx/apple/securityupdate_2004-05-24_(10_2_8).html

if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(12519);
 script_version ("$Revision: 1.12 $");
 script_cve_id("CVE-2004-0485", "CVE-2004-0486");
 script_osvdb_id(6184, 6536);

 script_name(english:"Mac OS X Multiple Vulnerabilities (Security Update 2004-05-24)");
 script_summary(english:"Check for Security Update 2004-05-24");
 
 script_set_attribute(
   attribute:"synopsis",
   value:
"The remote host is missing a Mac OS X update that fixes a security
issue." );
 script_set_attribute(
   attribute:"description", 
   value:
"The remote host is missing Security Update 2004-05-24.  This security
update includes fixes for the following components :

  HelpViewer
  Terminal

This update fixes security issues that could allow an attacker to
execute arbitrary commands on the remote host by exploiting a flaw
in Safari and the components listed above.  A remote attacker could
exploit this flaw by tricking a user into visiting a malicious website." );
 # http://web.archive.org/web/20080915104713/http://support.apple.com/kb/HT1646?
 script_set_attribute(
   attribute:"see_also",
   value:"http://www.nessus.org/u?210abeb5"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Install Security Update 2004-05-24."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/07/06");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/05/14");
 script_set_attribute(attribute:"patch_publication_date", value: "2004/05/21");
 script_cvs_date("$Date: 2013/03/05 23:04:26 $");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"MacOS X Local Security Checks");

 script_copyright(english:"This script is Copyright (C) 2004-2013 Tenable Network Security, Inc.");

 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/MacOSX/packages");
 exit(0);
}


packages = get_kb_item("Host/MacOSX/packages");
if ( ! packages ) exit(0);

uname = get_kb_item("Host/uname");
# MacOS X 10.2.8 and 10.3.3 only
if ( egrep(pattern:"Darwin.* (6\.8\.|7\.3\.)", string:uname) )
{
  if ( ! egrep(pattern:"^SecUpd2004-05-24", string:packages) ) security_warning(0);
}
