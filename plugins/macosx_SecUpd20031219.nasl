#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(12516);
 script_version ("$Revision: 1.16 $");
 script_cve_id("CVE-2003-1007", "CVE-2003-1008", "CVE-2003-1010", "CVE-2003-1011",
               "CVE-2003-1006", "CVE-2003-0962", "CVE-2003-1009", "CVE-2003-0851", "CVE-2003-0792");
 script_osvdb_id(
  2699,
  2765,
  2868,
  2898,
  3043,
  7069,
  7070,
  7097,
  7098
 );

 script_name(english:"Mac OS X Multiple Vulnerabilities (Security Update 2003-12-19)");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a Mac OS X security update." );
 script_set_attribute(attribute:"description", value:
"The remote host is missing Security Update 2003-12-19.

This security update includes the following components :

 - AFP Server
 - cd9600.util
 - Directory Services
 - fetchmail
 - fs_usage
 - rsync
 - System Initialization

For MacOS X 10.3, it also includes :

 - ASN.1 Decoding for PKI

This update contains various fixes which may allow an attacker to execute
arbitrary code on the remote host." );
 # http://web.archive.org/web/20060418210647/http://docs.info.apple.com/article.html?artnum=120291
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?44c2938e");
 script_set_attribute(attribute:"solution", value:
"Install security update 2003-12-19. For more information,
see http://support.apple.com/kb/HT1646." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
 script_set_attribute(attribute:"canvas_package", value:'CANVAS');

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/07/06");
 script_set_attribute(attribute:"vuln_publication_date", value: "2003/10/20");
 script_set_attribute(attribute:"patch_publication_date", value: "2003/12/19");
 script_cvs_date("$Date: 2016/05/20 14:12:05 $");
script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
script_end_attributes();

 script_summary(english:"Check for Security Update 2003-12-19");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
 script_family(english:"MacOS X Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/MacOSX/packages");
 exit(0);
}

#

packages = get_kb_item("Host/MacOSX/packages");
if ( ! packages ) exit(0);

uname = get_kb_item("Host/uname");

# Security Update 2004-05-03 actually includes this update for MacOS X 10.2.8 Client
if ( egrep(pattern:"Darwin.* 6\.8\.", string:uname) )
{
 if ( egrep(pattern:"^SecUpd2004-05-03", string:packages) ) exit(0);
}



# MacOS X 10.2.8 and 10.3.3 only
if ( egrep(pattern:"Darwin.* (6\.8\.|7\.[12]\.)", string:uname) )
{
  if ( ! egrep(pattern:"^SecurityUpd2003-12-19", string:packages) ) security_hole(0);
}
