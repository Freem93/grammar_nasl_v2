#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);


include("compat.inc");

if(description)
{
 script_id(12517);
 script_version ("$Revision: 1.15 $");
 script_cvs_date("$Date: 2013/03/04 23:24:26 $");

 script_cve_id("CVE-2004-0085", "CVE-2004-0086", "CVE-2004-0087", "CVE-2004-0088", "CVE-2004-0089",
               "CVE-2003-0789", "CVE-2003-0542", "CVE-2004-0092", "CVE-2003-0542");
 script_bugtraq_id(9069);
 script_osvdb_id(
  2733,
  6816,
  6817,
  6818,
  6819,
  6820,
  6821,
  7611,
  15889
 );

 script_name(english:"Mac OS X Multiple Vulnerabilities (Security Update 2004-01-26)");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a Mac OS X security update." );
 script_set_attribute(attribute:"description", value:
"The remote host is missing Security Update 2004-01-26.

This security update includes the following components :

 - Apache 1.3
 - Classic
 - Mail
 - Safari
 - Windows File Sharing

For MacOS 10.1.5, it only includes the following :

 - Mail

This update contains various fixes which may allow an attacker to execute
arbitrary code on the remote host." );
 # http://web.archive.org/web/20040206220131/http://www.apple.com/downloads/macosx/apple/securityupdate_2004-01-26_%2810_2_8_Server%29.html
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f54f1ccf" );
 # http://web.archive.org/web/20040206214559/http://www.apple.com/downloads/macosx/apple/securityupdate_2004-01-26_%2810_1_5%29.html
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1a627a5f" );
 script_set_attribute(attribute:"solution", value:
"Install security update 2004-01-26. See 
http://support.apple.com/kb/HT1646 for more details." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:W/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(119);

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/07/06");
 script_set_attribute(attribute:"vuln_publication_date", value: "2003/10/29");
 script_set_attribute(attribute:"patch_publication_date", value: "2004/01/26");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
 script_end_attributes();

 script_summary(english:"Check for Security Update 2004-01-26");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2013 Tenable Network Security, Inc.");
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

# MacOS X 10.1.5, 10.2.8 and 10.3.2 only
if ( egrep(pattern:"Darwin.* (5\.5\.|6\.8\.|7\.2\.)", string:uname) )
{
  if ( ! egrep(pattern:"^SecurityUpd2004-01-26", string:packages) ) { 
		security_hole(0);
		exit(0);
		}
 else  {
        set_kb_item(name:"CVE-2004-0174", value:TRUE);
        set_kb_item(name:"CVE-2003-0020", value:TRUE);
        }
}

if ( egrep(pattern:"Darwin.*", string:uname) )
{
        set_kb_item(name:"CVE-2004-0174", value:TRUE);
        set_kb_item(name:"CVE-2003-0020", value:TRUE);
}
