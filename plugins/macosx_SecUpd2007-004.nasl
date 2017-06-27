#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);

if (NASL_LEVEL < 3000) exit(0);


include("compat.inc");

if(description)
{
 script_id(25081);
 script_version ("$Revision: 1.21 $");
 script_cvs_date("$Date: 2016/11/28 21:06:38 $");
 
 script_cve_id("CVE-2006-0300", "CVE-2006-5867", "CVE-2006-6143", "CVE-2006-6652", "CVE-2007-0022",
               "CVE-2007-0465", "CVE-2007-0646", "CVE-2007-0724", "CVE-2007-0725", "CVE-2007-0729",
               "CVE-2007-0732", "CVE-2007-0734", "CVE-2007-0735", "CVE-2007-0736", "CVE-2007-0737",
               "CVE-2007-0738", "CVE-2007-0739", "CVE-2007-0741", "CVE-2007-0742", "CVE-2007-0743",
               "CVE-2007-0744", "CVE-2007-0746", "CVE-2007-0747", "CVE-2007-0957", "CVE-2007-1216");
 script_bugtraq_id(23569);
 script_osvdb_id(
  23371,
  31281,
  31580,
  31605,
  31781,
  32705,
  32708,
  34104,
  34105,
  34844,
  34855,
  34857,
  34858,
  34859,
  34860,
  34861,
  34862,
  34863,
  34864,
  34865,
  34866,
  34867,
  34868,
  34870,
  34871
 );

 script_name(english:"Mac OS X Multiple Vulnerabilities (Security Update 2007-004)");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a Mac OS X update that fixes a security
issue." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Mac OS X 10.4 that does not have
Security Update 2007-004 applied.

This update fixes security flaws in the following applications :

AFP Client
AirPort
CarbonCore
diskdev_cmds
fetchmail
ftpd
gnutar
Help Viewer
HID Family
Installer
Kerberos
Libinfo
Login Window
network_cmds
SMB
System Configuration
URLMount
Video Conference
WebDAV" );
 # http://web.archive.org/web/20071213053008/http://docs.info.apple.com/article.html?artnum=305391
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cf3b0926" );
 script_set_attribute(attribute:"solution", value:
"Install Security Update 2007-004 :

# http://web.archive.org/web/20070423190224/http://www.apple.com/support/downloads/securityupdate2007004universal.html
http://www.nessus.org/u?f44d0fd9" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(119, 134, 264);

 script_set_attribute(attribute:"plugin_publication_date", value: "2007/04/21");
 script_set_attribute(attribute:"vuln_publication_date", value: "2007/04/09");
 script_set_attribute(attribute:"patch_publication_date", value: "2007/04/19");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
 script_end_attributes();

 script_summary(english:"Check for the presence of Security Update 2007-004");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
 script_family(english:"MacOS X Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/MacOSX/packages");
 exit(0);
}

#

packages = get_kb_item("Host/MacOSX/packages");
if ( ! packages ) exit(0);



uname = get_kb_item("Host/uname");
if ( egrep(pattern:"Darwin.* (7\.[0-9]\.|8\.[0-9]\.)", string:uname) )
{
  if (!egrep(pattern:"^SecUpd(Srvr)?(2007-00[4-9]|200[89]-|20[1-9][0-9]-)", string:packages))
    security_hole(0);
}
