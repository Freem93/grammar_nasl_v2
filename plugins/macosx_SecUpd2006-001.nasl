#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(20990);
 script_version("$Revision: 1.22 $");
 script_cvs_date("$Date: 2015/01/26 14:44:46 $");

 script_cve_id("CVE-2005-2713", "CVE-2005-2714", "CVE-2005-3319", "CVE-2005-3353", "CVE-2005-3391",
               "CVE-2005-3392", "CVE-2005-3706", "CVE-2005-3712", "CVE-2005-4217", "CVE-2005-4504",
               "CVE-2006-0383", "CVE-2006-0384", "CVE-2006-0386", "CVE-2006-0387", "CVE-2006-0388",
               "CVE-2006-0389", "CVE-2006-0391", "CVE-2006-0395", "CVE-2006-0848");
 script_bugtraq_id(16736, 16907);
 script_osvdb_id(
  20491,
  20897,
  20898,
  21492,
  21800,
  22037,
  23510,
  23636,
  23637,
  23638,
  23640,
  23641,
  23642,
  23643,
  23644,
  23645,
  23646,
  23647,
  23648,
  23649
 );

 script_name(english:"Mac OS X Multiple Vulnerabilities (Security Update 2006-001)");
 script_summary(english:"Check for Security Update 2006-001");

 script_set_attribute(attribute:"synopsis", value:"The remote operating system is missing a vendor-supplied patch.");
 script_set_attribute(attribute:"description", value:
"The remote host is running Apple Mac OS X, but lacks
Security Update 2006-001.

This security update contains fixes for the following
applications :

apache_mod_php
automount
Bom
Directory Services
iChat
IPSec
LaunchServices
LibSystem
loginwindow
Mail
rsync
Safari
Syndication");
 script_set_attribute(attribute:"see_also", value:"http://docs.info.apple.com/article.html?artnum=303382");
 script_set_attribute(attribute:"solution", value:
"Mac OS X 10.4 :
http://www.apple.com/support/downloads/securityupdate2006001macosx1045ppc.html
http://www.apple.com/support/downloads/securityupdate2006001macosx1045intel.html

Mac OS X 10.3 :
http://www.apple.com/support/downloads/securityupdate20060011039client.html
http://www.apple.com/support/downloads/securityupdate20060011039server.html");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'Safari Archive Metadata Command Execution');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2005/12/21");
 script_set_attribute(attribute:"patch_publication_date", value:"2006/03/03");
 script_set_attribute(attribute:"plugin_publication_date", value:"2006/03/02");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");
 script_family(english:"MacOS X Local Security Checks");

 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/MacOSX/packages");
 exit(0);
}


packages = get_kb_item("Host/MacOSX/packages");
if ( ! packages ) exit(0);


uname = get_kb_item("Host/uname");
if ( egrep(pattern:"Darwin.* (7\.[0-9]\.|8\.[0-5]\.)", string:uname) )
{
  if (!egrep(pattern:"^SecUpd(Srvr)?(2006-00[123467]|2007-003)", string:packages)) security_hole(0);
}
