#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(19773);
 script_version("$Revision: 1.18 $");
 script_cvs_date("$Date: 2016/11/28 21:06:38 $");

  script_cve_id("CVE-2005-1992", "CVE-2005-2524", "CVE-2005-2741", "CVE-2005-2742", "CVE-2005-2743",
                "CVE-2005-2744", "CVE-2005-2745", "CVE-2005-2746", "CVE-2005-2747", "CVE-2005-2748");
 script_bugtraq_id(14914, 14939);
 script_osvdb_id(
  17407,
  19703,
  19704,
  19705,
  19706,
  19707,
  19708,
  19709,
  19710,
  19711
 );

 script_name(english:"Mac OS X Multiple Vulnerabilities (Security Update 2005-008)");
 script_summary(english:"Check for Security Update 2005-008");

 script_set_attribute(attribute:"synopsis", value:"The remote operating system is missing a vendor-supplied patch.");
 script_set_attribute(attribute:"description", value:
"The remote host is running Apple Mac OS X, but lacks
Security Update 2005-008.

This security update contains fixes for the following
applications :

- ImageIO
- LibSystem
- Mail
- QuickDraw
- Ruby
- SecurityAgent
- securityd");
 # http://web.archive.org/web/20060419122213/http://docs.info.apple.com/article.html?artnum=302413
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b7db6d8b");
 script_set_attribute(attribute:"solution", value:
"Mac OS X 10.4 :
http://support.apple.com/downloads/Security_Update_2005_008__Mac_OS_X_10_4_2_

Mac OS X 10.3 :
http://support.apple.com/downloads/Security_Update_2005_008__Mac_OS_X_10_3_9_");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2005/06/22");
 script_set_attribute(attribute:"patch_publication_date", value:"2005/06/22");
 script_set_attribute(attribute:"plugin_publication_date", value:"2005/09/23");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
 script_family(english:"MacOS X Local Security Checks");

 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/MacOSX/packages");
 exit(0);
}


packages = get_kb_item("Host/MacOSX/packages");
if ( ! packages ) exit(0);


uname = get_kb_item("Host/uname");
if ( egrep(pattern:"Darwin.* (7\.[0-9]\.|8\.2\.)", string:uname) )
{
  if (!egrep(pattern:"^SecUpd(Srvr)?(2005-008|2006-00[123467]|2007-003)", string:packages)) security_hole(0);
}
