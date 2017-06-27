#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(20249);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2014/05/21 16:54:05 $");

  script_cve_id("CVE-2005-1993", "CVE-2005-2088", "CVE-2005-2272", "CVE-2005-2491", "CVE-2005-2700",
                "CVE-2005-2757", "CVE-2005-2969", "CVE-2005-3185", "CVE-2005-3700", "CVE-2005-3701",
                "CVE-2005-3702", "CVE-2005-3704", "CVE-2005-3705");
  script_bugtraq_id(13993, 14011, 14106, 14620, 14721, 15071, 15102, 16882, 16903, 16904, 16926, 29011);
  script_osvdb_id(
    17396,
    17397,
    17738,
    18906,
    19188,
    19919,
    20011,
    20012,
    21271,
    21272,
    21273,
    21274,
    21275,
    21276,
    21277,
    79193
  );

  script_name(english:"Mac OS X Multiple Vulnerabilities (Security Update 2005-009)");
  script_summary(english:"Check for Security Update 2005-009");

  script_set_attribute(attribute:"synopsis", value:"The remote operating system is missing a vendor-supplied patch.");
  script_set_attribute(attribute:"description", value:
"The remote host is running Apple Mac OS X, but lacks
Security Update 2005-009.

This security update contains fixes for the following
applications :

- Apache2
- Apache_mod_ssl
- CoreFoundation
- curl
- iodbcadmintool
- OpenSSL
- passwordserver
- Safari
- sudo
- syslog");
  script_set_attribute(attribute:"see_also", value:"http://docs.info.apple.com/article.html?artnum=302847");
  script_set_attribute(attribute:"solution", value:
"Mac OS X 10.4 :
http://www.apple.com/support/downloads/securityupdate2005009tigerclient.html
http://www.apple.com/support/downloads/securityupdate2005009tigerserver.html

Mac OS X 10.3 :
http://www.apple.com/support/downloads/securityupdate2005009pantherclient.html
http://www.apple.com/support/downloads/securityupdate2005009pantherserver.html");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/06/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/06/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/11/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2014 Tenable Network Security, Inc.");
  script_family(english:"MacOS X Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/MacOSX/packages");
  exit(0);
}


packages = get_kb_item("Host/MacOSX/packages");
if ( ! packages ) exit(0);


uname = get_kb_item("Host/uname");
if ( egrep(pattern:"Darwin.* (7\.[0-9]\.|8\.[0-3]\.)", string:uname) )
{
  if (!egrep(pattern:"^SecUpd(Srvr)?(2005-009|2006-00[123467]|2007-003)", string:packages)) security_hole(0);
}
