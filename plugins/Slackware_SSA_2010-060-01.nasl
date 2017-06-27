# This script was automatically generated from Slackware security
# advisory SSA-2010-060-01. It is released under the Nessus Script Licence.
#
# Slackware Security Advisories are Copyright (C) 1999-2011 Slackware
# Linux, Inc. See http://www.slackware.com/about/ or 
# http://www.slackware.com/security/. Slackware(R) is a registered trademark 
# of Slackware Linux, Inc.

if (!defined_func("bn_random")) exit(0);
include("compat.inc");

if (description)
{
  script_id(50435);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2011/07/28 01:59:07 $");

  script_xref(name:"SSA", value:"2010-060-01");

  script_name(english:"SSA-2010-060-01 : seamonkey");
  script_summary(english:"Checks for updated package(s) in /var/log/packages");

  script_set_attribute(attribute:"synopsis", value: 
"The remote Slackware host is missing one or more security-related
patches.");
  script_set_attribute(attribute:"description", value:
'New seamonkey packages are available for Slackware 12.2, 13.0, and
-current to fix security issues.');
  script_set_attribute(attribute:"see_also", value:
"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2010&m=slackware-security.473276");
  script_set_attribute(attribute:"see_also", value:
"http://www.mozilla.org/security/known-vulnerabilities/seamonkey20.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected package(s).");
  script_set_attribute(attribute:"risk_factor", value:"High");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/03/01");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux");
  script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"plugin_publication_date", value: "2010/11/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Slackware Local Security Checks");

  script_copyright("This script is Copyright (C) 2010-2011 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Slackware/release", "Host/Slackware/packages");

  exit(0);
}

include("slackware.inc");
include("global_settings.inc");

if (!get_kb_item("Host/Slackware/packages")) exit(0, "Could not obtain the list of packages.");

flag = 0;

if (slackware_check(osver:"12.2", pkgname:"seamonkey", pkgver:"2.0.3", pkgnum:"1", pkgarch:"i486")) flag++;
if (slackware_check(osver:"13.0", pkgname:"seamonkey", pkgver:"2.0.3", pkgnum:"1", pkgarch:"i486")) flag++;
if (slackware_check(osver:"13.0", pkgname:"seamonkey-solibs", pkgver:"2.0.3", pkgnum:"1", pkgarch:"i486")) flag++;
if (slackware_check(osver:"13.0", pkgname:"seamonkey", pkgver:"2.0.3", pkgnum:"1", pkgarch:"x86_64")) flag++;
if (slackware_check(osver:"13.0", pkgname:"seamonkey-solibs", pkgver:"2.0.3", pkgnum:"1", pkgarch:"x86_64")) flag++;
if (slackware_check(osver:"current", pkgname:"seamonkey-solibs", pkgver:"2.0.3", pkgnum:"1", pkgarch:"i486")) flag++;
if (slackware_check(osver:"current", pkgname:"seamonkey", pkgver:"2.0.3", pkgnum:"1", pkgarch:"i486")) flag++;
if (slackware_check(osver:"current", pkgname:"seamonkey-solibs", pkgver:"2.0.3", pkgnum:"1", pkgarch:"x86_64")) flag++;
if (slackware_check(osver:"current", pkgname:"seamonkey", pkgver:"2.0.3", pkgnum:"1", pkgarch:"x86_64")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:slackware_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
