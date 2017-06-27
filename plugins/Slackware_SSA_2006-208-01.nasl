#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Slackware Security Advisory 2006-208-01. The text 
# itself is copyright (C) Slackware Linux, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22102);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2014/08/21 14:15:31 $");

  script_xref(name:"SSA", value:"2006-208-01");

  script_name(english:"Slackware 10.2 / current : firefox/thunderbird/seamonkey (SSA:2006-208-01)");
  script_summary(english:"Checks for updated packages in /var/log/packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Slackware host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"New Firefox and Thunderbird packages are available for Slackware 10.2
and -current to fix security issues. In addition, a new SeaMonkey
package is available for Slackware -current to fix similar issues."
  );
  # http://www.mozilla.org/projects/security/known-vulnerabilities.html#firefox
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3462ca90"
  );
  # http://www.mozilla.org/projects/security/known-vulnerabilities.html#seamonkey
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?637d935f"
  );
  # http://www.mozilla.org/projects/security/known-vulnerabilities.html#thunderbird
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f7275234"
  );
  # http://www.slackware.com/security/viewer.php?l=slackware-security&y=2006&m=slackware-security.479461
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a238dd2f"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected mozilla-firefox, mozilla-thunderbird and / or
seamonkey packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:mozilla-firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:mozilla-thunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:seamonkey");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:10.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/07/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2014 Tenable Network Security, Inc.");
  script_family(english:"Slackware Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Slackware/release", "Host/Slackware/packages");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("slackware.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Slackware/release")) audit(AUDIT_OS_NOT, "Slackware");
if (!get_kb_item("Host/Slackware/packages")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Slackware", cpu);


flag = 0;
if (slackware_check(osver:"10.2", pkgname:"mozilla-firefox", pkgver:"1.5.0.5", pkgarch:"i686", pkgnum:"1")) flag++;
if (slackware_check(osver:"10.2", pkgname:"mozilla-thunderbird", pkgver:"1.5.0.5", pkgarch:"i686", pkgnum:"1")) flag++;

if (slackware_check(osver:"current", pkgname:"mozilla-firefox", pkgver:"1.5.0.5", pkgarch:"i686", pkgnum:"1")) flag++;
if (slackware_check(osver:"current", pkgname:"mozilla-thunderbird", pkgver:"1.5.0.5", pkgarch:"i686", pkgnum:"1")) flag++;
if (slackware_check(osver:"current", pkgname:"seamonkey", pkgver:"1.0.3", pkgarch:"i486", pkgnum:"1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:slackware_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
