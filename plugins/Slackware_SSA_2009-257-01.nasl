#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Slackware Security Advisory 2009-257-01. The text 
# itself is copyright (C) Slackware Linux, Inc.
#

include("compat.inc");

if (description)
{
  script_id(40977);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2013/06/01 00:40:51 $");

  script_osvdb_id(57970, 57971, 57972, 57973, 57974, 57975, 57976, 57977, 57978, 57979, 57980);
  script_xref(name:"SSA", value:"2009-257-01");

  script_name(english:"Slackware 12.2 / 13.0 / current : mozilla-firefox (SSA:2009-257-01)");
  script_summary(english:"Checks for updated package in /var/log/packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Slackware host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"New mozilla-firefox packages are available for Slackware 12.2, 13.0,
and -current to fix security issues. The Firefox 3.0.14 package may
also be used with Slackware 11.0 or newer."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/known-vulnerabilities/firefox30.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/known-vulnerabilities/firefox35.html"
  );
  # http://www.slackware.com/security/viewer.php?l=slackware-security&y=2009&m=slackware-security.419366
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?51d64591"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mozilla-firefox package."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:mozilla-firefox");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:12.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:13.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/09/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/09/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2013 Tenable Network Security, Inc.");
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
if (slackware_check(osver:"12.2", pkgname:"mozilla-firefox", pkgver:"3.0.14", pkgarch:"i686", pkgnum:"1")) flag++;

if (slackware_check(osver:"13.0", pkgname:"mozilla-firefox", pkgver:"3.5.3", pkgarch:"i686", pkgnum:"1")) flag++;
if (slackware_check(osver:"13.0", arch:"x86_64", pkgname:"mozilla-firefox", pkgver:"3.5.3", pkgarch:"x86_64", pkgnum:"1")) flag++;

if (slackware_check(osver:"current", pkgname:"mozilla-firefox", pkgver:"3.5.3", pkgarch:"i686", pkgnum:"1")) flag++;
if (slackware_check(osver:"current", arch:"x86_64", pkgname:"mozilla-firefox", pkgver:"3.5.3", pkgarch:"x86_64", pkgnum:"1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:slackware_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
