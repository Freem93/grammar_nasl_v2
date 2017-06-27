#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Slackware Security Advisory 2008-043-01. The text 
# itself is copyright (C) Slackware Linux, Inc.
#

include("compat.inc");

if (description)
{
  script_id(31053);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2013/06/01 00:40:50 $");

  script_xref(name:"SSA", value:"2008-043-01");

  script_name(english:"Slackware 10.2 / 11.0 / 12.0 / current : firefox, seamonkey (SSA:2008-043-01)");
  script_summary(english:"Checks for updated packages in /var/log/packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Slackware host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"New mozilla-firefox packages are available for Slackware 10.2, 11.0,
12.0, and -current to fix security issues. New seamonkey updates are
available for Slackware 11.0, 12.0, and -current to address similar
issues."
  );
  # http://www.slackware.com/security/viewer.php?l=slackware-security&y=2008&m=slackware-security.453296
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c0b5ea5d"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mozilla-firefox and / or seamonkey packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:mozilla-firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:seamonkey");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:10.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:11.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:12.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/02/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/02/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2013 Tenable Network Security, Inc.");
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
if (slackware_check(osver:"10.2", pkgname:"mozilla-firefox", pkgver:"2.0.0.12", pkgarch:"i686", pkgnum:"1")) flag++;

if (slackware_check(osver:"11.0", pkgname:"mozilla-firefox", pkgver:"2.0.0.12", pkgarch:"i686", pkgnum:"1")) flag++;
if (slackware_check(osver:"11.0", pkgname:"seamonkey", pkgver:"1.1.8", pkgarch:"i486", pkgnum:"1_slack11.0")) flag++;

if (slackware_check(osver:"12.0", pkgname:"mozilla-firefox", pkgver:"2.0.0.12", pkgarch:"i686", pkgnum:"1")) flag++;
if (slackware_check(osver:"12.0", pkgname:"seamonkey", pkgver:"1.1.8", pkgarch:"i486", pkgnum:"1_slack12")) flag++;

if (slackware_check(osver:"current", pkgname:"mozilla-firefox", pkgver:"2.0.0.12", pkgarch:"i686", pkgnum:"1")) flag++;
if (slackware_check(osver:"current", pkgname:"seamonkey", pkgver:"1.1.8", pkgarch:"i486", pkgnum:"1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:slackware_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
