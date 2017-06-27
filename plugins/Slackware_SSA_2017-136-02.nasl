#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Slackware Security Advisory 2017-136-02. The text 
# itself is copyright (C) Slackware Linux, Inc.
#

include("compat.inc");

if (description)
{
  script_id(100224);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/05/17 14:19:07 $");

  script_xref(name:"SSA", value:"2017-136-02");

  script_name(english:"Slackware 13.37 / 14.0 / 14.1 / 14.2 / current : kdelibs (SSA:2017-136-02)");
  script_summary(english:"Checks for updated package in /var/log/packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Slackware host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"New kdelibs packages are available for Slackware 13.37, 14.0, 14.1,
14.2, and -current to fix a security issue."
  );
  # http://www.slackware.com/security/viewer.php?l=slackware-security&y=2017&m=slackware-security.474306
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?16e0d7c3"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kdelibs package."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:kdelibs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:13.37");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:14.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:14.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:14.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (slackware_check(osver:"13.37", pkgname:"kdelibs", pkgver:"4.5.5", pkgarch:"i486", pkgnum:"3_slack13.37")) flag++;
if (slackware_check(osver:"13.37", arch:"x86_64", pkgname:"kdelibs", pkgver:"4.5.5", pkgarch:"x86_64", pkgnum:"3_slack13.37")) flag++;

if (slackware_check(osver:"14.0", pkgname:"kdelibs", pkgver:"4.8.5", pkgarch:"i486", pkgnum:"2_slack14.0")) flag++;
if (slackware_check(osver:"14.0", arch:"x86_64", pkgname:"kdelibs", pkgver:"4.8.5", pkgarch:"x86_64", pkgnum:"2_slack14.0")) flag++;

if (slackware_check(osver:"14.1", pkgname:"kdelibs", pkgver:"4.10.5", pkgarch:"i486", pkgnum:"3_slack14.1")) flag++;
if (slackware_check(osver:"14.1", arch:"x86_64", pkgname:"kdelibs", pkgver:"4.10.5", pkgarch:"x86_64", pkgnum:"3_slack14.1")) flag++;

if (slackware_check(osver:"14.2", pkgname:"kdelibs", pkgver:"4.14.32", pkgarch:"i586", pkgnum:"1_slack14.2")) flag++;
if (slackware_check(osver:"14.2", arch:"x86_64", pkgname:"kdelibs", pkgver:"4.14.32", pkgarch:"x86_64", pkgnum:"1_slack14.2")) flag++;

if (slackware_check(osver:"current", pkgname:"kdelibs", pkgver:"4.14.32", pkgarch:"i586", pkgnum:"1")) flag++;
if (slackware_check(osver:"current", arch:"x86_64", pkgname:"kdelibs", pkgver:"4.14.32", pkgarch:"x86_64", pkgnum:"1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:slackware_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
