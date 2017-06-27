#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Slackware Security Advisory 2016-242-01. The text 
# itself is copyright (C) Slackware Linux, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93198);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2016/08/30 13:55:14 $");

  script_cve_id("CVE-2016-5389");
  script_xref(name:"SSA", value:"2016-242-01");

  script_name(english:"Slackware 14.1 : kernel (SSA:2016-242-01)");
  script_summary(english:"Checks for updated packages in /var/log/packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Slackware host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"New kernel packages are available for Slackware 14.1 to fix a
security issue."
  );
  # http://www.slackware.com/security/viewer.php?l=slackware-security&y=2016&m=slackware-security.650340
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4e9b6c9a"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:kernel-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:kernel-generic-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:kernel-huge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:kernel-huge-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:kernel-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:kernel-modules-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:kernel-source");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:14.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (slackware_check(osver:"14.1", pkgname:"kernel-generic", pkgver:"3.10.103", pkgarch:"i486", pkgnum:"1")) flag++;
if (slackware_check(osver:"14.1", pkgname:"kernel-generic-smp", pkgver:"3.10.103_smp", pkgarch:"i686", pkgnum:"1")) flag++;
if (slackware_check(osver:"14.1", pkgname:"kernel-headers", pkgver:"3.10.103_smp", pkgarch:"x86", pkgnum:"1")) flag++;
if (slackware_check(osver:"14.1", pkgname:"kernel-huge", pkgver:"3.10.103", pkgarch:"i486", pkgnum:"1")) flag++;
if (slackware_check(osver:"14.1", pkgname:"kernel-huge-smp", pkgver:"3.10.103_smp", pkgarch:"i686", pkgnum:"1")) flag++;
if (slackware_check(osver:"14.1", pkgname:"kernel-modules", pkgver:"3.10.103", pkgarch:"i486", pkgnum:"1")) flag++;
if (slackware_check(osver:"14.1", pkgname:"kernel-modules-smp", pkgver:"3.10.103_smp", pkgarch:"i686", pkgnum:"1")) flag++;
if (slackware_check(osver:"14.1", pkgname:"kernel-source", pkgver:"3.10.103_smp", pkgarch:"noarch", pkgnum:"1")) flag++;
if (slackware_check(osver:"14.1", arch:"x86_64", pkgname:"kernel-generic", pkgver:"3.10.103", pkgarch:"x86_64", pkgnum:"1")) flag++;
if (slackware_check(osver:"14.1", arch:"x86_64", pkgname:"kernel-headers", pkgver:"3.10.103", pkgarch:"x86", pkgnum:"1")) flag++;
if (slackware_check(osver:"14.1", arch:"x86_64", pkgname:"kernel-huge", pkgver:"3.10.103", pkgarch:"x86_64", pkgnum:"1")) flag++;
if (slackware_check(osver:"14.1", arch:"x86_64", pkgname:"kernel-modules", pkgver:"3.10.103", pkgarch:"x86_64", pkgnum:"1")) flag++;
if (slackware_check(osver:"14.1", arch:"x86_64", pkgname:"kernel-source", pkgver:"3.10.103", pkgarch:"noarch", pkgnum:"1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:slackware_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
