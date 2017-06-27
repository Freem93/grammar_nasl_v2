#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Slackware Security Advisory 2009-342-01. The text 
# itself is copyright (C) Slackware Linux, Inc.
#

include("compat.inc");

if (description)
{
  script_id(54875);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2013/06/01 00:40:51 $");

  script_cve_id("CVE-2009-1298");
  script_xref(name:"SSA", value:"2009-342-01");

  script_name(english:"Slackware current : kernel (SSA:2009-342-01)");
  script_summary(english:"Checks for updated packages in /var/log/packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Slackware host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"New Linux kernel packages are available for Slackware 13.0 and
-current to address a security issue. A kernel bug discovered by David
Ford may allow remote attackers to crash the kernel by sending an
oversized IP packet. While the impact on ordinary servers is still
unclear (the problem was noticed while running openvasd), we are
issuing these kernel packages as a preemptive measure."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lkml.org/lkml/2009/11/25/104"
  );
  # http://www.slackware.com/security/viewer.php?l=slackware-security&y=2009&m=slackware-security.603376
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4ca18c3b"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:kernel-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:kernel-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:kernel-generic-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:kernel-huge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:kernel-huge-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:kernel-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:kernel-modules-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:kernel-source");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/12/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/05/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2013 Tenable Network Security, Inc.");
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
if (slackware_check(osver:"current", pkgname:"kernel-firmware", pkgver:"2.6.29.6", pkgarch:"noarch", pkgnum:"3")) flag++;
if (slackware_check(osver:"current", pkgname:"kernel-generic", pkgver:"2.6.29.6", pkgarch:"i486", pkgnum:"3")) flag++;
if (slackware_check(osver:"current", pkgname:"kernel-generic-smp", pkgver:"2.6.29.6_smp", pkgarch:"i686", pkgnum:"3")) flag++;
if (slackware_check(osver:"current", pkgname:"kernel-headers", pkgver:"2.6.29.6_smp", pkgarch:"x86", pkgnum:"3")) flag++;
if (slackware_check(osver:"current", pkgname:"kernel-huge", pkgver:"2.6.29.6", pkgarch:"i486", pkgnum:"3")) flag++;
if (slackware_check(osver:"current", pkgname:"kernel-huge-smp", pkgver:"2.6.29.6_smp", pkgarch:"i686", pkgnum:"3")) flag++;
if (slackware_check(osver:"current", pkgname:"kernel-modules", pkgver:"2.6.29.6", pkgarch:"i486", pkgnum:"3")) flag++;
if (slackware_check(osver:"current", pkgname:"kernel-modules-smp", pkgver:"2.6.29.6_smp", pkgarch:"i686", pkgnum:"3")) flag++;
if (slackware_check(osver:"current", pkgname:"kernel-source", pkgver:"2.6.29.6_smp", pkgarch:"noarch", pkgnum:"3")) flag++;
if (slackware_check(osver:"current", arch:"x86_64", pkgname:"kernel-firmware", pkgver:"2.6.29.6", pkgarch:"noarch", pkgnum:"3")) flag++;
if (slackware_check(osver:"current", arch:"x86_64", pkgname:"kernel-generic", pkgver:"2.6.29.6", pkgarch:"x86_64", pkgnum:"3")) flag++;
if (slackware_check(osver:"current", arch:"x86_64", pkgname:"kernel-headers", pkgver:"2.6.29.6", pkgarch:"x86", pkgnum:"3")) flag++;
if (slackware_check(osver:"current", arch:"x86_64", pkgname:"kernel-huge", pkgver:"2.6.29.6", pkgarch:"x86_64", pkgnum:"3")) flag++;
if (slackware_check(osver:"current", arch:"x86_64", pkgname:"kernel-modules", pkgver:"2.6.29.6", pkgarch:"x86_64", pkgnum:"3")) flag++;
if (slackware_check(osver:"current", arch:"x86_64", pkgname:"kernel-source", pkgver:"2.6.29.6", pkgarch:"noarch", pkgnum:"3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:slackware_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
