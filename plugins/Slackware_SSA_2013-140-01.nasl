#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Slackware Security Advisory 2013-140-01. The text 
# itself is copyright (C) Slackware Linux, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66638);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2014/02/10 00:39:20 $");

  script_cve_id("CVE-2013-2094");
  script_xref(name:"SSA", value:"2013-140-01");

  script_name(english:"Slackware 13.37 / 14.0 : kernel (SSA:2013-140-01)");
  script_summary(english:"Checks for updated packages in /var/log/packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Slackware host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"New Linux kernel packages are available for Slackware 13.37 and 14.0
to fix a security issue."
  );
  # http://www.slackware.com/security/viewer.php?l=slackware-security&y=2013&m=slackware-security.597338
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a5f13505"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:13.37");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:14.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");
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
if (slackware_check(osver:"13.37", pkgname:"kernel-firmware", pkgver:"20130512git", pkgarch:"noarch", pkgnum:"1")) flag++;
if (slackware_check(osver:"13.37", pkgname:"kernel-generic", pkgver:"2.6.37.6", pkgarch:"i486", pkgnum:"3")) flag++;
if (slackware_check(osver:"13.37", pkgname:"kernel-generic-smp", pkgver:"2.6.37.6_smp", pkgarch:"i686", pkgnum:"3")) flag++;
if (slackware_check(osver:"13.37", pkgname:"kernel-headers", pkgver:"2.6.37.6_smp", pkgarch:"x86", pkgnum:"3")) flag++;
if (slackware_check(osver:"13.37", pkgname:"kernel-huge", pkgver:"2.6.37.6", pkgarch:"i486", pkgnum:"3")) flag++;
if (slackware_check(osver:"13.37", pkgname:"kernel-huge-smp", pkgver:"2.6.37.6_smp", pkgarch:"i686", pkgnum:"3")) flag++;
if (slackware_check(osver:"13.37", pkgname:"kernel-modules", pkgver:"2.6.37.6", pkgarch:"i486", pkgnum:"3")) flag++;
if (slackware_check(osver:"13.37", pkgname:"kernel-modules-smp", pkgver:"2.6.37.6_smp", pkgarch:"i686", pkgnum:"3")) flag++;
if (slackware_check(osver:"13.37", pkgname:"kernel-source", pkgver:"2.6.37.6_smp", pkgarch:"noarch", pkgnum:"3")) flag++;
if (slackware_check(osver:"13.37", arch:"x86_64", pkgname:"kernel-firmware", pkgver:"20130512git", pkgarch:"noarch", pkgnum:"1")) flag++;
if (slackware_check(osver:"13.37", arch:"x86_64", pkgname:"kernel-generic", pkgver:"2.6.37.6", pkgarch:"x86_64", pkgnum:"3")) flag++;
if (slackware_check(osver:"13.37", arch:"x86_64", pkgname:"kernel-headers", pkgver:"2.6.37.6", pkgarch:"x86", pkgnum:"3")) flag++;
if (slackware_check(osver:"13.37", arch:"x86_64", pkgname:"kernel-huge", pkgver:"2.6.37.6", pkgarch:"x86_64", pkgnum:"3")) flag++;
if (slackware_check(osver:"13.37", arch:"x86_64", pkgname:"kernel-modules", pkgver:"2.6.37.6", pkgarch:"x86_64", pkgnum:"3")) flag++;
if (slackware_check(osver:"13.37", arch:"x86_64", pkgname:"kernel-source", pkgver:"2.6.37.6", pkgarch:"noarch", pkgnum:"3")) flag++;

if (slackware_check(osver:"14.0", pkgname:"kernel-firmware", pkgver:"20130512git", pkgarch:"noarch", pkgnum:"1")) flag++;
if (slackware_check(osver:"14.0", pkgname:"kernel-generic", pkgver:"3.2.45", pkgarch:"i486", pkgnum:"1")) flag++;
if (slackware_check(osver:"14.0", pkgname:"kernel-generic-smp", pkgver:"3.2.45_smp", pkgarch:"i686", pkgnum:"1")) flag++;
if (slackware_check(osver:"14.0", pkgname:"kernel-headers", pkgver:"3.2.45_smp", pkgarch:"x86", pkgnum:"1")) flag++;
if (slackware_check(osver:"14.0", pkgname:"kernel-huge", pkgver:"3.2.45", pkgarch:"i486", pkgnum:"1")) flag++;
if (slackware_check(osver:"14.0", pkgname:"kernel-huge-smp", pkgver:"3.2.45_smp", pkgarch:"i686", pkgnum:"1")) flag++;
if (slackware_check(osver:"14.0", pkgname:"kernel-modules", pkgver:"3.2.45", pkgarch:"i486", pkgnum:"1")) flag++;
if (slackware_check(osver:"14.0", pkgname:"kernel-modules-smp", pkgver:"3.2.45_smp", pkgarch:"i686", pkgnum:"1")) flag++;
if (slackware_check(osver:"14.0", pkgname:"kernel-source", pkgver:"3.2.45_smp", pkgarch:"noarch", pkgnum:"1")) flag++;
if (slackware_check(osver:"14.0", arch:"x86_64", pkgname:"kernel-firmware", pkgver:"20130512git", pkgarch:"noarch", pkgnum:"1")) flag++;
if (slackware_check(osver:"14.0", arch:"x86_64", pkgname:"kernel-generic", pkgver:"3.2.45", pkgarch:"x86_64", pkgnum:"1")) flag++;
if (slackware_check(osver:"14.0", arch:"x86_64", pkgname:"kernel-headers", pkgver:"3.2.45", pkgarch:"x86", pkgnum:"1")) flag++;
if (slackware_check(osver:"14.0", arch:"x86_64", pkgname:"kernel-huge", pkgver:"3.2.45", pkgarch:"x86_64", pkgnum:"1")) flag++;
if (slackware_check(osver:"14.0", arch:"x86_64", pkgname:"kernel-modules", pkgver:"3.2.45", pkgarch:"x86_64", pkgnum:"1")) flag++;
if (slackware_check(osver:"14.0", arch:"x86_64", pkgname:"kernel-source", pkgver:"3.2.45", pkgarch:"noarch", pkgnum:"1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:slackware_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
