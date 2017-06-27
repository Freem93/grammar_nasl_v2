#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Slackware Security Advisory 2003-336-01. The text 
# itself is copyright (C) Slackware Linux, Inc.
#

include("compat.inc");

if (description)
{
  script_id(18743);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2013/06/01 00:36:12 $");

  script_cve_id("CVE-2003-0961");
  script_xref(name:"SSA", value:"2003-336-01");

  script_name(english:"Slackware 9.1 / current : Kernel security update (SSA:2003-336-01)");
  script_summary(english:"Checks for updated packages in /var/log/packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Slackware host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"New kernels are available for Slackware 9.1 and -current. These have
been upgraded to Linux kernel version 2.4.23, which fixes a bug in the
kernel's do_brk() function that could be exploited to gain root
privileges. These updated kernels and modules should be installed by
any sites running a 2.4 kernel earlier than 2.4.23. Linux 2.0 and 2.2
kernels are not vulnerable."
  );
  # http://www.slackware.com/security/viewer.php?l=slackware-security&y=2003&m=slackware-security.236102
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?aa018f51"
  );
  # http://www.slackware.com/security/viewer.php?l=slackware-security&y=2003&m=slackware-security.718266
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0ba653f4"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:alsa-driver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:alsa-driver-xfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:alsa-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:alsa-oss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:alsa-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:kernel-ide");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:kernel-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:kernel-modules-xfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:kernel-source");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:9.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2003/12/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/07/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2013 Tenable Network Security, Inc.");
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
if (slackware_check(osver:"9.1", pkgname:"kernel-ide", pkgver:"2.4.23", pkgarch:"i486", pkgnum:"1")) flag++;
if (slackware_check(osver:"9.1", pkgname:"kernel-modules", pkgver:"2.4.23", pkgarch:"i486", pkgnum:"1")) flag++;
if (slackware_check(osver:"9.1", pkgname:"kernel-source", pkgver:"2.4.23", pkgarch:"noarch", pkgnum:"2")) flag++;

if (slackware_check(osver:"current", pkgname:"alsa-driver", pkgver:"0.9.8", pkgarch:"i486", pkgnum:"1")) flag++;
if (slackware_check(osver:"current", pkgname:"alsa-driver-xfs", pkgver:"0.9.8", pkgarch:"i486", pkgnum:"1")) flag++;
if (slackware_check(osver:"current", pkgname:"alsa-lib", pkgver:"0.9.8", pkgarch:"i486", pkgnum:"1")) flag++;
if (slackware_check(osver:"current", pkgname:"alsa-oss", pkgver:"0.9.8", pkgarch:"i486", pkgnum:"1")) flag++;
if (slackware_check(osver:"current", pkgname:"alsa-utils", pkgver:"0.9.8", pkgarch:"i486", pkgnum:"1")) flag++;
if (slackware_check(osver:"current", pkgname:"kernel-headers", pkgver:"2.4.23", pkgarch:"i386", pkgnum:"1")) flag++;
if (slackware_check(osver:"current", pkgname:"kernel-ide", pkgver:"2.4.23", pkgarch:"i486", pkgnum:"1")) flag++;
if (slackware_check(osver:"current", pkgname:"kernel-modules", pkgver:"2.4.23", pkgarch:"i486", pkgnum:"1")) flag++;
if (slackware_check(osver:"current", pkgname:"kernel-modules-xfs", pkgver:"2.4.23", pkgarch:"i486", pkgnum:"1")) flag++;
if (slackware_check(osver:"current", pkgname:"kernel-source", pkgver:"2.4.23", pkgarch:"noarch", pkgnum:"2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:slackware_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
