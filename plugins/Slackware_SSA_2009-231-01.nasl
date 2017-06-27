#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Slackware Security Advisory 2009-231-01. The text 
# itself is copyright (C) Slackware Linux, Inc.
#

include("compat.inc");

if (description)
{
  script_id(40623);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2013/06/01 00:40:51 $");

  script_xref(name:"SSA", value:"2009-231-01");

  script_name(english:"Slackware 12.2 : kernel [updated] (SSA:2009-231-01)");
  script_summary(english:"Checks for updated packages in /var/log/packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Slackware host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This is a followup to the SSA:2009-230-01 advisory noting some
errata. The generic SMP kernel update for Slackware 12.2 was built
using the .config for a huge kernel, not a generic one. The kernel
previously published as kernel-generic-smp and in the gemsmp.s
directory works and is secure, but is larger than it needs to be. It
has been replaced in the Slackware 12.2 patches with a generic SMP
kernel. A new svgalib_helper package (compiled for a 2.6.27.31 kernel)
was added to the Slackware 12.2 /patches. An error was noticed in the
SSA:2009-230-01 advisory concerning the packages for Slackware
-current 32-bit. The http links given refer to packages with a -1
build version. The actual packages have a build number of -2."
  );
  # http://www.slackware.com/security/viewer.php?l=slackware-security&y=2009&m=slackware-security.449266
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6bdb98d3"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected kernel-generic-smp, kernel-modules-smp and / or
kernel-source packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:kernel-generic-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:kernel-modules-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:kernel-source");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:12.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/08/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/08/20");
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
if (slackware_check(osver:"12.2", pkgname:"kernel-generic-smp", pkgver:"2.6.27.31_smp", pkgarch:"i686", pkgnum:"2")) flag++;
if (slackware_check(osver:"12.2", pkgname:"kernel-modules-smp", pkgver:"2.6.27.31_smp", pkgarch:"i686", pkgnum:"2")) flag++;
if (slackware_check(osver:"12.2", pkgname:"kernel-source", pkgver:"2.6.27.31_smp", pkgarch:"noarch", pkgnum:"2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:slackware_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
