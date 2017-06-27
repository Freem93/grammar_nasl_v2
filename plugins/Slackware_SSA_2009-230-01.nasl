#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Slackware Security Advisory 2009-230-01. The text 
# itself is copyright (C) Slackware Linux, Inc.
#

include("compat.inc");

if (description)
{
  script_id(40622);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2015/12/01 14:29:29 $");

  script_cve_id("CVE-2009-2692");
  script_xref(name:"SSA", value:"2009-230-01");

  script_name(english:"Slackware 12.2 / current : kernel (SSA:2009-230-01)");
  script_summary(english:"Checks for updated packages in /var/log/packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Slackware host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"New Linux kernel packages are available for Slackware 12.2 and
-current to address a security issue. A kernel bug discovered by Tavis
Ormandy and Julien Tinnes of the Google Security Team could allow a
local user to fill memory page zero with arbitrary code and then use
the kernel sendpage operation to trigger a NULL pointer dereference,
executing the code in the context of the kernel. If successfully
exploited, this bug can be used to gain root access. At this time we
have prepared fixed kernels for the stable version of Slackware
(12.2), as well as for both 32-bit x86 and x86_64 -current versions.
Additionally, we have added a package to the /patches directory for
Slackware 12.1 and 12.2 that will set the minimum memory page that can
be mmap()ed from userspace without additional privileges to 4096. The
package will work with any kernel supporting the vm.mmap_min_addr
tunable, and should significantly reduce the potential harm from this
bug, as well as future similar bugs that might be found in the kernel.
More updated kernels may follow."
  );
  # http://www.slackware.com/security/viewer.php?l=slackware-security&y=2009&m=slackware-security.877234
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f87ae2f9"
  );
  # http://www.slackware.com/security/viewer.php?l=slackware-security&y=2009&m=slackware-security.449266
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6bdb98d3"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Linux Kernel Sendpage Local Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:12.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/08/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/08/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");
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
if (slackware_check(osver:"12.2", pkgname:"kernel-firmware", pkgver:"2.6.27.31", pkgarch:"noarch", pkgnum:"1")) flag++;
if (slackware_check(osver:"12.2", pkgname:"kernel-generic", pkgver:"2.6.27.31", pkgarch:"i486", pkgnum:"1")) flag++;
if (slackware_check(osver:"12.2", pkgname:"kernel-generic-smp", pkgver:"2.6.27.31_smp", pkgarch:"i686", pkgnum:"2")) flag++;
if (slackware_check(osver:"12.2", pkgname:"kernel-headers", pkgver:"2.6.27.31_smp", pkgarch:"x86", pkgnum:"1")) flag++;
if (slackware_check(osver:"12.2", pkgname:"kernel-huge", pkgver:"2.6.27.31", pkgarch:"i486", pkgnum:"1")) flag++;
if (slackware_check(osver:"12.2", pkgname:"kernel-huge-smp", pkgver:"2.6.27.31_smp", pkgarch:"i686", pkgnum:"1")) flag++;
if (slackware_check(osver:"12.2", pkgname:"kernel-modules", pkgver:"2.6.27.31", pkgarch:"i486", pkgnum:"1")) flag++;
if (slackware_check(osver:"12.2", pkgname:"kernel-modules-smp", pkgver:"2.6.27.31_smp", pkgarch:"i686", pkgnum:"2")) flag++;
if (slackware_check(osver:"12.2", pkgname:"kernel-source", pkgver:"2.6.27.31_smp", pkgarch:"noarch", pkgnum:"2")) flag++;

if (slackware_check(osver:"current", pkgname:"kernel-firmware", pkgver:"2.6.29.6", pkgarch:"noarch", pkgnum:"1")) flag++;
if (slackware_check(osver:"current", pkgname:"kernel-generic", pkgver:"2.6.29.6", pkgarch:"i486", pkgnum:"1")) flag++;
if (slackware_check(osver:"current", pkgname:"kernel-generic-smp", pkgver:"2.6.29.6_smp", pkgarch:"i686", pkgnum:"1")) flag++;
if (slackware_check(osver:"current", pkgname:"kernel-headers", pkgver:"2.6.29.6_smp", pkgarch:"x86", pkgnum:"1")) flag++;
if (slackware_check(osver:"current", pkgname:"kernel-huge", pkgver:"2.6.29.6", pkgarch:"i486", pkgnum:"1")) flag++;
if (slackware_check(osver:"current", pkgname:"kernel-huge-smp", pkgver:"2.6.29.6_smp", pkgarch:"i686", pkgnum:"1")) flag++;
if (slackware_check(osver:"current", pkgname:"kernel-modules", pkgver:"2.6.29.6", pkgarch:"i486", pkgnum:"1")) flag++;
if (slackware_check(osver:"current", pkgname:"kernel-modules-smp", pkgver:"2.6.29.6_smp", pkgarch:"i686", pkgnum:"1")) flag++;
if (slackware_check(osver:"current", pkgname:"kernel-source", pkgver:"2.6.29.6_smp", pkgarch:"noarch", pkgnum:"1")) flag++;
if (slackware_check(osver:"current", arch:"x86_64", pkgname:"kernel-firmware", pkgver:"2.6.29.6", pkgarch:"noarch", pkgnum:"2")) flag++;
if (slackware_check(osver:"current", arch:"x86_64", pkgname:"kernel-generic", pkgver:"2.6.29.6", pkgarch:"x86_64", pkgnum:"2")) flag++;
if (slackware_check(osver:"current", arch:"x86_64", pkgname:"kernel-headers", pkgver:"2.6.29.6", pkgarch:"x86", pkgnum:"2")) flag++;
if (slackware_check(osver:"current", arch:"x86_64", pkgname:"kernel-huge", pkgver:"2.6.29.6", pkgarch:"x86_64", pkgnum:"2")) flag++;
if (slackware_check(osver:"current", arch:"x86_64", pkgname:"kernel-modules", pkgver:"2.6.29.6", pkgarch:"x86_64", pkgnum:"2")) flag++;
if (slackware_check(osver:"current", arch:"x86_64", pkgname:"kernel-source", pkgver:"2.6.29.6", pkgarch:"noarch", pkgnum:"2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:slackware_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
