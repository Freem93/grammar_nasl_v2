#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2007-599.
#

include("compat.inc");

if (description)
{
  script_id(25587);
  script_version ("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/10/21 22:04:02 $");

  script_xref(name:"FEDORA", value:"2007-599");

  script_name(english:"Fedora Core 5 : kernel-2.6.20-1.2320.fc5 (2007-599)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora Core host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Merged stable kernel 2.6.20.12, 2.6.20.13, 2.6.20.14:
http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.20.12
http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.20.13
http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.20.14

Added the latest GFS2 updates from the maintainers.

CVE-2007-2451: Unspecified vulnerability in drivers/crypto/geode-aes.c
in GEODE-AES in the Linux kernel before 2.6.21.3 allows attackers to
obtain sensitive information via unspecified vectors.

CVE-2007-2875: Integer underflow in the cpuset_tasks_read function in
the Linux kernel before 2.6.20.13, and 2.6.21.x before 2.6.21.4, when
the cpuset filesystem is mounted, allows local users to obtain kernel
memory contents by using a large offset when reading the
/dev/cpuset/tasks file.

CVE-2007-2876: Linux Kernel is prone to multiple weaknesses and
vulnerabilities that can allow remote attackers to carry out various
attacks, including denial-of-service attacks.

CVE-2007-2453: The random number feature in Linux kernel 2.6 before
2.6.20.13, and 2.6.21.x before 2.6.21.4, (1) does not properly seed
pools when there is no entropy, or (2) uses an incorrect cast when
extracting entropy, which might cause the random number generator to
provide the same values after reboots on systems without an entropy
source.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.20.12"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.20.13"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.20.14"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-June/002266.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7698e22d"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel-kdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel-kdump-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel-smp-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel-smp-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel-smp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel-xen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel-xen0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel-xen0-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel-xenU");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel-xenU-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora_core:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/06/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/06/27");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2015 Tenable Network Security, Inc.");
  script_family(english:"Fedora Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Fedora" >!< release) audit(AUDIT_OS_NOT, "Fedora");
os_ver = eregmatch(pattern: "Fedora.*release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Fedora");
os_ver = os_ver[1];
if (! ereg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 5.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC5", reference:"kernel-2.6.20-1.2320.fc5")) flag++;
if (rpm_check(release:"FC5", reference:"kernel-debug-2.6.20-1.2320.fc5")) flag++;
if (rpm_check(release:"FC5", reference:"kernel-debug-devel-2.6.20-1.2320.fc5")) flag++;
if (rpm_check(release:"FC5", reference:"kernel-debuginfo-2.6.20-1.2320.fc5")) flag++;
if (rpm_check(release:"FC5", reference:"kernel-devel-2.6.20-1.2320.fc5")) flag++;
if (rpm_check(release:"FC5", reference:"kernel-doc-2.6.20-1.2320.fc5")) flag++;
if (rpm_check(release:"FC5", reference:"kernel-kdump-2.6.20-1.2320.fc5")) flag++;
if (rpm_check(release:"FC5", reference:"kernel-kdump-devel-2.6.20-1.2320.fc5")) flag++;
if (rpm_check(release:"FC5", cpu:"i386", reference:"kernel-smp-2.6.20-1.2320.fc5")) flag++;
if (rpm_check(release:"FC5", cpu:"i386", reference:"kernel-smp-debug-2.6.20-1.2320.fc5")) flag++;
if (rpm_check(release:"FC5", cpu:"i386", reference:"kernel-smp-debug-devel-2.6.20-1.2320.fc5")) flag++;
if (rpm_check(release:"FC5", cpu:"i386", reference:"kernel-smp-devel-2.6.20-1.2320.fc5")) flag++;
if (rpm_check(release:"FC5", reference:"kernel-xen-2.6.20-1.2320.fc5")) flag++;
if (rpm_check(release:"FC5", reference:"kernel-xen-devel-2.6.20-1.2320.fc5")) flag++;
if (rpm_check(release:"FC5", reference:"kernel-xen0-2.6.20-1.2320.fc5")) flag++;
if (rpm_check(release:"FC5", reference:"kernel-xen0-devel-2.6.20-1.2320.fc5")) flag++;
if (rpm_check(release:"FC5", reference:"kernel-xenU-2.6.20-1.2320.fc5")) flag++;
if (rpm_check(release:"FC5", reference:"kernel-xenU-devel-2.6.20-1.2320.fc5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel / kernel-debug / kernel-debug-devel / kernel-debuginfo / etc");
}
